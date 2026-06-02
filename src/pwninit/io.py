import subprocess
import time
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import docker
from pwn import context, gdb, log, pause, process, remote, ssh

from pwninit.kernel import inject
import pwninit.helpers.utils as utils


@dataclass(frozen=True)
class NC:
    """
    Dataclass for representing a network connection.

    Attributes:
        host (str): The host address.
        port (int): The port number.
    """

    host: str
    port: int


@dataclass(frozen=True)
class SSH:
    """
    Dataclass for representing an SSH connection.

    Attributes:
        user (str): The SSH username.
        host (str): The host address.
        password (str|None): The SSH password (default: None).
        port (int): The SSH port (default: 22).
        path (str): The SSH cwd (default: ".")
    """

    user: str
    host: str
    password: str|None = None
    port: int = 22
    path: str|None = None


class IOContext:
    """
    A context class for managing IO connections (local, remote, SSH, Docker, kernel).

    Attributes:
        args: CLI arguments for the connection.
        config: Configuration for the target (e.g., binary path, environment).
        ssh_conn: The SSH connection object.
        conn: The active connection object (e.g., `process`, `remote`, `ssh`).
        proc: The process object for local debugging.
    """

    def __init__(
        self,
        args: Any,
        config: Any,
        proc: Any | None = None,
        conn: Any | None = None,
        ssh_conn: Any | None = None,
    ) -> None:
        self.args = args
        self.config = config
        self.ssh_conn: Any | None = ssh_conn
        self.conn: Any | None = conn
        self.proc: Any | None = proc

    def __getattr__(self, name: str) -> Any:
        if name != "conn" and self.conn is not None:
            return getattr(self.conn, name)
        raise AttributeError(name)

    def __create_remote_connection(self) -> Any:
        return remote(
            self.args.remote.host,
            self.args.remote.port,
            ssl=self.args.ssl,
        )

    def __create_ssh_connection(self) -> Any:
        return ssh(
            user=self.args.remote.user,
            password=self.args.remote.password,
            host=self.args.remote.host,
            port=self.args.remote.port,
        )

    def __create_ssh_process(self) -> Any:
        if self.args.debug:
            return gdb.debug(
                self.config.chall,
                ssh=self.ssh_conn,
                cwd=self.args.remote.path
            )

        return self.ssh_conn.process(
            self.config.chall,
            env=self.config.env,
            cwd=self.args.remote.path
        )

    def __create_kernel_process(self) -> Any:
        status = log.progress("compiling exploit")
        subprocess.run(
            ["make"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        status.success("done")

        status = log.progress("injecting exploit")
        if not inject(self.config.archive, "exploit"):
            status.failure("failed")
        status.success("done")

        gdb_script = ""
        if self.args.debug:
            gdb_script = self.args.gdb_cmd if self.args.gdb_cmd else ""
            self.config.chall.append("-s")

        p = process(self.config.chall, env=self.config.env)

        if self.args.debug:
            gdb.attach(
                target=("localhost", 1234),
                exe=f"{self.config.kernel}.elf",
                gdbscript=gdb_script,
            )

        return p

    def __create_local_process(self) -> Any:
        if self.config.archive:
            return self.__create_kernel_process()

        gdb_script = self.args.gdb_cmd if self.args.gdb_cmd else ""
        if self.args.debug:
            return gdb.debug(
                self.config.chall,
                gdbscript=gdb_script,
                env=self.config.env,
            )
        elif self.args.strace:
            return process(
                ["strace", "-o", "strace.out", self.config.chall],
                env=self.config.env,
            )
        else:
            p = process(self.config.chall, env=self.config.env)
            if self.args.attach:
                gdb.attach(p, gdbscript=gdb_script)
                log.info("Attached gdb")
                pause()
            return p

    def __launch_docker(self) -> Any:
        client = docker.from_env()
        name = Path(".").resolve().name
        image_tag = getattr(
            self.config, "docker_image", f"pwninit-{name}:latest"
        ).lower()

        container = next((c for c in client.containers.list() if c.image.tags[-1] == image_tag), None)

        if not container:
            container = client.containers.run(
                image_tag,
                pid_mode="host",
                ports={
                    f"{self.args.remote.port}/tcp": self.args.remote.port
                },
                privileged=True,
                detach=True,
            )

        return container

    def __docker_get_bin_pid(self, top) -> int:
        bin = ''
        if hasattr(self.config, "docker_bin"):
            bin = self.config.docker_bin

        for line in top["Processes"]:
            _, pid, *_, cmd = line

            if self.config.binary in cmd:
                return int(pid)
            elif "socat" in cmd:
                bin = re.search(r'(?i)exec:([^,\s]+)', cmd).group(1)
            elif bin == cmd:
                return int(pid)


    def __debug_docker(self, container: Any) -> None:
        processes = container.top()
        pid = self.__docker_get_bin_pid(processes)
        if not pid:
            log.warning("Bin isn't running — check Dockerfile or bin name")
            exit(1)

        gdb.attach(pid, exe=self.config.binary)

    def test_connection(self) -> bool:
        try:
            buf = self.recv(timeout=2)
            self.unrecv(buf)
            return True
        except EOFError:
            log.warning("Failed to connect to docker")
            return False

    def connect(self, enable_log: bool = True) -> "IOContext | None":
        """
        Establish a connection based on the provided arguments and configuration.

        Args:
            enable_log (bool): If True, enable logging (default: True).

        Returns:
            self: On success.
            None: On failure.
        """
        if not enable_log:
            log_level = context.log_level
            context.log_level = "error"

        if self.conn:
            return self

        is_local_process = not self.args.remote or (
            self.args.local and not self.proc
        )
        is_docker_debug = self.args.docker and (
            self.args.debug or self.args.attach
        )
        is_ssh = isinstance(self.args.remote, SSH)

        if is_local_process:
            self.conn = self.proc = self.__create_local_process()
            
        if self.args.docker:
            container = self.__launch_docker()

        if self.args.remote and is_ssh:
            self.ssh_conn = self.__create_ssh_connection()
            if not self.ssh_conn:
                return None
            self.conn = self.__create_ssh_process()
        elif self.args.remote:
            self.conn = self.__create_remote_connection()

        if is_docker_debug and self.test_connection():
            self.__debug_docker(container)

        if not self.conn:
            log.warning("Failed to create process")
            return None

        if not enable_log:
            context.log_level = log_level

        return self

    def reconnect(self, enable_log: bool = True) -> "IOContext | None":
        """
        Close the current connection and reconnect.

        Args:
            enable_log (bool): If True, enable logging (default: True).

        Returns:
            IOContext | None: The reconnected context, or None on failure.
        """
        if self.conn:
            self.close(enable_log)
        return self.connect(enable_log)

    def close(self, enable_log: bool = True) -> None:
        """
        Close the current connection.

        Args:
            enable_log (bool): If True, enable logging (default: True).
        """
        if not self.conn:
            return
        if not enable_log:
            log_level = context.log_level
            context.log_level = "error"
        self.conn.close()
        self.conn = None
        if not enable_log:
            context.log_level = log_level

    def prompt(self, data: str | bytes, **kwargs: Any) -> None:
        """
        Send data to the target, optionally waiting for a prefix.

        Args:
            data: The data to send.
            **kwargs: Additional arguments for `send`/`sendline` (e.g., `prefix`, `line`).
        """
        prefix = utils.encode(kwargs.pop("prefix", self.config.prefix))
        line = utils.encode(kwargs.pop("line", True))
        data = utils.encode(data)
        r = self.conn

        if prefix and line:
            r.sendlineafter(prefix, data, **kwargs)
        elif prefix:
            r.sendafter(prefix, data, **kwargs)
        elif not prefix and line:
            r.sendline(data, **kwargs)
        else:
            r.send(data, **kwargs)

    def sla(self, *args: str | bytes, **kwargs: Any) -> None:
        """
        Send a line after a prefix (shorthand for `prompt` with `line=True`).

        Args:
            *args: If one argument, it is the data to send. If two, the first is the prefix and the second is the data.
            **kwargs: Additional arguments for `prompt`.
        """
        if len(args) == 1:
            self.prompt(args[0], **kwargs)
        elif len(args) >= 2:
            self.prompt(args[1], prefix=args[0], **kwargs)

    def sa(self, *args: str | bytes, **kwargs: Any) -> None:
        """
        Send data after a prefix (shorthand for `prompt` with `line=False`).

        Args:
            *args: If one argument, it is the data to send. If two, the first is the prefix and the second is the data.
            **kwargs: Additional arguments for `prompt`.
        """
        self.sla(*args, line=False, **kwargs)

    def sl(self, data: str | bytes, **kwargs: Any) -> None:
        """
        Send a line without waiting for a prefix.

        Args:
            data: The data to send.
            **kwargs: Additional arguments for `prompt`.
        """
        self.prompt(data, prefix=None, **kwargs)

    def send(self, data: str | bytes, **kwargs: Any) -> None:
        """
        Send data without waiting for a prefix or newline.

        Args:
            data: The data to send.
            **kwargs: Additional arguments for `prompt`.
        """
        self.prompt(data, prefix=None, line=False, **kwargs)

    def recv(
        self,
        prefix: str | bytes | int | None = None,
        **kwargs: Any,
    ) -> bytes:
        """
        Receive data from the target, optionally waiting for a prefix.

        Args:
            prefix: The prefix to wait for (bytes, str, or int for `recvn`).
            **kwargs: Additional arguments for `recv`/`recvline`/`recvuntil`.

        Returns:
            bytes: The received data.
        """
        r = kwargs.pop("io", self.conn)
        line = kwargs.pop("line", False)

        if prefix is None:
            return r.recvline(**kwargs) if line else r.recv(**kwargs)
        elif isinstance(prefix, int):
            return r.recvn(prefix, **kwargs)

        prefix = utils.encode(prefix)
        drop = kwargs.pop("drop", True)
        if line:
            r.recvuntil(prefix, drop=drop, **kwargs)
            return r.recvline(drop=drop, **kwargs)
        else:
            return r.recvuntil(prefix, drop=drop, **kwargs)

    def ru(self, u: str | bytes, **kwargs: Any) -> bytes:
        """
        Receive data until a specific string (shorthand for `recv` with `prefix`).

        Args:
            u: The string to wait for.
            **kwargs: Additional arguments for `recv`.
        """
        return self.recv(u, **kwargs)

    def rl(self, **kwargs: Any) -> bytes:
        """
        Receive a line (shorthand for `recv` with `line=True`).

        Returns:
            bytes: The received line.
        """
        return self.recv(line=True, **kwargs)

    def rla(self, d: str | bytes, **kwargs: Any) -> bytes:
        """
        Receive a line after a specific string (shorthand for `recv` with `prefix` and `line=True`).

        Args:
            d: The string to wait for.
            **kwargs: Additional arguments for `recv`.
        """
        return self.recv(d, line=True, **kwargs)

    def ra(self) -> bytes:
        """
        Receive all remaining data.

        Returns:
            bytes: All remaining data.
        """
        return self.recvall()

    def itrv(self) -> Any:
        """
        Switch to interactive mode.

        Returns:
            Any: The result of the interactive session.
        """
        return self.interactive()

    def urecv(self) -> bytes:
        """
        Undo the last receive operation.

        Returns:
            bytes: The data that was un-received.
        """
        return self.unrecv()

    def rln(self, n: int, **kwargs: Any) -> list[bytes]:
        """
        Receive `n` lines.

        Args:
            n (int): The number of lines to receive.
            **kwargs: Additional arguments for `recv`.

        Returns:
            list[bytes]: A list of received lines.
        """
        return [self.rl(**kwargs) for _ in range(n)]

    def pow(self) -> None:
        """
        Solve any pows implemented in utils using what's been received.
        """
        utils.solve_pow(self.clean())


ioctx: IOContext | None = None


def set_ctx(new_ctx: IOContext) -> None:
    global ioctx
    ioctx = new_ctx


def _require_ctx() -> None:
    if ioctx is None:
        raise RuntimeError("IOContext not initialized — call set_ctx() first")


def _ctx(method_name: str) -> Any:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        _require_ctx()
        return getattr(ioctx, method_name)(*args, **kwargs)

    wrapper.__name__ = method_name
    return wrapper


def connect(
    args: Any | None = None,
    config: Any | None = None,
    default: bool = False,
) -> IOContext | None:
    global ioctx
    if not args:
        args = ioctx.args
    if not config:
        config = ioctx.config
    io = IOContext(args, config)
    if default:
        ioctx = io
    return io.connect()


reconnect: Any = _ctx("reconnect")
close: Any = _ctx("close")
prompt: Any = _ctx("prompt")
sla: Any = _ctx("sla")
sa: Any = _ctx("sa")
sl: Any = _ctx("sl")
send: Any = _ctx("send")
recv: Any = _ctx("recv")
ru: Any = _ctx("ru")
ra: Any = _ctx("ra")
rl: Any = _ctx("rl")
rla: Any = _ctx("rla")
rln: Any = _ctx("rln")
urecv: Any = _ctx("unrecv")
clean: Any = _ctx("clean")
itrv: Any = _ctx("interactive")
pow: Any = _ctx("pow")
