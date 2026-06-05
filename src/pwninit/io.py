from __future__ import annotations

import argparse
import subprocess
import time
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import docker
from pwn import context, gdb, log, pause, process, remote, ssh, pwnlib

from pwninit.kernel import inject
import pwninit.helpers as helpers


@dataclass(frozen=True)
class NC:
    """Dataclass representing a network connection configuration.

    Attributes:
        host (str): The target remote host domain or IP address.
        port (int): The target remote network port number.
    """

    host: str
    port: int


@dataclass(frozen=True)
class SSH:
    """Dataclass representing an SSH connection configuration.

    Attributes:
        user (str): The SSH username.
        host (str): The target host address.
        password (str | None): The SSH password credentials.
        port (int): The target SSH daemon port (default: 22).
        path (str | None): Explicit remote current working directory path.
    """

    user: str
    host: str
    password: str | None = None
    port: int = 22
    path: str | None = None


@dataclass
class Args:
    """IO connection parameters
    
    Attributes:
        remote (SSH | NC | None): Remote target as NC (ip:port) or SSH (user:pass@ip:port). ``None`` runs locally.
        local (bool): Spawn the challenge as a local server before connecting.
        ssl (bool): Wrap the TCP connection in TLS. Only applies to NC targets.
        docker (bool): Launch the challenge via Docker before connecting.
        debug (bool): Open the binary under GDB on launch. Mutually exclusive with ``attach``.
        attach (bool): Spawn normally then attach GDB after launch. Mutually exclusive with ``debug``.
        gdb_cmd (str | None): GDB script passed on startup. Requires ``debug`` or ``attach``.
        strace (bool): Run under strace, writing output to ``strace.out``.
    """
    remote: SSH | NC | None = None
    local: bool = False
    ssl: bool = False
    docker: bool = False
    debug: bool = False
    attach: bool = False
    gdb_cmd: str | None = None
    strace: bool = False

class IOContext:
    """A context wrapper class managing multi-tier execution pipes spanning local

    processes, network sockets, SSH sessions, Docker instances, or simulated kernels.

    Attributes:
        args: Parsed command line execution arguments object.
        config: Structured binary and operational workspace definitions.
        ssh_conn: Active raw pwntools SSH context channel instance.
        conn: Reference link pointing directly to active IO communication tube.
        proc: Reference to local operating process instance when debugging.
    """

    def __init__(
        self,
        args: Args,
        config: Any,
        proc: pwnlib.tubes.process.process | None = None,
        conn: pwnlib.tubes.tube | None = None,
        ssh_conn: pwnlib.tubes.ssh | None = None,
    ) -> None:
        """Initializes the IOContext tracking state and establishes the connection pipeline.

        Args:
            args (Args): Parsed command-line execution and environment flags.
            config (Any): Workspace configuration mapping binaries, files, and environment paths.
            proc (pwnlib.tubes.process.process | None, optional): An active local target 
                process instance. Defaults to None.
            conn (pwnlib.tubes.tube | None, optional): An active communication channel 
                (e.g., remote socket, SSH process). Defaults to None.
            ssh_conn (pwnlib.tubes.ssh | None, optional): An active raw pwntools SSH context 
                session handle. Defaults to None.

        Side Effects:
            Triggers `self.connect()` during initialization to immediately evaluate environment 
            arguments and bind to the correct communication pipeline.
        """
        self.args = args
        self.config = config
        self.ssh_conn = ssh_conn
        self.conn = conn
        self.proc = proc

        self.connect()

    def __getattr__(self, name: str) -> Any:
        if name != "conn" and self.conn is not None:
            return getattr(self.conn, name)
        raise AttributeError(name)

    def __create_remote_connection(self) -> Any:
        deadline = time.time() + 10.0
        last_err = None
        io = None

        p = log.progress(f"Opening connection to {self.args.remote.host} on port {self.args.remote.port}")

        while time.time() < deadline:
            if io:
                io.close()
            try:
                log_level = context.log_level
                context.log_level = 'error'
                io = remote(
                    self.args.remote.host,
                    self.args.remote.port,
                    ssl=self.args.ssl,
                    timeout=1,
                )

                if not io.connected():
                    io.close()
                    continue

                io.unrecv(io.recv(timeout=0.5))
                context.log_level = log_level

                p.success("Done")
                return io

            except Exception as e:
                last_err = e
                time.sleep(0.1)

        p.failure(f"Could not connect within 5s: {last_err}")
        return None

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

        return p

    def __launch_docker(self) -> Any:
        client = docker.from_env()
        name = Path(".").resolve().name
        image_tag = getattr(
            self.config, "docker_image", f"pwninit-{name}:latest"
        ).lower()

        try:
            client.images.get(image_tag)
        except docker.errors.ImageNotFound:
            raise RuntimeError(
                f"Docker image '{image_tag}' not found. "
                "Build step likely failed or was not loaded (--load missing)."
            )

        container = next((c for c in client.containers.list() if c.image.tags and c.image.tags[-1] == image_tag), None)

        if container:
            if container.status != "running":
                container.start()

            container.reload()
            return container

        container = client.containers.run(
            image_tag,
            pid_mode="host",
            ports={
                f"{self.args.remote.port}/tcp": self.args.remote.port
            },
            privileged=True,
            detach=True,
            tty=True,
            stdin_open=True
        )

        for _ in range(50):
            container.reload()
            if container.status == "running":
                return container
            time.sleep(0.1)

        logs = container.logs().decode(errors="ignore")

        raise RuntimeError(
            f"Container failed to start properly.\nLogs:\n{logs}"
        )


    def __docker_get_bin_pid(self, top: dict) -> int | None:
        binary_name = ""
        if hasattr(self.config, "docker_bin"):
            binary_name = self.config.docker_bin

        for line in top["Processes"]:
            _, pid, *_, cmd = line

            if self.config.binary in cmd:
                return int(pid)
            elif "socat" in cmd:
                match = re.search(r'(?i)exec:([^,\s]+)', cmd)
                if match:
                    binary_name = match.group(1)
            elif binary_name == cmd or binary_name == Path(cmd).name:
                return int(pid)

        return None

    def __debug_docker(self, container: Any) -> None:
        processes = container.top()
        pid = self.__docker_get_bin_pid(processes)
        if not pid:
            log.warning("Bin isn't running - check Dockerfile or bin name")
            sys.exit(1)

        gdb.attach(pid, exe=self.config.binary)

        
    def connect(self, enable_log: bool = True) -> "IOContext | None":
        """Establish connection bindings matching active environment arguments.

        Args:
            enable_log (bool): Output standard configuration status logging streams.

        Returns:
            IOContext | None: Active operational self reference or None if failed.
        """
        if not enable_log:
            log_level = context.log_level
            context.log_level = "error"

        if self.conn:
            return self

        if self.ssh_conn:
            return self.__create_ssh_process()

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
            self.conn = self.__create_ssh_process() if self.ssh_conn else None
        elif self.args.remote:
            self.conn = self.__create_remote_connection()

        if not self.conn:
            log.warning("Failed to create process")
            return None

        if is_docker_debug:
            self.__debug_docker(container)

        if not enable_log:
            context.log_level = log_level

        return self

    def reconnect(self, enable_log: bool = True) -> "IOContext | None":
        """Close active handles and re-run initialization structures."""
        self.close(enable_log)
        return self.connect(enable_log)

    def close(self, enable_log: bool = True) -> None:
        """Safely close active descriptor pipes and clear tracking variables."""
        if not self.conn and not self.proc:
            return

        if not enable_log:
            log_level = context.log_level
            context.log_level = "error"

        if self.conn:
            self.conn.close()
            self.conn = None

        if self.proc:
            self.proc.close()
            self.proc = None

        if not enable_log:
            context.log_level = log_level

    def prompt(self, data: str | bytes, **kwargs: Any) -> None:
        """Transmit parameters downstream, adapting automatically to specific prefixes or line endings."""
        prefix = helpers.encode(kwargs.pop("prefix", self.config.prefix))
        line = helpers.encode(kwargs.pop("line", True))
        data = helpers.encode(data)
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
        """Send line after target prefix indicator."""
        if len(args) == 1:
            self.prompt(args[0], **kwargs)
        elif len(args) >= 2:
            self.prompt(args[1], prefix=args[0], **kwargs)

    def sa(self, *args: str | bytes, **kwargs: Any) -> None:
        """Send raw data chunk after target prefix indicator."""
        self.sla(*args, line=False, **kwargs)

    def sl(self, data: str | bytes, **kwargs: Any) -> None:
        """Send data appended with trailing system line termination characters."""
        self.prompt(data, prefix=None, **kwargs)

    def send(self, data: str | bytes, **kwargs: Any) -> None:
        """Transmit raw payload blocks over the active data stream."""
        self.prompt(data, prefix=None, line=False, **kwargs)

    def recv(self, prefix: str | bytes | int | None = None, **kwargs: Any) -> bytes:
        """Extract bytes back up from tracking pipelines matching constraints."""
        r = kwargs.pop("io", self.conn)
        line = kwargs.pop("line", False)

        if prefix is None:
            return r.recvline(**kwargs) if line else r.recv(**kwargs)
        elif isinstance(prefix, int):
            return r.recvn(prefix, **kwargs)

        prefix = helpers.encode(prefix)
        drop = kwargs.pop("drop", True)
        if line:
            r.recvuntil(prefix, drop=drop, **kwargs)
            return r.recvline(drop=drop, **kwargs)
        else:
            return r.recvuntil(prefix, drop=drop, **kwargs)

    def ru(self, u: str | bytes, **kwargs: Any) -> bytes:
        """Extract buffer chunks up until a specified delimiter sequence."""
        return self.recv(u, **kwargs)

    def rl(self, **kwargs: Any) -> bytes:
        """Extract a single structured newline terminated string sequence."""
        return self.recv(line=True, **kwargs)

    def rla(self, d: str | bytes, **kwargs: Any) -> bytes:
        """Extract a complete newline bounded sequence string following an initial key token."""
        return self.recv(d, line=True, **kwargs)

    def ra(self) -> bytes:
        """Drain all remaining communication bytes entirely from the active pipe."""
        return self.conn.recvall()

    def itrv(self) -> Any:
        """Yield direct console access over descriptor channels back to the interactive shell."""
        return self.conn.interactive()

    def urecv(self, *args: Any, **kwargs: Any) -> bytes:
        """Push target chunks back down into the pipeline buffer storage array."""
        return self.conn.unrecv(*args, **kwargs)

    def rln(self, n: int, **kwargs: Any) -> list[bytes]:
        """Iteratively parse distinct newline chunks returning sequence listings."""
        return [self.rl(**kwargs) for _ in range(n)]

    def pow(self) -> None:
        """Examine text contents currently available within pipes to isolate and process computational puzzles."""
        helpers.solve_pow(self.conn.clean())

def _require_ctx() -> IOContext:
    from pwninit.context import ioctx
    if ioctx is None:
        raise RuntimeError("IOContext not initialized - call set_ctx() first")
    return ioctx


def _ctx(method_name: str) -> Any:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        ctx = _require_ctx()
        return getattr(ctx, method_name)(*args, **kwargs)

    wrapper.__name__ = method_name
    return wrapper


reconnect = _ctx("reconnect")
close = _ctx("close")
prompt = _ctx("prompt")
sla = _ctx("sla")
sa = _ctx("sa")
sl = _ctx("sl")
send = _ctx("send")
recv = _ctx("recv")
ru = _ctx("ru")
ra = _ctx("ra")
rl = _ctx("rl")
rla = _ctx("rla")
rln = _ctx("rln")
urecv = _ctx("urecv")
clean = _ctx("clean")
itrv = _ctx("itrv")
pow = _ctx("pow")


def connect(
    args: Args | None = None,
    config: Config | None = None,
    default: bool = True,
) -> IOContext | None:
    """Instantiate a new IOContext connection
    
    Args:
        args (argparse.Namespace | None): Args to pass to IOContext (default keep the actual args)
        config (Config | None): Config to pass to IOContext (default keep the actual config)
        default (bool): Set the new connection to default (default false)

    Returns:
        IOContext | None: Active IOContext instance
    """    
    if not args or not config:
        ctx = _require_ctx()

    args = args if args else ctx.args
    config = config if config else ctx.config

    io = IOContext(args, config)
    if default:
        from pwninit.context import set_ctx
        set_ctx(io)
    return io

