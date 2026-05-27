import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import docker
from pwn import context, gdb, log, pause, process, remote, ssh

from pwninit.kernel import inject


@dataclass
class NC:
    host: str
    port: int


@dataclass
class SSH:
    user: str
    host: str
    password: str = ''
    port: int = 22


class IOContext():
    def __init__(self, args, config, proc=None, conn=None, ssh_conn=None):
        self.args = args
        self.config = config
        self.ssh_conn = ssh_conn
        self.conn = conn
        self.proc = proc

    def __getattr__(self, name):
        if name != 'conn' and self.conn is not None:
            return getattr(self.conn, name)
        raise AttributeError(name)

    def __create_remote_connection(self):
        if isinstance(self.args.remote, NC):
            try:
                return remote(self.args.remote.host, self.args.remote.port, ssl=self.args.ssl)
            except Exception as e:
                log.error("Failed to connect to %s:%d - %s" % (self.args.remote.host, self.args.remote.port, str(e)))

        elif isinstance(self.args.remote, SSH):
            try:
                return ssh(user=self.args.remote.user, password=self.args.remote.password,
                           host=self.args.remote.host, port=self.args.remote.port)
            except Exception as e:
                log.error("SSH connection failed: %s" % str(e))

    def __create_ssh_process(self):
        if self.args.path:
            chall_path = str(Path(self.args.path) / self.config.chall)
        else:
            chall_path = self.config.chall
        try:
            if self.args.debug:
                return gdb.debug(chall_path, ssh=self.ssh_conn)
            else:
                return self.ssh_conn.process(chall_path, env=self.config.env)
        except Exception as e:
            log.error("Failed to create SSH process: %s" % str(e))

    def __create_kernel_process(self):
        status = log.progress('compiling exploit')
        subprocess.run(["make"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status.success('done')

        status = log.progress('injecting exploit')
        if not inject(self.config.archive, "exploit"):
            status.failure("failed")
        status.success('done')

        gdb_script = ""
        if self.args.debug:
            gdb_script = self.args.gdb_cmd if self.args.gdb_cmd else ""
            self.config.chall.append('-s')

        p = process(self.config.chall, env=self.config.env)

        if self.args.debug:
            gdb.attach(target=('localhost', 1234), exe=f'{self.config.kernel}.elf', gdbscript=gdb_script)

        return p

    def __create_local_process(self):
        try:
            if self.config.archive:
                return self.__create_kernel_process()

            gdb_script = self.args.gdb_cmd if self.args.gdb_cmd else ""
            if self.args.debug:
                return gdb.debug(self.config.chall, gdbscript=gdb_script, env=self.config.env)
            elif self.args.strace:
                return process(["strace", "-o", "strace.out", self.config.chall], env=self.config.env)
            else:
                p = process(self.config.chall, env=self.config.env)
                if self.args.attach:
                    gdb.attach(p, gdbscript=gdb_script)
                    log.info("Attached gdb")
                    pause()
                return p
        except Exception as e:
            log.error("Failed to create local process: %s" % str(e))

    def __launch_docker(self):
        client = docker.from_env()
        name = Path('.').resolve().name
        image_tag = getattr(self.config, 'docker_image', f"pwninit-{name}:latest").lower()

        container = next(
            (c for c in client.containers.list() if c.image.tags[-1] == image_tag),
            None
        )

        if not container:
            try:
                container = client.containers.run(
                    image_tag,
                    pid_mode="host",
                    ports={f'{self.args.remote.port}/tcp': self.args.remote.port},
                    privileged=True,
                    detach=True,
                )
            except docker.errors.APIError as e:
                log.warning(f'Failed to launch docker: {e}')
                exit(1)

        return container

    def __debug_docker(self, container):
        processes = container.top()
        pid = None
        bin = None

        if hasattr(self.config, "docker_bin"):
            bin = self.config.docker_bin
        else:
            for p in processes['Processes']:
                if self.config.binary in p[-1]:
                    pid = int(p[1])
                    break
                if 'socat' in p[-1]:
                    bin = p[-1].split('exec:')[1].split(',')[0]
                    break

            if not bin and not pid:
                log.warning("No socat running nor binary — set docker_bin in Config")
                exit(1)

        if not pid:
            for p in processes['Processes']:
                if bin in p[-1]:
                    pid = int(p[1])

        if not pid:
            log.warning("Bin isn't running — check Dockerfile or bin name")
            exit(1)

        gdb.attach(pid, exe=self.config.binary)

    def connect(self, enable_log=True):
        if not enable_log:
            log_level = context.log_level
            context.log_level = "error"

        if not self.conn:
            if (self.args.local or self.args.docker) and not self.args.remote:
                self.args.remote = NC('localhost', 5000)
                
            if not self.args.remote or self.args.local and not self.proc:
                self.proc = io = self.__create_local_process()

            if self.args.docker:
                container = self.__launch_docker()

            if self.args.remote:
                if isinstance(self.args.remote, SSH):
                    if not self.ssh_conn:
                        self.ssh_conn = self.__create_remote_connection()
                        if not self.ssh_conn:
                            return 1
                    io = self.__create_ssh_process()
                else:
                    if self.args.local:
                        time.sleep(0.2)
                    io = self.__create_remote_connection()
            
            if self.args.docker and (self.args.debug or self.args.attach):
                try:
                    buf = io.recv(timeout=2)
                    io.unrecv(buf)
                except:
                    log.warning("Failed to connect to docker")
                    exit(1)

                self.__debug_docker(container)

            if not io:
                log.warning("Failed to create process")
                exit(1)

            self.conn = io

        if not enable_log:
            context.log_level = log_level

        return self

    def reconnect(self, enable_log=True):
        if self.conn:
            self.close(enable_log)
        return self.connect(enable_log)

    def close(self, enable_log=True):
        if not self.conn:
            return
        if not enable_log:
            log_level = context.log_level
            context.log_level = "error"
        self.conn.close()
        self.conn = None
        if not enable_log:
            context.log_level = log_level

    def encode(self, data):
        if isinstance(data, int):
            data = str(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        return data

    def prompt(self, data, **kwargs):
        data = self.encode(data)
        r = kwargs.pop("io", self.conn)
        prefix = self.encode(kwargs.pop("prefix", self.config.prefix))
        line = self.encode(kwargs.pop("line", True))
        if prefix is not None:
            if line:
                r.sendlineafter(prefix, data, **kwargs)
            else:
                r.sendafter(prefix, data, **kwargs)
        else:
            if line:
                r.sendline(data, **kwargs)
            else:
                r.send(data, **kwargs)

    def sla(self, *args, **kwargs):
        if len(args) == 1:
            self.prompt(args[0], **kwargs)
        elif len(args) >= 2:
            self.prompt(args[1], prefix=args[0], **kwargs)

    def sa(self, *args, **kwargs):
        self.sla(*args, line=False, **kwargs)

    def sl(self, data, **kwargs):
        self.prompt(data, prefix=None, **kwargs)

    def send(self, data, **kwargs):
        self.prompt(data, prefix=None, line=False, **kwargs)

    def recv(self, prefix=None, **kwargs):
        r = kwargs.pop("io", self.conn)
        line = kwargs.pop("line", False)
        if prefix is None:
            return r.recvline(**kwargs) if line else r.recv(**kwargs)
        elif isinstance(prefix, int):
            return r.recvn(prefix, **kwargs)
        else:
            if isinstance(prefix, str):
                prefix = prefix.encode()
            drop = kwargs.pop("drop", True)
            if line:
                r.recvuntil(prefix, drop=drop, **kwargs)
                return r.recvline(drop=drop, **kwargs)
            else:
                return r.recvuntil(prefix, drop=drop, **kwargs)

    def ru(self, u, **kwargs):   return self.recv(u, **kwargs)
    def rl(self, **kwargs):      return self.recv(line=True, **kwargs)
    def rla(self, d, **kwargs):  return self.recv(d, line=True, **kwargs)
    def ra(self):                return self.recvall()
    def itrv(self):              return self.interactive()
    def urecv(self):             return self.unrecv()

    def rln(self, n, **kwargs):
        return [self.rl(**kwargs) for _ in range(n)]


ioctx = None


def set_ctx(new_ctx: IOContext):
    global ioctx
    ioctx = new_ctx


def _require_ctx():
    if ioctx is None:
        raise RuntimeError("IOContext not initialized — call set_ctx() first")


def _ctx(method_name):
    def wrapper(*args, **kwargs):
        _require_ctx()
        return getattr(ioctx, method_name)(*args, **kwargs)
    wrapper.__name__ = method_name
    return wrapper


def connect(args=None, config=None, default=False):
    global ioctx
    if not args:
        args = ioctx.args
    if not config:
        config = ioctx.config
    io = IOContext(args, config)
    if default:
        ioctx = io
    return io.connect()


reconnect = _ctx("reconnect")
close     = _ctx("close")
prompt    = _ctx("prompt")
sla       = _ctx("sla")
sa        = _ctx("sa")
sl        = _ctx("sl")
send      = _ctx("send")
recv      = _ctx("recv")
ru        = _ctx("ru")
ra        = _ctx("ra")
rl        = _ctx("rl")
rla       = _ctx("rla")
rln       = _ctx("rln")
urecv     = _ctx("unrecv")
clean     = _ctx("clean")
itrv      = _ctx("interactive")
