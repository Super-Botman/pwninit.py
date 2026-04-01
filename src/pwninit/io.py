import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import docker
from pwn import context, gdb, log, pause, process, remote, ssh

from pwninit.kernel import inject


@dataclass
class plain:
    host: str
    port: int

@dataclass
class ssh:
    user: str
    password: str
    host: str
    port: int = 22

class IOContext:
    def __init__(self, args, config, prefix=None, proc=None, conn=None, ssh_conn=None):
        self.args = args
        self.config = config
        self.prefix = prefix
        self.ssh_conn = ssh_conn
        self.conn = conn
        self.proc = proc
    
    def __create_remote_connection(self):
        if isinstance(self.args.remote, plain):
            try:
                return remote(self.args.remote.host, self.args.remote.port, ssl=self.args.ssl)
            except Exception as e:
                log.error("Failed to connect to %s:%d - %s" % (self.args.remote.host, self.args.remote.port, str(e)))

        elif isinstance(self.args.remote, ssh):
            try:
                return ssh(user=self.args.remote.user, password=self.args.remote.password, host=self.args.remote.host, port=self.args.remote.port)
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
                return self.ssh_conn.process(chall_path)
        except Exception as e:
            log.error("Failed to create SSH process: %s" % str(e))


    def __create_kernel_process(self):
        status = log.progress('compiling exploit')
        subprocess.run(
            ["make"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        status.success('done')

        status = log.progress('injecting exploit')
        if not inject(self.config.archive, "exploit"):
            status.failure("failed")

        status.success('done')
        if self.args.debug:
            gdb_script = self.args.gdb_cmd if self.args.gdb_cmd else ""
            self.config.chall.append('-s')

        p = process(self.config.chall)

        if self.args.debug:
            gdb.attach(
                target=('localhost', 1234),
                exe=f'{self.config.kernel}.elf',
                gdbscript=gdb_script
        )

        return p
        

    def __create_local_process(self):
        try:
            if self.config.archive:
                return self.__create_kernel_process()

            gdb_script = self.args.gdb_cmd if self.args.gdb_cmd else ""
            if self.args.debug:
                return gdb.debug([self.config.chall], gdbscript=gdb_script)
            elif self.args.strace:
                return process(["strace", "-o", "strace.out", self.config.chall])
            else:
                p = process(self.config.chall)
                if self.args.attach:
                    gdb.attach(p, gdbscript=gdb_script)
                    log.info("Attached gdb")
                    pause()
                return p
        except Exception as e:
            log.error("Failed to create local process: %s" % str(e))

    def __launch_docker(self):
        client = docker.from_env()

        path = Path('.')
        name = path.resolve().name
        image_tag = self.config.docker_image if hasattr(self.config, 'docker_image') else f"pwninit-{name}:latest"

        containers = client.containers.list()
        container = None
        for c in containers:
            if c.image.tags[-1] == image_tag:
                container = c
                
        if not container:
            try:
                container = client.containers.run(
                    image_tag,
                    pid_mode="host",
                    ports={f'{self.args.remote.port}/tcp': self.args.remote.port},
                    privileged=True,
                    detach=True
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
                log.warning("No socat running nor binary, set directly the docker_bin in Config")
                exit(1)

        print(pid)
        if not pid:
            for p in processes['Processes']:
                if bin in p[-1]:
                    pid = int(p[1])

        if not pid:
            log.warning("Bin isn't running, check that Dockerfile is working or bin is correct")
            exit(1)

        gdb.attach(pid, exe=self.config.binary)

    def connect(self, log=True):
        if not log:
            log_level = context.log_level
            context.log_level = "error"

        if not self.conn:
            if (self.args.local or self.args.docker) and not self.args.remote:
                self.args.remote = plain('localhost', 5000)
                
            if not self.args.remote or self.args.local and not self.proc:
                io = self.__create_local_process()
                self.proc = io

            if self.args.docker:
                container = self.__launch_docker()

            if self.args.remote:
                if isinstance(self.args.remote, ssh):
                    if not self.ssh_conn:
                        self.ssh_conn = self.__create_remote_connection()
                        if not self.ssh_conn:
                            return 1
                    io = self.__create_ssh_process()
                else:
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

        if not log:
            context.log_level = log_level

        return self.conn

    def reconnect(self, log=True):
        if self.conn:
            self.close(log)
        return self.connect(log)

    def close(self, log=True):
        if not log:
            log_level = context.log_level
            context.log_level = "error"
        self.conn.close()
        self.conn = None
        if not log:
            context.log_level = log_level

    def encode(self, data):
        if type(data) == int:
            data = str(data).encode()
        elif type(data) == str:
            data = data.encode()
        return data
    
    def prompt(self, data, **kwargs):
        data = self.encode(data)

        r = kwargs.pop("io", self.conn)
        prefix = self.encode(kwargs.pop("prefix", self.prefix))
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
            if line:
                return r.recvline(**kwargs)
            else:
                return r.recv(**kwargs)
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

    def ru(self, u, **kwargs):
        return self.recv(u, **kwargs)

    def rl(self, **kwargs):
        return self.recv(line=True, **kwargs)

    def rla(self, d, **kwargs):
        return self.recv(d, line=True, **kwargs)

    def rln(self, n, **kwargs):
        lines = []
        for _ in range(n):
            lines.append(self.rl(**kwargs))
        return lines

    def ra(self):
        return self.conn.recvall()

ioctx = None

def set_ctx(new_ctx: IOContext):
    global ioctx
    ioctx = new_ctx

def _require_ctx():
    if ioctx is None:
        raise RuntimeError("PwnContext not initialized (call set_ctx first)")

def connect(host=None, port=None, default=False):
    global ioctx

    if host is not None:
        ioctx.args.remote[1] = host

    if port is not None:
        ioctx.args.remote[2] = port

    io = IOContext(ioctx.args, ioctx.chall, ioctx.prefix, ioctx.conn)
    if default:
        ioctx = io
    return io.connect()

reconnect = lambda *a, **k: (_require_ctx(), ioctx.reconnect(*a, **k))[1]
close = lambda *a, **k: (_require_ctx(), ioctx.close(*a, **k))[1]

prompt = lambda *a, **k: (_require_ctx(), ioctx.prompt(*a, **k))[1]

sla = lambda *a, **k: (_require_ctx(), ioctx.sla(*a, **k))[1]
sa  = lambda *a, **k: (_require_ctx(), ioctx.sa(*a, **k))[1]
sl  = lambda *a, **k: (_require_ctx(), ioctx.sl(*a, **k))[1]
send = lambda *a, **k: (_require_ctx(), ioctx.send(*a, **k))[1]

recv = lambda *a, **k: (_require_ctx(), ioctx.recv(*a, **k))[1]
ru   = lambda *a, **k: (_require_ctx(), ioctx.ru(*a, **k))[1]
ra   = lambda *a, **k: (_require_ctx(), ioctx.ra(*a, **k))[1]
rl   = lambda *a, **k: (_require_ctx(), ioctx.rl(*a, **k))[1]
rla  = lambda *a, **k: (_require_ctx(), ioctx.rla(*a, **k))[1]
rln  = lambda *a, **k: (_require_ctx(), ioctx.rln(*a, **k))[1]

urecv = lambda *a, **k: (_require_ctx(), ioctx.conn.unrecv(*a, **k))[1]
clean = lambda *a, **k: (_require_ctx(), ioctx.conn.clean(*a, **k))[1]
itrv = lambda *a, **k: (_require_ctx(), ioctx.conn.interactive(*a, **k))[1]
