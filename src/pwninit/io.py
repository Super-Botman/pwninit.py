import subprocess
from dataclasses import dataclass
from pathlib import Path

from pwn import ELF, context, gdb, log, pause, process, remote, ssh

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
            gdb_script = f'''
                set architecture i386:x86-64
                add-symbol-file {self.config.binary} 0xffffffffc0000000
                continue
            '''
            gdb_script += self.args.gdb_cmd if self.args.gdb_cmd else ""
            self.config.chall.append('-s')
            self.config.chall.append('-S')

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

    def connect(self, log=True):
        if not log:
            context.log_level = "error"

        if not self.conn:
            if self.args.local and not self.args.remote:
                self.args.remote = plain('localhost', 5000)
                
            if not self.args.remote or self.args.local and not self.proc:
                io = self.__create_local_process()
                self.proc = io

            if self.args.remote:
                if isinstance(self.args.remote, ssh):
                    if not self.ssh_conn:
                        self.ssh_conn = self.__create_remote_connection()
                        if not self.ssh_conn:
                            return 1
                    io = self.__create_ssh_process()
                else:
                    io = self.__create_remote_connection()

            if not io:
                log.error("Failed to create process")

            self.conn = io

        context.log_level = "info"
        return self.conn

    def reconnect(self, log=True):
        if self.conn:
            self.close(log)
        return self.connect(log)

    def close(self, log=True):
        if not log:
            context.log_level = "error"
        self.conn.close()
        self.conn = None
        context.log_level = "info"

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
