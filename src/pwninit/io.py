from pwn import process, log, gdb, ssh, remote, context, ELF, pause
from pathlib import Path

NC = 1
SSH = 2

class IOContext:
    def __init__(self, args, chall, prefix):
        self.args = args
        self.chall = chall
        self.prefix = prefix
        self.ssh_conn = None
        self._conn = None
    
    def __create_remote_connection(self):
        conn_type = self.args.remote[0]

        if conn_type == NC:
            ip, port = self.args.remote[1], self.args.remote[2]
            try:
                return remote(ip, port, ssl=self.args.ssl)
            except Exception as e:
                log.error("Failed to connect to %s:%d - %s" % (ip, port, str(e)))

        elif conn_type == SSH:
            user, password, ip, port = self.args.remote[1:5]
            try:
                return ssh(user=user, password=password, host=ip, port=port)
            except Exception as e:
                log.error("SSH connection failed: %s" % str(e))


    def __create_ssh_process(self):
        chall_path = str(Path(self.args.path) / self.chall)
        try:
            if self.args.debug:
                return gdb.debug(chall_path, ssh=self.ssh_conn)
            else:
                return self.ssh_conn.process(chall_path)
        except Exception as e:
            log.error("Failed to create SSH process: %s" % str(e))


    def __create_local_process(self):
        try:
            gdb_script = self.args.gdb_command if self.args.gdb_command else ""
            if self.args.debug:
                return gdb.debug([self.chall], gdbscript=gdb_script)
            elif self.args.strace:
                return process(["strace", "-o", "strace.out", self.chall])
            else:
                p = process(self.chall)
                if self.args.attach:
                    gdb.attach(p, gdbscript=gdb_script)
                    log.info("Attached gdb")
                    pause()
                return p
        except Exception as e:
            log.error("Failed to create local process: %s" % str(e))

    @property
    def conn(self):
        if not self._conn:
            if self.args.local_bin and not self.args.remote:
                self.args.remote = [NC, 'localhost', 1337]
                
            if not self.args.remote or self.args.local_bin:
                io = self.__create_local_process()

            if self.args.remote:
                if self.args.remote[0] == SSH:
                    self.ssh_conn = self.__create_remote_connection()
                    if not self.ssh_conn:
                        return 1
                    io = self.__create_ssh_process()
                else:
                    io = self.__create_remote_connection()

            if not io:
                log.error("Failed to create process")

            self._conn = io
        return self._conn

    @conn.setter
    def conn(self, io):
        return self._conn

    def reconnect(self):
        self._conn.close()
        self._conn = None
        return self.conn
    
    def prompt(self, data, **kwargs):
        if type(data) == int:
            data = str(data).encode()
        elif type(data) == str:
            data = data.encode()

        r = kwargs.pop("io", self._conn)
        prefix = kwargs.pop("prefix", self.prefix)
        line = kwargs.pop("line", True)
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
                return r.recvlineuntil(prefix, drop=drop, **kwargs)
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

ioctx = None

def set_ctx(new_ctx: IOContext):
    global ioctx
    ioctx = new_ctx

def _require_ctx():
    if ioctx is None:
        raise RuntimeError("PwnContext not initialized (call set_ctx first)")

def connect(default=False):
    io = IOContext(ioctx.args, ioctx.chall, ioctx.prefix)
    if default:
        ioctx = io
    return io.conn

reconnect = lambda *a, **k: (_require_ctx(), ioctx.reconnect(*a, **k))[1]

prompt = lambda *a, **k: (_require_ctx(), ioctx.prompt(*a, **k))[1]

sla = lambda *a, **k: (_require_ctx(), ioctx.sla(*a, **k))[1]
sa  = lambda *a, **k: (_require_ctx(), ioctx.sa(*a, **k))[1]
sl  = lambda *a, **k: (_require_ctx(), ioctx.sl(*a, **k))[1]
send = lambda *a, **k: (_require_ctx(), ioctx.send(*a, **k))[1]

recv = lambda *a, **k: (_require_ctx(), ioctx.recv(*a, **k))[1]
ru   = lambda *a, **k: (_require_ctx(), ioctx.ru(*a, **k))[1]
rl   = lambda *a, **k: (_require_ctx(), ioctx.rl(*a, **k))[1]
rla  = lambda *a, **k: (_require_ctx(), ioctx.rla(*a, **k))[1]
rln  = lambda *a, **k: (_require_ctx(), ioctx.rln(*a, **k))[1]
