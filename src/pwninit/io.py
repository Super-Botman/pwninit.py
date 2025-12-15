from pwn import process, log, gdb, ssh, remote, context, ELF
from pathlib import Path

NC = 1
SSH = 2

class IOContext:
    def __init__(self, args, chall):
        self.args = args
        self.chall = chall
        self.ssh_conn = None
        self._io = None

    @property
    def io(self):
        if self.args.remote:
            if self.args.remote[0] == SSH:
                self.ssh_conn = self.create_remote_connection()
                if not self.ssh_conn:
                    return 1
                io = self.create_ssh_process()
            else:
                io = self.create_remote_connection()
        else:
            io = self.create_local_process()

        if not io:
            log.error("Failed to create process")

        self._io = io
        return self._io

    @io.setter
    def io(self, io):
        return self._io


    def create_remote_connection(self):
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


    def create_ssh_process(self):
        chall_path = str(Path(self.args.path) / self.chall)
        try:
            if self.args.debug:
                return gdb.debug(chall_path, ssh=self.ssh_conn)
            else:
                return self.ssh_conn.process(chall_path)
        except Exception as e:
            log.error("Failed to create SSH process: %s" % str(e))


    def create_local_process(self):
        try:
            if self.args.debug:
                gdb_script = self.args.gdb_command if self.args.gdb_command else ""
                return gdb.debug([self.chall], gdbscript=gdb_script)
            elif self.args.strace:
                return process(["strace", "-o", "strace.out", exploit.CHALL])
            else:
                return process(self.chall)
        except Exception as e:
            log.error("Failed to create local process: %s" % str(e))

    def reconnect(self):
        self._io.close()
        return self.io


ctx = None

def set_ctx(new_ctx: IOContext):
    global ctx
    ctx = new_ctx

def _require_ctx():
    if ctx is None:
        raise RuntimeError("PwnContext not initialized (call set_ctx first)")

reconnect = lambda *a, **k: (_require_ctx(), ctx.reconnect(*a, **k))[1]
