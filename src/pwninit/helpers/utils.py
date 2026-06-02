import math
import re
from subprocess import run, PIPE, DEVNULL

from pwninit.config import config
from pwninit.helpers.constants import *
from pwn import ELF, ROP, asm, context, log, rol, ror, unpack, flat
from pwn import u64 as pu64
from pwn import u32 as pu32
from pwn import u16 as pu16

u64 = lambda d: pu64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pu32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pu16(d.ljust(2, b"\0")[:2])
upack = lambda d: unpack(d.ljust(context.bits // 8, b"\x00"), context.bits)


class HouseOfMuney:
    """Exploitation helper for the House of Muney technique.
    
    This class facilitates dynamic symbol table (`.dynsym`) rewriting 
    to hijack function resolution in dynamically linked ELF binaries.
    """

    def __init__(self, elf: ELF):
        """Initialize the HouseOfMuney context.

        Args:
            elf (ELF): The target ELF binary.
        """
        self.elf = elf
        self.payload = self.elf.get_segment_for_address(0).data()
        self.dynsym = self.elf.get_section_by_name(".dynsym")
        self.gnuhash = self.elf.get_section_by_name(".gnu.hash")

    def strtab(self) -> int:
        """Get the offset to the string table."""
        return self.dynsym.stringtable.header["sh_offset"]

    def symbol_offset(self, name: str | bytes) -> int:
        """Locate the exact binary offset of a specific symbol inside `.dynsym`.

        Args:
            name (str | bytes): The name of the symbol to find.

        Returns:
            int: The absolute offset, or -1 if not found.
        """
        sym = self.get_sym(name)
        if sym is None:
            return -1

        p = flat(self.dynsym.structs.Elf_Sym.build(sym))
        offset = self.dynsym.data().find(p)
        if offset == -1:
            return -1
        return self.dynsym.header["sh_offset"] + offset

    def get_sym(self, name: str | bytes):
        """Retrieve the raw symbol entry via the GNU hash table.

        Args:
            name (str | bytes): The target symbol name.
        """
        return self.gnuhash.get_symbol(name).entry

    def set_sym(self, name: str | bytes, sym):
        """Overwrite an existing symbol entry in the ELF data payload.

        Args:
            name (str | bytes): The symbol name.
            sym: The struct built entry to write back.
        """
        off = self.symbol_offset(name)
        self.write(off, self.dynsym.structs.Elf_Sym.build(sym))

    def set_call(self, name: str | bytes, offset: int, data: bytes = b"sh\0"):
        """Hijack a symbol to act as a GNU indirect function (IFUNC) call.

        Args:
            name (str | bytes): The symbol to hijack.
            offset (int): The target execution offset.
            data (bytes): Data to inject into the string table (default: `b"sh\\0"`).
        """
        sym = self.get_sym(name)
        idx = u32(data)
        sym["st_name"] = idx
        sym["st_value"] = offset
        # Note: STT_GNU_IFUNC must be available in your local scope/constants
        sym["st_info"]["type"] = STT_GNU_IFUNC 
        self.set_sym(name, sym)
        self.write(self.strtab() + idx, name)
        self.write(self.strtab() + idx + len(name), b"\0")

    def set_offset(self, name: str | bytes, offset: int):
        """Directly patch the virtual value offset of a specific symbol.

        Args:
            name (str | bytes): The symbol to patch.
            offset (int): The new offset value.
        """
        sym = self.get_sym(name)
        sym["st_value"] = offset
        self.set_sym(name, sym)

    def write(self, addr: int, data: bytes | str):
        """Patch the internal ELF payload memory representation.

        Args:
            addr (int): The starting address offset.
            data (bytes | str): The raw bytes to write.
        """
        if isinstance(data, str):
            data = data.encode()
        elif not isinstance(data, bytes):
            raise ValueError("Data must be bytes or str")
            
        if addr < 0 or addr + len(data) > len(self):
            raise IndexError("Write out of bounds")
            
        self.payload = self.payload[:addr] + data + self.payload[addr + len(data) :]

    def read(self, addr: int, size: int) -> bytes:
        """Read a chunk from the internal ELF payload memory representation.

        Args:
            addr (int): The starting address offset.
            size (int): Amount of bytes to read.
        """
        return self.payload[addr : addr + size]

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        return self.payload


def _get_binary(name: str):
    # Note: Requires `config` to be imported/defined in the environment
    b = config.get(name, default=None)
    if b is None:
        log.warn(f"Proof of work binary for {name} not found in config")
    return b


def solve_sossette(data: bytes) -> bytes | None:
    """Solve sossette proof of work."""
    binary = _get_binary("sossette")
    if binary is None:
        return None

    prefix = re.findall(rb"SHA256\(([0-9A-Za-z]+) ", data)
    difficulty = re.findall(rb"starts with (\d+) bits", data)
    if len(prefix) == 0 or len(difficulty) == 0:
        log.error(f"Proof of work failed (sossette): {data}")

    prefix = prefix[0]
    difficulty = difficulty[0]
    p = run([binary, prefix, difficulty], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (sossette): {data}")

    return p.stdout


def solve_hxp(data: bytes) -> bytes | None:
    """Solve hxp proof of work."""
    binary = _get_binary("hxp")
    if binary is None:
        return None

    prefix = re.findall(rb"sha256\(unhex\(\"([0-9A-fa-f]+)\"", data)
    difficulty = re.findall(rb"ends with (\d+) zero", data)
    if len(prefix) == 0 or len(difficulty) == 0:
        log.error(f"Proof of work failed (hxp): {data}")

    prefix = prefix[0]
    difficulty = difficulty[0]
    p = run([binary, difficulty, prefix], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (hxp): {data}")

    return p.stdout


def solve_redpwn(data: bytes) -> bytes | None:
    """Solve redpwn proof of work."""
    binary = _get_binary("redpwn")
    if binary is None:
        return None

    arg = re.findall(rb"\| sh -s (.+)\n", data)
    if len(arg) == 0:
        log.error(f"Proof of work failed (redpwn): {data}")

    arg = arg[0]
    p = run([binary, "solve", arg], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (redpwn): {data}")

    return p.stdout


def solve_kctf(data: bytes) -> bytes | None:
    """Solve kctf proof of work."""
    binary = _get_binary("kctf")  
    if binary is None:
        return None

    arg = re.findall(rb"\) solve (.+)\n", data)
    if len(arg) == 0:
        log.error(f"Proof of work failed (kctf): {data}")

    arg = arg[0]
    p = run([binary, arg], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (kctf): {data}")

    return p.stdout


def solve_hashcash(data: bytes) -> bytes | None:
    """Solve hashcash proof of work."""
    binary = _get_binary("hashcash")
    if binary is None:
        return None

    cmd = re.findall(rb"hashcash (-m.*?b\d+) ([0-9A-Za-z+/]+)", data)
    if len(cmd) == 0:
        log.error(f"Proof of work failed (hashcash): {data}")

    cmd = cmd[0]
    p = run([binary, cmd[0], cmd[1]], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (hashcash): {data}")

    return p.stdout


def solve_pow(data: bytes) -> bytes | None:
    """Take a buffer, detect the proof of work type, and solve it.

    Args:
        data (bytes): The buffer containing the PoW challenge string.
    """
    functions = {
        b"Please provide an ASCII printable": solve_sossette,
        b"give S such that sha256": solve_hxp,
        b"https://pwn.red/pow": solve_redpwn,
        b"please solve a pow first": solve_kctf,
        b"hashcash": solve_hashcash,
    }

    for s, f in functions.items():
        if s in data:
            return f(data).strip()

    log.warn(f"Unknown proof of work: {data}")
    return None


def getb(d: bytes | str, a: bytes | str, b: bytes | str) -> bytes | str:
    """Extract a substring between two delimiters.

    Args:
        d (bytes | str): The data to search in.
        a (bytes | str): The start delimiter.
        b (bytes | str): The end delimiter.

    Returns:
        bytes | str: The isolated substring.

    Example:
    
        >>> getb(b"Here is the [secret] data", b"[", b"]")
        b'secret'
    """
    a_ = d.find(a)
    if a_ == -1 or len(a) == 0:
        a_ = 0
    b_ = d.find(b, a_ + len(a))
    if b_ == -1 or len(b) == 0:
        b_ = len(d)
    return d[a_ + len(a) : b_]


def getr(d: bytes | str, p: str) -> bytes | str:
    """Extract the first match of a regex pattern from the data.

    Args:
        d (bytes | str): The data to search in.
        p (str): The regex pattern.

    Returns:
        bytes | str: The first match of the pattern.
        
    Example:
    
        >>> getr("Leak: 0x7ffff7e45000", r"0x[0-9a-f]+")
        '0x7ffff7e45000'
    """
    return re.findall(p, d)[0]


def safelink_bf64(ptr: int) -> int:
    """Recover a safelinked next pointer assuming both next & addr are in the same page.

    Args:
        ptr (int): The mangled/safelinked next value.
        
    Returns:
        int: The brute-forced original pointer.
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
    """Print hex formatted values for debugging specified keyword arguments.

    Args:
        **kwargs: Key-value pairs to print.

    Example:
    
        >>> printx(libc_base=0x7ffff7e00000, heap=0x555555559000)
        [+] libc_base: 0x7ffff7e00000
        [+] heap: 0x555555559000
    """
    for k, v in kwargs.items():
        log.success("%s: %#x" % (k, v))


def hexdump(data: bytes, s: int = context.word_size // 8):
    """Print an aligned hexdump of the specified data payload.

    Args:
        data (bytes): The data to dump.
        s (int): The size of each chunk in bytes (default: machine word size).
    """
    idx_max = math.ceil(math.log(len(data), 16))
    for i in range(0, len(data), s):
        log.info(f"%0{idx_max}x: %#0{2 * s + 2}x" % (i, u64(data[i : i + s])))


def safelink(addr: int, ptr: int) -> int:
    """Compute the glibc >= 2.32 safelink value for a fastbin/tcache pointer.

    Args:
        addr (int): The storage address of the pointer.
        ptr (int): The actual target pointer value.

    Returns:
        int: The masked value to write to memory.
        
    Example:
    
        >>> safelink(0x555555559010, 0x555555559050)
        0x55555000c040
    """
    return (addr >> 12) ^ ptr


def ptr_mangle(addr: int, cookie: int = 0) -> int:
    """Mangle a pointer (e.g., setjmp/longjmp or exit handlers) with a TLS cookie.

    Args:
        addr (int): The raw memory address.
        cookie (int): The thread-local pointer guard cookie.

    Returns:
        int: The heavily mangled value.
    """
    return rol(addr ^ cookie, 17)


def ptr_demangle(addr: int, cookie: int = 0) -> int:
    """Demangle a pointer previously protected by a TLS pointer guard.

    Args:
        addr (int): The mangled memory address.
        cookie (int): The thread-local pointer guard cookie.

    Returns:
        int: The resolved raw memory address.
    """
    return ror(addr, 17) ^ cookie


def ptr_cookie(mangled: int, demangled: int) -> int:
    """Compute the thread-local pointer guard cookie given a known pointer pair.

    Args:
        mangled (int): The protected value found in memory.
        demangled (int): The expected/known original value.

    Returns:
        int: The underlying cookie guard value.
    """
    return ptr_demangle(mangled, demangled)


def jitspray(code: str, size: int = 8, jmp: bytes = b"\xeb\x03") -> list[int]:
    """Perform a jitspray with `movabs` on x64 by default.

    Args:
        code (str): Multi-line assembly code string.
        size (int): Maximum code part size (default 8 for movabs).
        jmp (bytes): Stub for jumping between code parts.
        
    Returns:
        list[int]: Array of packed integer values representing the spray.
    """
    code_parts = [asm(c) for c in code.splitlines()]
    size -= len(jmp)
    parts = [b""]
    for c in code_parts:
        if len(c) > size:
            log.error(f"jitspray(): code part {c.hex()} too long for maximum size {size}")
            
        p = parts[-1]
        if len(p) + len(c) > size:
            parts[-1] = p.ljust(size, b"\x90") + jmp
            parts.append(c)
        else:
            parts[-1] += c
            
    return [u64(p) for p in parts]


def encode(data: str | int | bytes) -> bytes:
    """Encode strings or integers into a raw byte format safely.

    Args:
        data: The payload to encode.

    Returns:
        bytes: The sanitized byte array.
    """
    if isinstance(data, int):
        data = str(data).encode()
    elif isinstance(data, str):
        data = data.encode()
    return data
