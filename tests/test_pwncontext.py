from pwninit import PwnContext
from pwn import ELF


def test_init(iocontext):
    pwnctx = PwnContext(iocontext)

    assert pwnctx.elf == ELF(iocontext.binary)
