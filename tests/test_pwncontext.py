import logging
from unittest.mock import MagicMock
import pytest
from pwninit import PwnContext, cyclic
from pwn import ELF, PwnlibException

LOGGER = logging.getLogger(__name__)

def test_init(ioctx):
    pwnctx = PwnContext(ioctx)
    assert isinstance(pwnctx.elf, ELF)
    assert isinstance(pwnctx.libc, ELF)


    ioctx.config.binary = ELF(ioctx.config.binary)
    ioctx.config.libc = ELF(ioctx.config.libc)
    pwnctx = PwnContext(ioctx)
    assert isinstance(pwnctx.elf, ELF)
    assert isinstance(pwnctx.libc, ELF)

def test_canary(ioctx, caplog):
    caplog.set_level(logging.INFO)
    pwnctx = PwnContext(ioctx)
    
    pwnctx.canary = 0xdeadbeef
    assert pwnctx.canary == 0xdeadbeef

def test_resolve(ioctx, caplog):
    pwnctx = PwnContext(ioctx)
    main_off = 0x4011b7
    
    assert pwnctx.resolve(0x401000) == 0x401000

    assert pwnctx.resolve("main") == main_off
    assert pwnctx.resolve("main+0x10") == main_off+0x10
    assert pwnctx.resolve("main + 0x20") == main_off+0x20
    assert pwnctx.resolve("main-0x50") == main_off-0x50

    caplog.set_level(logging.ERROR)
    with pytest.raises(PwnlibException) as resolve_failed:
        pwnctx.resolve("non_existent_symbol")

    assert "not found" in str(resolve_failed.value)

def test_check_and_find_leak(ioctx):
    pwnctx = PwnContext(ioctx)
    pwnctx._canary = 0x0011223344556677
    
    ioctx.proc = None
    assert pwnctx.check_leak(0x401000) == (None, None)
    
    # Restore mock process & memory mapping regions
    ioctx.proc = MagicMock()
    ioctx.maps = MagicMock(return_value=[
        MagicMock(path="/usr/lib/libc.so.6", start=0x7ffff7a00000, end=0x7ffff7bc0000),
        MagicMock(path="/challenge/binary", start=0x400000, end=0x402000)
    ])

    assert pwnctx.check_leak(0x0011223344556677) == ("canary", 0x0011223344556677)

    leak_type, _ = pwnctx.check_leak(0x7ffff7a15000)
    assert leak_type == "libc"

    raw_buffer = b"Data received: 0x7ffff7a15000\n"
    assert pwnctx.find_leak(raw_buffer) == 0x7ffff7a15000


def test_ropchain(ioctx):
    pwnctx = PwnContext(ioctx)
    pwnctx.libc.address = 0x500000

    chain = {"system": ["/bin/sh"]}
    payload = pwnctx.ropchain(chain)
    assert b"/bin/sh" in payload


def test_bof_payload_generation(ioctx):
    pwnctx = PwnContext(ioctx)
    pwnctx.offset = 40
    pwnctx.canary = 0x11223344

    payload_simple = pwnctx.bof(data=0x401000, bp=0x11223344)
    assert len(payload_simple) == 44
    assert payload_simple.startswith(cyclic(32))
    assert payload_simple[36:40] == b"\x44\x33\x22\x11"
    assert payload_simple[40:44] == b"\x00\x10\x40\x00"

    payload_protected = pwnctx.bof(data=0x401000)
    assert payload_protected[32:36] == b"\x44\x33\x22\x11"
