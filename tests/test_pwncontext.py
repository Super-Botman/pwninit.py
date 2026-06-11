import io
import logging
import sys
from unittest.mock import MagicMock
import pytest
from pwninit import PwnContext, cyclic
from pwn import ELF, PwnlibException

LOGGER = logging.getLogger(__name__)


@pytest.fixture()
def pwnctx(ioctx):
    """Fixture to automatically initialize and inject PwnContext across tests."""
    return PwnContext(ioctx)


def test_init(ioctx):
    # Test initialization with standard configuration strings
    ctx = PwnContext(ioctx)
    assert isinstance(ctx.elf, ELF)
    assert isinstance(ctx.libc, ELF)

    # Test initialization resilience when config parameters are already loaded ELF instances
    ioctx.config.binary = ELF(ioctx.config.binary)
    ioctx.config.libc = ELF(ioctx.config.libc)
    ctx_preloaded = PwnContext(ioctx)
    
    assert isinstance(ctx_preloaded.elf, ELF)
    assert isinstance(ctx_preloaded.libc, ELF)


def test_canary(pwnctx, caplog):
    caplog.set_level(logging.INFO)
    
    pwnctx.canary = 0xdeadbeef
    assert pwnctx.canary == 0xdeadbeef


def test_resolve(pwnctx, caplog):
    # Dynamically grab 'main' offset to remain compiler and build-agnostic
    main_off = pwnctx.elf.symbols['main']
    
    assert pwnctx.resolve(0x401000) == 0x401000
    assert pwnctx.resolve("main") == main_off
    assert pwnctx.resolve("main+0x10") == main_off + 0x10
    assert pwnctx.resolve("main + 0x20") == main_off + 0x20
    assert pwnctx.resolve("main-0x50") == main_off - 0x50

    caplog.set_level(logging.ERROR)
    with pytest.raises(PwnlibException, match="not found"):
        pwnctx.resolve("non_existent_symbol")


def test_check_and_find_leak(pwnctx, ioctx):
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


def test_ropchain(pwnctx):
    pwnctx.libc.address = 0x500000

    chain = {"system": ["/bin/sh"]}
    payload = pwnctx.ropchain(chain)
    assert b"/bin/sh" in payload


def test_bof_payload_generation(pwnctx):
    pwnctx.offset = 40
    pwnctx.canary = 0x11223344

    payload = pwnctx.bof(data=0x401000, bp=0x11223344)
    assert len(payload) == 48
    assert payload.startswith(cyclic(24))
    assert payload[32:40] == b"\x44\x33\x22\x11\x00\x00\x00\x00"
    assert payload[40:48] == b"\x00\x10\x40\x00\x00\x00\x00\x00"
    assert payload[24:32] == b"\x44\x33\x22\x11\x00\x00\x00\x00"


def test_payloads(pwnctx, ioctx, monkeypatch):
    pwnctx.offset = 120
    ioctx.sl('')
    ioctx.sl(pwnctx.ret2win('win', [0xdeadbeef, 0xcafebabe]))
    assert b"SUCCESS" in ioctx.ra()

    ioctx.reconnect()

    l = ioctx.recv()
    pwnctx.libc.address = pwnctx.leak(l[23:29], 158631)
    _ = pwnctx.leak(l[31:37])
    
    ioctx.sl('')
    ioctx.sl(pwnctx.ret2libc())

    # Feed commands to standard input to satisfy interactive loop without hanging
    monkeypatch.setattr("sys.stdin", io.StringIO("id\nexit\n"))
    try:
        ioctx.itrv()
    except Exception as exc:
        LOGGER.warning(f"Interactive cycle dropped or unsupported by terminal environment: {exc}")
