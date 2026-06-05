import pytest
from pwn import PwnlibException
from pwninit import set_ctx, ioctx, pwnctx, IOContext, Args, Config, PwnContext, rl, sl, binsh, close
from conftest import path

def test_set_ctx():
    conf = Config(
        binary="/bin/sh",
        libc=f"{path}/libc.so.6"
    )
    set_ctx(IOContext(Args(), conf))
    assert sl("ls") is None
    assert rl().endswith(b"\n")

    set_ctx(PwnContext(ioctx))
    assert binsh()
    close()

    with pytest.raises(PwnlibException) as setctxinfo:
        set_ctx({})

    assert "Invalid" in str(setctxinfo.value)
