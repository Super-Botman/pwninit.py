import pytest
from pwn import PwnlibException
from pwninit import set_ctx, IOContext, Args, Config, PwnContext, rl, sl, binsh, close

def test_set_ctx(shared_path):
    conf = Config(
        binary="/bin/sh",
        libc=f"{shared_path}/libc.so.6"
    )
    set_ctx(IOContext(Args(), conf))
    from pwninit.context import ioctx, pwnctx

    assert ioctx and not pwnctx
    assert sl("ls") is None
    assert rl().endswith(b"\n")

    set_ctx(PwnContext(ioctx))
    from pwninit.context import pwnctx

    assert pwnctx
    assert binsh()
    close()

    with pytest.raises(PwnlibException) as setctxinfo:
        set_ctx({})

    assert "Invalid" in str(setctxinfo.value)
