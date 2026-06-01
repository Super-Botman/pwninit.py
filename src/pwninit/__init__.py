from pwn import *
from .io import *
from .helpers import *
from types import SimpleNamespace

from .io import ioctx
from .helpers import pwnctx

config = None


class Config(SimpleNamespace):
    def __init__(
        self,
        binary=None,
        libc=None,
        chall=None,
        env={},
        archive=None,
        kernel=None,
        prefix=None,
        **kwargs,
    ):
        global config
        if binary and not chall:
            chall = binary
        super().__init__(
            binary=binary,
            libc=libc,
            chall=chall,
            env=env,
            archive=archive,
            kernel=kernel,
            prefix=prefix,
            **kwargs,
        )
        config = self
