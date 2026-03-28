from pwn import *
from .io import *
from .helpers import *
from types import SimpleNamespace

config = None

class Config(SimpleNamespace):
    def __init__(self, binary=None, libc=None, chall=None, archive=None, kernel=None):
        global config
        if binary and not chall: chall=binary
        super().__init__(binary=binary, libc=libc, chall=chall, archive=archive, kernel=kernel)
        config = self
