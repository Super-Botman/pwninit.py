from pwn import *
from .io import *
from .pwncontext import *
from .helpers import *
from .context import *
from types import SimpleNamespace

config = None

class Config(SimpleNamespace):
    """A configuration container for exploit development and CTF challenges.

    Inherits from `SimpleNamespace` to allow attribute-style access (e.g., `config.binary`).
    Upon instantiation, it automatically updates a global `config` variable to point 
    to the latest instance, allowing global access to the configuration state.

    Attributes:
        binary (ELF | str | None): The main target binary file or ELF object.
        libc (ELF | str | None): The companion Libc library file or ELF object.
        libs (list): A list of paths to additional shared libraries required by the binary.
        chall (list | str): The challenge definition, defaults to the `binary` value if not specified.
        env (dict): Environment variables to pass to the process during execution.
        archive (str): Path to an archive file (e.g., zip, tar) containing the fs for kernel challenges.
        kernel (str): Path to a kernel image (e.g., bzImage) for kernel challenges.
        prefix (str): A prefix string used for io interaction.
        **kwargs: Arbitrary keyword arguments dynamically attached as attributes, can be used by anything.
    """
    def __init__(
        self,
        binary: ELF | str | None = None,
        libc: ELF | str | None = None,
        libs: list = [],
        chall: list | str = [],
        env: dict = {},
        archive: str = "",
        kernel: str = "",
        prefix: str ="",
        **kwargs,
    ):
        global config
        if binary and not chall:
            chall = binary
        super().__init__(
            binary=binary,
            libc=libc,
            libs=libs,
            chall=chall,
            env=env,
            archive=archive,
            kernel=kernel,
            prefix=prefix,
            **kwargs,
        )
        config = self
