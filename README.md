# pwninit

![Tests Status](https://github.com/Super-Botman/pwninit.py/actions/workflows/tests.yml/badge.svg)

A Python toolkit for CTF binary exploitation. Streamline setup, development, and execution of exploits with automated binary analysis, library management, and template generation.

📖 **Full documentation**: [pwninit.0xb0tm4n.org](https://pwninit.0xb0tm4n.org)

## Installation

```sh
pip install pwninit.py
```

## Basic Usage Example

Setup the chall:

```sh
$ pwninit
```

Edit exploit.py:

```python
from pwninit import *

Config(
    binary="./chall",
    libc="./libc.so.6"
)

def exploit(ctx, io):
    exe = ctx.elf
    libc = ctx.libc

    ctx.offset = 128
    sl(ret2win('shell', ret=False))
    itrv()
```

Run the exploit:

```sh
$ run
```
