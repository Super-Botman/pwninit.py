# pwninit 🚧 WIP 🚧

We're currently redesigning the whole lib with a better code, a lot of helpers to automate exploitation and a lot more parameters to run the exploits.
---

A comprehensive Python toolkit for CTF binary exploitation challenges that streamlines the setup and execution process.

## Features

- **Automated binary analysis** - Automatically detects and categorizes ELF binaries (challenge, libc, linker)
- **Library management** - Fetches matching libc and linker libraries using libcdb
- **Binary patching** - Automatically patches binaries with correct libc/linker using patchelf
- **Template generation** - Creates exploit templates and documentation stubs
- **Multi-target execution** - Supports local, remote (netcat), and SSH execution modes
- **Debugging support** - Integrated GDB debugging with custom commands
- **Provider system** - Extensible system for fetching challenges from various sources
- **Utility plugins** - Modular utilities for common exploitation tasks

## Installation

### Prerequisites
- Python 3.8+
- patchelf
- GDB (for debugging)
- kitty terminal (recommended)

### Install from source
```bash
git clone https://github.com/0xb0tm4n/pwninit.py
cd pwninit.py
python3 -m build

# Install with pipx
pipx install dist/pwninit-0.0.1-py3-none-any.whl

# Install with pip
pip install dist/pwninit-0.0.1-py3-none-any.whl
```

## Usage

### pwninit - Challenge Setup

Initialize a pwn challenge environment:

```bash
# Basic usage - scan current directory for binaries
pwninit

# List Plugins
pwninit -l

# Fetch challenge from provider
pwninit -p rootme https://www.root-me.org/fr/Challenges/App-Systeme/ELF-x86-Stack-buffer-overflow-basic-1

# Fetch libc from docker provider
pwninit -p docker

# Set args for providers
pwninit -p docker -tag 'chall_name'
```

**Options:**
- `-p, --provider <provider>` - Fetch challenge from URL or provider
- `-s, --setup <utils>` - Comma-separated list of utilities to run

### Configuration

pwninit supports configuration through `~/.config/pwninit.conf`:

```ini
author=YourName
```

You can also use environment variables:
- `PWNINIT_AUTHOR` - Override author name

### run - Exploit Execution  

Execute your exploit with various modes:

```bash
# Local execution
run

# Remote netcat connection
run -r target.com:1337

# SSH connection  
run -r user:password@target.com:22

# Debug mode with GDB
run -d

# Debug with custom GDB script
run -d --gdb-command 'break main'

# System call tracing
run -s

# Verbose output
run -v

# SSL/TLS connection
run -r target.com:443 --ssl
```

**Options:**
- `-r, --remote <addr>` - Remote connection (ip:port for nc, user:pass@ip:port for SSH)
- `-d, --debug` - Launch with GDB debugger
- `-s, --strace` - Run with strace, output saved to strace.out
- `--gdb-command <cmd>` - Execute GDB command on startup (requires -d)
- `-v, --verbose` - Enable verbose logging
- `--ssl` - Use SSL/TLS for remote connections

### exploit.py - Exploits development

You can use a variety of helpers from `pwninit.utils`:
```py
from pwn import *
from pwninit.utils import *

CHALL = "./bin"
LIBC = "./libc.so.6"

def exploit(io, elf, libc=Null):

```


## Generated Files

pwninit creates the following files:

- **exploit.py** - Main exploit template with binary and libc paths
- **notes.md** - Documentation template with checksec output and metadata
- **Patched binary** - Original binary patched with correct libc/linker

## TODO

- Add kernel exploitation challenge support
- Implement configurable default utilities and providers
- Expand provider ecosystem with additional sources
- Simplify custom provider and utility development
- Improve terminal integration and display capabilities
- Add support to different challenge types like args, environment, etc.
- Handle jails (fuck jails)
- CTFd provider
- Add option in run to directly use farm for ADs
- Add option to run and debug in docker
