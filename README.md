# pwninit

A comprehensive Python toolkit for CTF binary exploitation challenges that streamlines the setup and execution process.

## 🚀 Features

- **Automated binary analysis** - Automatically detects and categorizes ELF binaries (challenge, libc, linker)
- **Library management** - Fetches matching libc and linker libraries using libcdb
- **Binary patching** - Automatically patches binaries with correct libc/linker using patchelf
- **Template generation** - Creates exploit templates and documentation stubs
- **Multi-target execution** - Supports local, remote (netcat), and SSH execution modes
- **Debugging support** - Integrated GDB debugging with custom commands
- **Provider system** - Extensible system for fetching challenges from various sources
- **Utility plugins** - Modular utilities for common exploitation tasks

## 📦 Installation

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

## 🛠 Usage

### pwninit - Challenge Setup

Initialize a pwn challenge environment:

```bash
# Basic usage - scan current directory for binaries
pwninit

# Fetch challenge from provider
pwninit -p https://www.root-me.org/fr/Challenges/App-Systeme/ELF-x86-Stack-buffer-overflow-basic-1

# Run utilities during setup  
pwninit -u menu,docker
```

**Options:**
- `-p, --provider <provider>` - Fetch challenge from URL or provider
- `-u, --utils <utils>` - Comma-separated list of utilities to run

### Configuration

pwninit supports configuration through `~/.config/pwninit.conf`:

```ini
# Author name for generated files
author=YourName

# Root-me provider settings
rootme_api_key=your_api_key_here
```

You can also use environment variables:
- `PWNINIT_AUTHOR` - Override author name
- `ROOTME_API_KEY` - Root-me API key for provider authentication

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

## 📁 Generated Files

pwninit creates the following files:

- **exploit.py** - Main exploit template with binary and libc paths
- **notes.md** - Documentation template with checksec output and metadata
- **Patched binary** - Original binary patched with correct libc/linker

## 🔧 Providers

Extend pwninit with custom challenge sources:

```python
# src/pwninit/providers/custom.py
def run(url, path):
    # Download and extract challenge
    return challenge_path
```

## 🛠 Utilities  

Add custom utilities for common tasks:

```python  
# src/pwninit/utils/custom.py
def run(files, bins, path):
    # Modify generated files or perform setup tasks
    return files
```

Built-in utilities:
- **menu** - Generate menu interaction functions
- **docker** - Set up Docker environment for libc testing

## 🏗 Project Structure

```
src/pwninit/
├── pwninit.py      # Main challenge setup logic
├── run.py          # Exploit execution runner  
├── providers/      # Challenge source providers
├── utils/          # Setup utilities
└── templates/      # File templates
```

## 📋 TODO

- Add kernel exploitation challenge support
- Implement configurable default utilities and providers
- Expand provider ecosystem with additional sources
- Simplify custom provider and utility development
- Enhance exploit templates with advanced features
- Improve terminal integration and display capabilities
- Add support to different challenge types like args, environment, etc.
- Handle jails (fuck jails)
- CTFd provider

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👤 Author

- **0xb0tm4n** - [@0xb0tm4n](https://github.com/Super-Botman)

## 🙏 Acknowledgments

- [pwntools](https://github.com/Gallopsled/pwntools) - The Swiss army knife of CTF tools
- [libcdb](https://libc.rip/) - Libc database and download service
