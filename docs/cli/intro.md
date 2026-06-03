# CLI

## pwninit - Challenge Setup

Initialize a pwn challenge environment:

```sh
# Basic usage - scan current directory for binaries
pwninit

# List available plugins
pwninit -l

# Fetch challenge from a provider (e.g., RootMe)
pwninit -p rootme https://www.root-me.org/fr/Challenges/App-Systeme/ELF-x86-Stack-buffer-overflow-basic-1

# Fetch libc from Docker provider
pwninit -p docker

# Set arguments for providers (e.g., Docker tag)
pwninit -p docker -tag 'chall_name'
```

**Options:**

- `-p, --provider <provider>` - Set provider to run (e.g., `docker`, `rootme`, `pwncollege`)
- `-s, --setup <utils>` - Comma-separated list of utilities to run

---

## run - Exploit Execution

Execute your exploit with various modes:

```sh
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

- `-r, --remote <addr>` - Remote connection (`ip:port` for nc, `user:pass@ip:port` for SSH)
- `-d, --debug` - Launch with GDB debugger
- `-s, --strace` - Run with strace, output saved to `strace.out`
- `--gdb-command <cmd>` - Execute GDB command on startup (requires `-d`)
- `-v, --verbose` - Enable verbose logging
- `--ssl` - Use SSL/TLS for remote connections
