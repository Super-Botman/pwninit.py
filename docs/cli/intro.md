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

### Generated Files

`pwninit` automatically generates the following files in your working directory:

- **exploit.py** - Main exploit template with pre-configured binary and libc paths
- **exploit.c** - C exploit template for kernel exploitation
- **notes.md** - Documentation template with checksec output, binary metadata, and exploit development notes
- **Makefile** - Pre-configured Makefile for compiling exploits
- **Patched binary** - Original binary patched with the correct libc/linker

### Configuration

`pwninit` supports configuration through `~/.config/pwninit.conf`:

```ini
author="YourName"
```

You can also use environment variables:

- `PWNINIT_AUTHOR` - Override author name
- `PWNINIT_PROVIDER` - Default provider to use

---

## run - Exploit Execution

Execute your exploit with various modes:

```sh
# Local execution
run

# Remote netcat connection
run -r target.com:1337

# SSH connection
run -r user:password@target.com:22:/path

# Start the docker built during pwninit
run -D

# Debug mode with GDB
run -d

# Debug with GDB inside docker container
run -D -d

# Debug with custom GDB script
run -d -g 'break main'

# System call tracing
run -s

# Verbose output
run -v

# SSL/TLS connection
run -r target.com:443 --ssl

# Uses S4Dfarm as a target source
run -f -u https://farm.example.com -k password123 -r :2371
```

**Options:**

- `-v --verbose` - Enable verbose logging
- `-r --remote <addr>` - Remote connection (`ip:port` for nc, `user:pass@ip:port:path` for SSH)
- `-l --local <port> (default 5000)` - Start chall as local process but set conn as a remote connection (to target servers for example)
- `-S` `--ssl` - Use SSL/TLS for remote connections
- `-d --debug` - Launch with GDB debugger
- `-a --attach` - Attach to the process instead of starting with debugger
- `-D --docker` - Use the image build during pwninit
- `-g --gdb-command <cmd>` - Execute GDB command on startup (requires `-d` or `-a`)
- `-s --strace` - Run with strace, output saved to `strace.out`
- `-f --farm` - Farm mode
- `-u --url` - Set the url for the farm (require `-f`)
- `-k --password` - Set the password for the farm (require `-f`)
- `-t --period` - Set the period for the farm (require `-f`)
- `-j --jobs` - Set the number of jobs for the farm (require `-f`)

### Exploits

To help the development of exploits `pwninit.py` provide a handful of methods and classes via it library.

In this part we'll focus on the exploit development using `run` as a way of launching exploits.

Firstly, run is a simple cli that will just take the arguments and parse them to initialize the full [context](/pwninit/context), next it will check for the presence of any `exploit.py` with this structure:

```py
from pwninit import *

# We'll see later what this does.
Config(
  chall = "sh"
)

def exploit(ctx: PwnContext, ioctx: IOContext):
  # actual exploit
```

And after this full exploit loaded it will execute the `exploit` function and pass the newly initialised `ctx` and `ioctx`.

To initialise the context, `run` uses the `Config` namespace and the args provided by the user to initialise the two classes, [IOContext](/pwninit/io) and [PwnContext](/pwninit/io), this two classes are used to interact and parse the binary during runtime.

When all of this is set, you can use all the methods defined by IOContext and PwnContext directly in your exploit like this:

```py

def exploit(ctx: PwnContext, ioctx: IOContext):
  sl("test") # send b"test" followed by b"\n"
  line = rl() # receive a line sended by the challenge
  print(line)
  itrv() # get an interactive shell
```

Finally, to get a glimps of all the avaiables methods/helpers/config you can check [pwninit](/pwninit)
