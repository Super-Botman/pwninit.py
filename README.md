# pwninit-sh
---

## Installation
### Required
- python
- zsh
- kitty

```zsh
./install.sh
```

## Usage
With pwninit-sh you have two tools, run and pwninit, pwninit is used to setup the environment of the exploit and run... run the exploit specified in exploit.py

### Utils
With pwninit you have some utils to automate some tasks like menu function creations and docker libc fetching

### pwninit 
```zsh
pwninit <util>
```

### run
```zsh
usage: run [-h] [-r addr] [-d] [-s] [--gdb-command 'c'] [-v]

Runner for pwn exploits.

options:
  -h, --help            show this help message and exit
  -r addr, --remote addr
                        run remotely (ip:port for nc and
                        user:password@ip for ssh)
  -d, --debug           enable debug mode
  -s, --strace          run with strace and store the strace output
                        into strace.out
  --gdb-command 'c'     set a command to run at the start of gdb
                        work only if debug is set
  -v, --verbose         verbose mode
```


