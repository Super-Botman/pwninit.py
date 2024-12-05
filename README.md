# pwninit-sh
---

## Installation
```zsh
python -m build

# if you're sane 
pipx install dist/pwninit-0.0.1-py3-none-any.whl 

# or pip
pip install dist/pwninit-0.0.1-py3-none-any.whl 

```

## Usage
With pwninit.py you have two tools, run and pwninit, pwninit is used to setup the environment of the exploit and run to... run the exploit specified in exploit.py

### Utils
With pwninit you have some utils to automate some tasks like menu function creations and docker libc fetching

### pwninit 
```zsh
usage: pwninit [-h] [-p provider] [-u utils]

pwninit

options:
  -h, --help            show this help message and exit
  -p provider, --provider provider
                        fetch chall from url
  -u utils, --utils utils
                        scripts to run on the binary
```
#### utils
**menu**:
It will generate you all the code to interact with a chall menu.
usage: `-u menu`

#### providers
**docker**:
You can use docker provider when you got only a Dockerfile and yout want to extract the libc from it
usage: `-p docker`

**root-me**:
For this one you juste have to specify the url of the chall you wanna do and it will fetch you all the bins needed
usage: `-u https://root-me.org/<url>`

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
