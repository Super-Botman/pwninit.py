# `pwninit.py`

A tool to setup a full exploit template and fetch libs in a second

## Features:
- Finds all bins in dir and sort them by type (chall or libs)
- Fetch libc if ld detected automatically and patch the chall 
- Provide utils to fetch chall's bins directly from a url or to add content to you're exploit like menu interaction scripts
- Provide a easy to use runner to dev your exploit without even needing to think about how to interact with target.
- Create notes.md and exploit.py

## Installation
```zsh
git clone https://github.com/Super-Botman/pwninit.py.git
python -m build

# if you're sane 
pipx install dist/pwninit-0.0.1-py3-none-any.whl 

# or pip
pip install dist/pwninit-0.0.1-py3-none-any.whl 

```

## Usage
### Short 
Run `pwninit` to init notes.md and template and then `run` to run your exploit

### Longer
`pwninit` is the init tool, it will fill an exploit template and a writeup template but it can do more than that ! If you want to fetch some bins from a platform you can use `providers` with `-p` and it will fetch all is needed to pwn ! But maybe, you also want to generate some other things like menu interaction scripts, this is the job of the `utils` option (`-u`) wich allow you to specify some utils to run.

**Utils**

`menu`:
It will generate you all the code to interact with a chall menu.

usage: `-u menu`

**Providers**

`docker`:
You can use docker provider when you got only a Dockerfile and yout want to extract the libc from it

usage: `-p docker`

`root-me`:
For this one you juste have to specify the url of the chall you wanna do and it will fetch you all the bins needed

usage: `-u https://root-me.org/<url>`

---

`run` is the runner of you're template, without it the exploit template would be a little empty but when you use run it become a completely another script very configurable and easy to use.
To use it you just have to run `run`
```
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
