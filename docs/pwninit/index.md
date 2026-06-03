# Pwninit

---

## Architecture

`pwninit.py` is also a python lib consisting of two main submodules, io and helpers:

- `pwninit.io`: defines the class [IOContext](io) that is handling all the connection/debug/io.
- `pwninit.helpers`: defines a bunch of [Utils](utils) and [PwnContext](pwncontext).

---

## Context setup

**Note**:
When using [`run`](/cli/intro#run-exploit-execution) command, all the context initialisation is handled by it. This page explains how the lib works, if you want to learn how to use `run` got to [`exploit development`](/cli/exploit-dev).

### Initialisation

Initialisation of the context is pretty much the same for [IOContext](io) and [PwnContext](pwncontext), first we need to instantiate the class:

```py
from pwninit import Args, Config
import pwninit.io as io
import pwninit.helpers as helpers

# This dataclass serv as a glue between argparse.Namespace and custom scripts (1)
args = io.Args()
config = Config(
  chall=['ls']
)

ioctx = io.IOContext(args, config)
pwnctx = helpers.PwnContext(ioctx, config)
```

1. [`io.Args`](io/#pwninit.io.Args) - argument parser context

At this time you can already access all the methods through instance.method
For example:

```py
ioctx.itrv() # get full control over IOs (1)
```

1. [`IOContext.itrv()`](io/#pwninit.io.IOContext.itrv) - alias for IOContext.interactive()

But an other way to access all of these methods directly using the library is through [`set_ctx()`](io/#pwninit.io.set_ctx).

This function will define a singleton inside the lib so that any public methodes of [`IOContext`](io) or [`PwnContext`](pwncontext) can be globally accessible.

```py
>>> from pwninit import *
>>> itrv()
Traceback (most recent call last):
  File "<python-input-1>", line 1, in <module>
    itrv()
    ~~~~^^
  File "/home/botman/Documents/projects/pwninit/dev_env/venv/lib/python3.14/site-packages/pwninit/io.py", line 413, in wrapper
    ctx = _require_ctx()
  File "/home/botman/Documents/projects/pwninit/dev_env/venv/lib/python3.14/site-packages/pwninit/io.py", line 407, in _require_ctx
    raise RuntimeError("IOContext not initialized - call set_ctx() first")
RuntimeError: IOContext not initialized - call set_ctx() first
>>> ioctx = IOContext(Args(), Config(chall=['sh']))
>>> set_ctx(ioctx)
>>> itrv()
$ whoami
user
$
```

In the specific case of [`IOContext`](io) you can also use [`connect`](io/#pwninit.io.connect) that will [`set_ctx`](io/#pwninit.io.set_ctxi) and init a new class based on the args or previous config/args.
