# Pwninit

--- 

## Architecture

`pwninit.py` is also a python lib consisting of two main submodules, io and helpers.
`pwninit.io` defines the class [IOContext](io) that is handling all the connection/debug/io stuff for you, on the other and `pwninit.helpers` define a bunch of utils ([Utils](utils)) and [PwnContext](pwncontext), the first are simple utils that works independantly from the context and [PwnContext](pwncontext) is a class that defines a bunch of other utils more powerfull and based on the current exploit context.

---

## Context setup
**Note**:
When using [run](/cli/intro#run-exploit-execution) cli, all the context initialisation is handled by it.

### Initialisation
Initialisation of the context is pretty much the same for [IOContext](io) and [PwnContext](pwncontext), first we need to instantiate the class:
```py
from pwnint import Args, Config
import pwninit.io as io
import pwninit.helpers as helpers

args = io.Args()
config = Config(
  chall=['ls']
)

ioctx = io.IOContext(args, config)
pwnctx = helpers.PwnContext(ioctx, config)
```

at this time it's already usable but the next
