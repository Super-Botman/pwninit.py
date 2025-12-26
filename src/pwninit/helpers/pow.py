from . import helpers as hlp
from .. import io
from .. import config
from pwn import flat, log, tube
from subprocess import run, DEVNULL, PIPE
import re

def get_binary(name):
    b = config.config.get(name, default=None)
    if b is None:
        log.warn(f"Proof of work binary for {name} not found in config")
    return b

def _solve_sossette(data):
    binary = get_binary("sossette")
    if binary is None:
        return None

    prefix = re.findall(rb"SHA256\(([0-9A-Za-z]+) ", data)
    difficulty = re.findall(rb"starts with (\d+) bits", data)
    if len(prefix) == 0 or len(difficulty) == 0:
        log.error(f"Proof of work failed (sossette): {data}")
    
    prefix = prefix[0]
    difficulty = difficulty[0]
    p = run([binary, prefix, difficulty], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (sossette): {data}")
    
    return p.stdout

def _solve_hxp(data):
    binary = get_binary("hxp")
    if binary is None:
        return None

    prefix = re.findall(rb"sha256(unhex(\"[0-9A-fa-f]+\"", data)
    difficulty = re.findall(rb"starts with (\d+) bits", data)
    if len(prefix) == 0 or len(difficulty) == 0:
        log.error(f"Proof of work failed (hxp): {data}")
    
    prefix = prefix[0]
    difficulty = difficulty[0]
    p = run([binary, prefix, difficulty], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (hxp): {data}")
    
    return p.stdout

def _solve_redpwn(data):
    binary = get_binary("redpwn")
    if binary is None:
        return None

    arg = re.findall(rb"\| sh -s (.+)\n", data)
    if len(arg) == 0:
        log.error(f"Proof of work failed (redpwn): {data}")
    
    arg = arg[0]
    p = run([binary, arg], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (redpwn): {data}")
    
    return p.stdout

def _solve_kctf(data):
    binary = get_binary("kctf") # kctf & redpwn are actually the same
    if binary is None:
        return None

    arg = re.findall(rb"\) solve (.+)\n", data)
    if len(arg) == 0:
        log.error(f"Proof of work failed (kctf): {data}")
    
    arg = arg[0]
    p = run([binary, arg], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (kctf): {data}")
    
    return p.stdout

def _solve_hashcash(data):
    binary = get_binary("hashcash")
    if binary is None:
        return None

    cmd = re.findall(rb"hashcash (-m.*?b\d+) ([0-9A-Za-z+/]+)", data)
    if len(cmd) == 0:
        log.error(f"Proof of work failed (hashcash): {data}")
    
    cmd = cmd[0]
    p = run([binary, cmd[0], cmd[1]], stdout=PIPE, stderr=DEVNULL)
    if p.returncode != 0:
        log.error(f"Proof of work failed (hashcash): {data}")
    
    return p.stdout

_functions = {
    b"Please provide an ASCII printable": _solve_sossette,
    b"give S such that sha256": _solve_hxp,
    b"https://pwn.red/pow": _solve_redpwn,
    b"please solve a pow first": _solve_kctf,
    b"hashcash": _solve_hashcash,
}
def _solve_pow(data):
    for s, f in _functions.items():
        if s in data:
            return f(data).strip()
    log.warn(f"Unknown proof of work: {data}")
    return None
    
def solve_pow(io_=None):
    if isinstance(io_, tube) or isinstance(io_, io.IOContext):
        pow = _solve_pow(io_.clean())
        if pow is not None:
            io_.sendline(pow)
    elif io_ is None:
        io._require_ctx()
        pow = _solve_pow(io.ioctx.conn.clean())
        if pow is not None:
            io.ioctx.sl(pow)
    else:
        raise ValueError()
    
