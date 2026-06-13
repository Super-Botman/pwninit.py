import argparse
import importlib.util
import sys
import re

from pwn import ELF, context, log

from pwninit import IOContext, PwnContext, set_ctx, NC, SSH, Args
from pwninit.farm import run_farm

_NC_RE = re.compile(r"^(?P<host>[^:@]*):(?P<port>\d+)$")
_SSH_RE = re.compile(
    r"^(?P<user>[^:@]+)(?::(?P<password>[^@]*))?@(?P<host>[^:]+)(?::(?P<port>[^:]+))?(?::(?P<path>.+))?$"
)


def addr_type(value: str) -> SSH | NC:
    if m := _SSH_RE.match(value):
        port = m.group("port")
        path = m.group("path") or (port if port and not port.isdigit() else None)
        port = int(port) if port and port.isdigit() else 22
        return SSH(
            m.group("user"), m.group("host"), m.group("password") or None, port, path
        )

    if m := _NC_RE.match(value):
        return NC(m.group("host") or "localhost", int(m.group("port")))

    raise argparse.ArgumentTypeError(
        "Invalid format. Expected 'ip:port', 'user@ip:port', 'user@ip:/path', or 'user:pass@ip:port:/path'."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Runner for pwn exploits.")

    # --- Target ---
    target = parser.add_argument_group("target")
    target.add_argument(
        "-r",
        "--remote",
        action="store",
        metavar="addr",
        type=addr_type,
        help="run remotely (ip:port for nc, user:password@ip for ssh)",
    )
    target.add_argument(
        "-l",
        "--local",
        action="store_true",
        help="start the chall as a server (default port 1337, override with -r :port)",
    )
    target.add_argument("-S", "--ssl", action="store_true", help="enable ssl")

    # --- Debug ---
    debug = parser.add_argument_group("debug")
    debug.add_argument("-D", "--docker", action="store_true", help="enable debug mode")
    debug.add_argument("-d", "--debug", action="store_true", help="enable debug mode")
    debug.add_argument("-a", "--attach", action="store_true", help="attach gdb")
    debug.add_argument(
        "-g",
        "--gdb-cmd",
        action="store",
        metavar="'c'",
        help="gdb command to run on startup (requires --debug or --attach)",
    )
    debug.add_argument(
        "-s",
        "--strace",
        action="store_true",
        help="run with strace, output saved to strace.out",
    )

    # --- Misc ---
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")

    # --- Farm ---
    farm = parser.add_argument_group("farm")
    farm.add_argument(
        "-f", "--farm", action="store_true", help="run as farm client (AD mode)"
    )
    farm.add_argument(
        "-u", "--url", default="http://localhost:5000", help="farm server URL"
    )
    farm.add_argument("-k", "--password", default="1234", help="farm server password")
    farm.add_argument(
        "-t",
        "--period",
        type=float,
        default=None,
        help="rerun exploit on all teams every N seconds",
    )
    farm.add_argument(
        "-j", "--jobs", type=int, default=50, help="max concurrent exploit instances"
    )

    ns = parser.parse_args()

    if ns.gdb_cmd and not ns.debug and not ns.attach:
        log.error("--gdb-cmd requires --debug or --attach")
    if ns.debug and ns.attach:
        log.error("--debug and --attach are mutually exclusive")

    return ns


def get_exploit_setup() -> tuple:
    spec = importlib.util.spec_from_file_location("exploit", "exploit.py")
    mod = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(mod)
        from pwninit import config
    except FileNotFoundError:
        return None, None, None

    exploit = getattr(mod, "exploit", None)
    setup = getattr(mod, "setup", None)
    return setup, exploit, config


def cli() -> int:
    ns = parse_args()
    setup, exploit, config = get_exploit_setup()
    context.log_level = "DEBUG" if ns.verbose else "INFO"

    if not exploit:
        log.warn("exploit not found")
        return 1

    if not config:
        log.warn("config not found")
        return 1

    if not config.chall:
        log.warn("invalid config, chall not set")
        return 1

    if config.binary:
        context.binary = ELF(config.binary) if config.binary else None

    if context.binary:
        config.libc = ELF(config.libc) if config.libc else context.binary.libc

    if config.libs:
        config.libs = [ELF(l) for l in config.libs]

    if ns.farm:
        return run_farm(ns, config, exploit)

    args = Args(
        remote=ns.remote,
        local=ns.local,
        ssl=ns.ssl,
        docker=ns.docker,
        debug=ns.debug,
        attach=ns.attach,
        gdb_cmd=ns.gdb_cmd,
        strace=ns.strace,
    )

    if (args.local or args.docker) and not args.remote:
        args.remote = NC("localhost", 5000)

    if setup:
        setup(args, config)

    ioctx = IOContext(args, config)
    set_ctx(ioctx)

    pwnctx = PwnContext(ioctx)
    set_ctx(pwnctx)

    exploit(pwnctx, ioctx)

    return 0
