import argparse
import importlib.util
import sys
import re

from pwn import ELF, context, log

import pwninit.helpers.pwncontext as helpers
import pwninit.io as io
from pwninit.farm import run_farm

_NC_RE  = re.compile(r'^(?P<host>[^:@]*):(?P<port>\d+)$')
_SSH_RE = re.compile(r'^(?P<user>[^:@]+)(?::(?P<password>[^@]*))?@(?P<host>[^:]+)(?::(?P<port>[^:]+))?(?::(?P<path>.+))?$')

def addr_type(value: str) -> io.SSH | io.NC:
    if m := _SSH_RE.match(value):
        port = m.group("port")
        path = m.group("path") or (port if port and not port.isdigit() else None)
        port = int(port) if port and port.isdigit() else 22
        return io.SSH(m.group("user"), m.group("host"), m.group("password") or None, port, path)

    if m := _NC_RE.match(value):
        return io.NC(m.group("host") or "localhost", int(m.group("port")))

    raise argparse.ArgumentTypeError(
        "Invalid format. Expected 'ip:port', 'user@ip:port', 'user@ip:/path', or 'user:pass@ip:port:/path'."
    )

def parse_args():
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

    args = parser.parse_args()

    if args.gdb_cmd and not args.debug and not args.attach:
        log.error("--gdb-cmd requires --debug or --attach")
    if args.debug and args.attach:
        log.error("--debug and --attach are mutually exclusive")

    return args


def save_flag(flag):
    try:
        with open("flag", "w") as f:
            f.write(flag)
        log.success("Flag saved to file")
    except Exception as e:
        log.warning("Could not save flag to file: %s" % str(e))


def get_exploit() -> tuple:
    spec = importlib.util.spec_from_file_location("exploit", "exploit.py")
    mod = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(mod)
        from pwninit import config
    except FileNotFoundError:
        return None, None

    return getattr(mod, "exploit", None), config
    
def cli() -> int:
    args = parse_args()
    exploit, config = get_exploit()
    context.log_level = "DEBUG" if args.verbose else "INFO"

    if not exploit:
        log.warn("exploit not found")
        return 1

    if not config:
        log.warn("config not found")
        return 1

    if not config.chall:
        log.warn("invalid config, chall not set")
        return 1

    context.binary = ELF(config.binary) if config.binary else None
    if context.binary:
        libc = ELF(config.libc) if config.libc else context.binary.libc

    if args.farm:
        return run_farm(args, config, exploit)

    if (args.local or args.docker) and not args.remote:
        args.remote = io.NC("localhost", 5000)

    ctx = io.IOContext(args, config)
    if not ctx.connect():
        return 1
    io.set_ctx(ctx)

    ctx = helpers.PwnContext(io.ioctx, context.binary, libc, config.libs, config.prefix)
    helpers.set_ctx(ctx)

    exploit(helpers.pwnctx, io.ioctx)

    return 0
