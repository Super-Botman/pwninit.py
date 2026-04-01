import argparse
import importlib.util
import sys

from pwn import ELF, context, log

import pwninit.helpers as helpers
import pwninit.io as io
from pwninit.farm import run_farm


def addr_type(value):
    if "@" in value:
        creds, addr = value.split("@", 1)
        user, password = creds.split(":", 1) if ":" in creds else (creds, None)
        host, port = addr.split(":", 1) if ":" in addr else (addr, 22)
        return io.ssh(user, password, host, int(port))
    elif ":" in value:
        host, port = value.split(":", 1)
        return io.plain(host or "localhost", int(port))
    else:
        raise argparse.ArgumentTypeError(
            "Invalid format. Expected 'ip:port', 'user@ip', or 'user:pass@ip:port'."
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
    target.add_argument(
        "-p",
        "--path",
        action="store",
        metavar="'/challenge'",
        help="challenge path on remote ssh host",
    )

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
    if args.path and not args.remote:
        log.error("--path requires -r")

    return args


def save_flag(flag):
    try:
        with open("flag", "w") as f:
            f.write(flag)
        log.success("Flag saved to file")
    except Exception as e:
        log.warning("Could not save flag to file: %s" % str(e))


def cli():
    args = parse_args()

    spec = importlib.util.spec_from_file_location("exploit", "exploit.py")
    mod = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(mod)
        from pwninit import config
    except FileNotFoundError:
        log.warn("exploit not found")
        sys.exit(1)

    exploit = getattr(mod, "exploit", None)

    if not config:
        log.warn("config not found")
        sys.exit(1)

    if not config.chall:
        log.warn("invalide config, chall not set")

    context.log_level = "DEBUG" if args.verbose else "INFO"

    if config.binary:
        try:
            context.binary = ELF(config.binary)
        except Exception as e:
            log.warning("Could not load binary: %s" % str(e))

    if config.libc:
        try:
            libc = ELF(config.libc)
        except Exception as e:
            log.warning("Could not load libc: %s" % str(e))
    elif context.binary:
        libc = context.binary.libc

    if args.farm:
        return run_farm(args, config, exploit)

    ctx = io.IOContext(args, config)
    ctx.connect()
    io.set_ctx(ctx)

    if context.binary:
        ctx = helpers.PwnContext(io.ioctx.proc, context.binary, libc)
        helpers.set_ctx(ctx)

    try:
        flag = exploit(helpers.pwnctx, io.ioctx)
        if flag:
            log.success("flag: %s" % flag)
            save_flag(flag)
        else:
            log.warning("No flag returned from exploit")
    except Exception as e:
        log.error("Exploit failed: %s" % str(e))

    return 0
