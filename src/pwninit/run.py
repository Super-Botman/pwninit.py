from pwn import log, context, ELF
import argparse
import sys
from pathlib import Path
import pwninit.helpers as helpers
import pwninit.io as io

sys.path.insert(0, "./")
import exploit

NC = 1
SSH = 2

def addr_type(value):
    if "@" in value:
        creds, addr = value.split("@", 1)
        if ":" in creds:
            user, password = creds.split(":", 1)
        else:
            user, password = creds, None
        if ":" in addr:
            ip, port = addr.split(":", 1)
            return SSH, user, password, ip, int(port)
        else:
            ip = addr
            return SSH, user, password, ip, 22
    elif ":" in value:
        ip, port = value.split(":", 1)
        if ip == '':
            return NC, 'localhost', int(port)
        return NC, ip, int(port)
    else:
        raise argparse.ArgumentTypeError(
            "Invalid remote format. Expected 'ip:port', 'user@ip', or 'user:pass@ip:port'."
        )


def parse_args():
    parser = argparse.ArgumentParser(description="Runner for pwn exploits.")
    parser.add_argument(
        "-r", "--remote",
        action="store",
        metavar="addr",
        type=addr_type,
        help="run remotely (ip:port for nc and user:password@ip for ssh)",
    )
    parser.add_argument(
        "-l", "--local-bin",
        action="store_true",
        help="start the chall as a server, by default remote port is 1337 and can be changed using -r :port"
    )
    parser.add_argument("--ssl", action="store_true", help="enable ssl")
    parser.add_argument(
        '--path',
        action="store",
        metavar="'/challenge'",
        help="set a path where challenge is located when using remote ssh"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug mode")
    parser.add_argument("-a", "--attach", action="store_true", help="enable debug mode (gdb attach)")
    parser.add_argument(
        "--gdb-command",
        action="store",
        metavar="'c'",
        help="set a command to run at the start of gdb work only if debug is set",
    )
    parser.add_argument(
        "-s",
        "--strace",
        action="store_true",
        help="run with strace and store the strace output into strace.out",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    args = parser.parse_args()

    if args.gdb_command and not args.debug and not args.attach:
        log.error("--gdb-command can only be used with --debug")

    if args.debug and args.attach:
        log.error("--debug and --attach are incompatible")
        
    if args.path and not args.remote:
        log.error("--path can only be used with -r")

    return args


def setup_context(args):
    context.log_level = "DEBUG" if args.verbose else "INFO"

    libc = exploit.LIBC if hasattr(exploit, "LIBC") else None

    try:
        context.binary = ELF(exploit.CHALL)
    except Exception as e:
        log.warning("Could not load ELF: %s" % str(e))

    if libc is None:
        libc = context.binary.libc
    else:
        try:
            libc = ELF(libc)
        except Exception as e:
            log.warning("Could not load LIBC: %s" % str(e))

    return context.binary, libc

def save_flag(flag):
    try:
        with open("flag", "w") as f:
            f.write(flag)
        log.success("Flag saved to file")
    except Exception as e:
        log.warning("Could not save flag to file: %s" % str(e))

    # Rename the folder containing the exploit by appending a checkmark
    try:
        cwd = Path.cwd()
        if not cwd.name.endswith("✅"):
            new_path = cwd.parent / (cwd.name + "✅")
            if new_path.exists():
                log.warning("Cannot rename folder: target exists")
            else:
                cwd.rename(new_path)
    except Exception as e:
        log.warning("Could not rename folder: %s" % str(e))

def cli():
    args = parse_args()
    elf, libc = setup_context(args)

    elf = elf if isinstance(elf, ELF) else None
    libc = libc if isinstance(libc, ELF) else None
    binary = elf if isinstance(elf, str) else exploit.CHALL
    prefix = exploit.PREFIX if hasattr(exploit, "PREFIX") else "> "

    io.set_ctx(io.IOContext(args, exploit.CHALL, prefix))

    helpers.set_ctx(helpers.PwnContext(io.ioctx.proc, elf, libc, binary, prefix))

    try:
        flag = exploit.exploit(io.ioctx.conn, elf, libc)
        if flag:
            log.success("flag: %s" % flag)
            save_flag(flag)
        else:
            log.warning("No flag returned from exploit")
    except Exception as e:
        log.error("Exploit failed: %s" % str(e))

    return 0
