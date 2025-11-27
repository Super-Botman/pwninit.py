from pwn import process, log, gdb, ssh, remote, context, ELF
import argparse
import sys
from pathlib import Path

sys.path.insert(0, "./")
sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

import pwninit.utils as pwn_utils
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
        return NC, ip, int(port)
    else:
        raise argparse.ArgumentTypeError(
            "Invalid remote format. Expected 'ip:port', 'user@ip', or 'user:pass@ip:port'."
        )


def parse_args():
    parser = argparse.ArgumentParser(description="Runner for pwn exploits.")
    parser.add_argument(
        "-r",
        "--remote",
        action="store",
        metavar="addr",
        type=addr_type,
        help="run remotely (ip:port for nc and user:password@ip for ssh)",
    )
    parser.add_argument("--ssl", action="store_true", help="enable ssl")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug mode")
    parser.add_argument(
        "-s",
        "--strace",
        action="store_true",
        help="run with strace and store the strace output into strace.out",
    )
    parser.add_argument(
        "--gdb-command",
        action="store",
        metavar="'c'",
        help="set a command to run at the start of gdb work only if debug is set",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    args = parser.parse_args()

    if args.gdb_command and not args.debug:
        log.error("--gdb-command can only be used with --debug")

    return args


def setup_context(args):
    context.log_level = "DEBUG" if args.verbose else "INFO"
    context.terminal = ["kitten", "@launch", "--copy-env", "--cwd", "current"]

    libc = exploit.LIBC if hasattr(exploit, "LIBC") else None
    ret = [
        exploit.CHALL,
        libc
    ]

    try:
        context.binary = ELF(exploit.CHALL)
        ret[0] = context.binary
    except Exception as e:
        log.warning("Could not load ELF: %s" % str(e))

    if libc != None:
        try:
            ret[1] = ELF(libc)
        except Exception as e:
            log.warning("Could not load LIBC: %s" % str(e))

    return ret


def create_remote_connection(remote_info, ssl_enabled):
    conn_type = remote_info[0]

    if conn_type == NC:
        ip, port = remote_info[1], remote_info[2]
        try:
            return remote(ip, port, ssl=ssl_enabled)
        except Exception as e:
            log.error("Failed to connect to %s:%d - %s" % (ip, port, str(e)))

    elif conn_type == SSH:
        user, password, ip, port = remote_info[1:5]
        try:
            return ssh(user=user, password=password, host=ip, port=port)
        except Exception as e:
            log.error("SSH connection failed: %s" % str(e))


def create_ssh_process(ssh_conn, args):
    try:
        if args.debug:
            return gdb.debug(exploit.CHALL, ssh=ssh_conn)
        else:
            return ssh_conn.process(CHALL)
    except Exception as e:
        log.error("Failed to create SSH process: %s" % str(e))


def create_local_process(args):
    try:
        if args.debug:
            gdb_script = args.gdb_command if args.gdb_command else ""
            return gdb.debug([exploit.CHALL], gdbscript=gdb_script)
        elif args.strace:
            return process(["strace", "-o", "strace.out", exploit.CHALL])
        else:
            return process(exploit.CHALL)
    except Exception as e:
        log.error("Failed to create local process: %s" % str(e))


def save_flag(flag):
    try:
        with open("flag", "w") as f:
            f.write(flag)
        log.success("Flag saved to file")
    except Exception as e:
        log.warning("Could not save flag to file: %s" % str(e))


def cli():
    args = parse_args()
    elf, libc = setup_context(args)


    # Create connection/process
    if args.remote:
        if args.remote[0] == SSH:
            ssh_conn = create_remote_connection(args.remote, args.ssl)
            if not ssh_conn:
                return 1
            p = create_ssh_process(ssh_conn, args)
        else:
            p = create_remote_connection(args.remote, args.ssl)
    else:
        p = create_local_process(args)

    if not p:
        log.error("Failed to create process")

    if pwn_utils:
        pwn_utils.conn = p
        pwn_utils.elf = elf if isinstance(elf, ELF) else None
        pwn_utils.libc = libc if isinstance(libc, ELF) else None
        pwn_utils.binary = elf if isinstance(elf, str) else exploit.CHALL
        pwn_utils.prefix = exploit.PREFIX if hasattr(exploit, "PREFIX") else "> "
       

    try:
        flag = exploit.exploit(io=p, elf=elf, libc=libc)
        if flag:
            log.success("flag: %s" % flag)
            save_flag(flag)
        else:
            log.warning("No flag returned from exploit")
    except Exception as e:
        log.error("Exploit failed: %s" % str(e))

    return 0
