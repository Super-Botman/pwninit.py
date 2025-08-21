from pwn import process, log, gdb, ssh, remote, context, ELF
import argparse
import sys

sys.path.insert(0, './')

try:
    from exploit import exploit, CHALL
except Exception:
    log.failure("Cannot found exploit.py file")
    exit(1)

NC = 1
SSH = 2


def addr_type(value):
    if value.split(':')[0] != value and value.split('@')[0] != value:
        creds, addr = value.split('@')
        user, password = creds.split(':')
        ip, port = addr.split(':')
        return SSH, user, password, ip, int(port)
    elif value.split(':')[0] != value:
        ip, port = value.split(':')
        return NC, ip, int(port)
    else:
        raise argparse.ArgumentTypeError(
            "Invalid remote arg format. Expected 'ip:port' or 'user@ip'.")


def parse_args():
    parser = argparse.ArgumentParser(description='Runner for pwn exploits.')
    parser.add_argument('-r', '--remote', action='store', metavar='addr', type=addr_type,
                        help='run remotely (ip:port for nc and user:password@ip for ssh)')
    parser.add_argument('--ssl', action='store_true',
                        help='enable ssl')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='enable debug mode')
    parser.add_argument('-s', '--strace', action='store_true',
                        help='run with strace and store the strace output into strace.out')
    parser.add_argument('--gdb-command', action='store', metavar='\'c\'',
                        help='set a command to run at the start of gdb work only if debug is set')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='verbose mode')
    args = parser.parse_args()

    if args.gdb_command and not args.debug:
        log.error("--gdb-command can only be used with --debug")

    return args


def setup_context(args):
    context.log_level = "DEBUG" if args.verbose else "INFO"
    context.terminal = ['kitten', '@launch', '--copy-env', '--cwd', 'current']

    try:
        context.binary = ELF(CHALL)
        return context.binary
    except Exception as e:
        log.warning("Could not load ELF: %s" % str(e))
        return CHALL


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
            return gdb.debug(CHALL, ssh=ssh_conn)
        else:
            return ssh_conn.system(" ".join(CHALL) if isinstance(CHALL, list) else CHALL)
    except Exception as e:
        log.error("Failed to create SSH process: %s" % str(e))


def create_local_process(args):
    try:
        if args.debug:
            gdb_script = args.gdb_command if args.gdb_command else ""
            return gdb.debug([CHALL], gdbscript=gdb_script)
        elif args.strace:
            return process(["strace", "-o", "strace.out", CHALL])
        else:
            return process(CHALL)
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
    elf = setup_context(args)

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

    try:
        flag = exploit(p, elf)
        if flag:
            log.success("flag: %s" % flag)
            save_flag(flag)
        else:
            log.warning("No flag returned from exploit")
    except Exception as e:
        log.error("Exploit failed: %s" % str(e))

    return 0
