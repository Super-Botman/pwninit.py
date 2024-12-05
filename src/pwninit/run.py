from pwn import *
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


def cli():
    addr = ""
    parser = argparse.ArgumentParser(description='Runner for pwn exploits.')
    parser.add_argument('-r', '--remote', action='store', metavar='addr', type=addr_type,
                        help='run remotely (ip:port for nc and user:password@ip for ssh)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='enable debug mode')
    parser.add_argument('-s', '--strace', action='store_true',
                        help='run with strace and store the strace output into strace.out')
    parser.add_argument('--gdb-command', action='store', metavar='\'c\'',
                        help='set a command to run at the start of gdb work only if debug is set')
    parser.add_argument('-v', '--verbose',
                        action='store_true', help='verbose mode')
    args = parser.parse_args()

    if args.gdb_command and args.debug == False:
        print('''usage: run.py [-h] [-r ip] [-d] [--gdb-command 'c'] [-v] binary
run: error: Invalid argument, --gdb-command can be used only with --debug''')
        exit(0)

    context.log_level = "DEBUG" if args.verbose else "INFO"
    context.terminal = ['kitten', '@launch', '--copy-env', '--cwd', 'current']

    try:
        context.binary = elf = ELF(CHALL)
    except:
        elf = CHALL

    if args.remote:
        if args.remote[0] == NC:
            try:
                p = remote(args.remote[1], args.remote[2])
            except:
                exit(1)
        else:
            try:
                s = ssh(user=args.remote[1], password=args.remote[2],
                        host=args.remote[3], port=args.remote[4])
                p = s.run(CHALL)
            except RuntimeError as e:
                exit(1)
    else:
        if args.debug:
            p = gdb.debug(CHALL)
        else:
            if args.strace:
                p = process(["strace", "-o", "strace.out", CHALL])
            else:
                p = process(CHALL)

    exploit(p, elf)
