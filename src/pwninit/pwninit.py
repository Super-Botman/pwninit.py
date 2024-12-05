import argparse
import re
import shutil
import subprocess
import datetime
import importlib
import os
from pathlib import Path
from pwn import libcdb, ELF, context, log


def utils_type(value) -> list:
    return sum([value.replace(' ', '').split(',')], [])


def provider_type(value) -> list:
    url_pattern = r"(^https?:\/\/(?:www\.)?)([-a-zA-Z0-9@:%._\+~#=]{1,256})(\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$)"
    values = re.findall(url_pattern, value)

    if len(values) != 0 and len(values[0]) == 3:
        values[0][2] = values[0][2].split('.')[-1]
        return values[0]
    else:
        return ["", value, ""]


def find_binaries(dir) -> list:
    files = [os.path.join(dir, f) for f in os.listdir(
        dir) if os.path.isfile(os.path.join(dir, f))]

    binary_files = []
    for file in files:
        magic = open(file, "rb").read(4)
        if magic == b'\x7fELF':
            binary_files.append(file)

    return binary_files


def sort_binaries(files) -> dict:
    binaries = {}
    binaries["libc"] = []
    binaries["ld"] = []
    binaries["challs"] = []

    for f in files:
        soname = ""
        dynsym = ""

        try:
            elf = ELF(f, checksec=False)
            soname = elf.dynamic_by_tag("DT_SONAME").soname
        except Exception as e:
            pass

        if soname and ("libc.so.6" in soname or "libc.so.0" in soname):
            binaries["libc"].append(f)
        elif elf and (
                "_dl_tls_setup" in elf.sym or
                "name_to_handle_at" in elf.sym or
                "_rtld_global" in elf.sym):
            binaries["ld"].append(f)
        else:
            binaries["challs"].append(f)

    return binaries


def fetch_ld(bins: dict, path: Path):
    context.log_level = "error"
    for libc in bins["libc"]:
        lib_path = libcdb.download_libraries(libc)
        if lib_path is not None:
            ld_path = os.path.join(lib_path, 'ld-linux-x86-64.so.2')
            shutil.copy(ld_path, path)
            bins["ld"] = [str(path / 'ld-linux-x86-64.so.2')]
            return True
        else:
            return False


def patchelf(bins: dict, path: Path):
    os.system("patchelf --set-rpath %s %s" % (path, bins["challs"][0]))
    os.system("patchelf --set-interpreter  %s %s" %
              (bins["ld"][0], bins["challs"][0]))


def open_file(path: Path):
    mode = "w"
    if path.is_file():
        mode = "a" if input(
            "Do you want to overwrite the content of %s ? [Y,n]: " % os.path.basename(path)).lower() == "n" else "w"

    return open(path, mode)


def init_files(path, bins) -> dict:
    files = {}
    files["exploit.py"] = (
        "from pwn import *\n\nCHALL=\"%s\"\n" % bins["challs"][0])

    if bins["libc"]:
        files["exploit.py"] += ("LIBC=\"%s\"\n" % bins["libc"][0])

    chall = os.path.basename(path)
    files["notes.md"] = ("# [Pwn] %s | %s\n---\n" %
                         (chall, datetime.datetime.now().strftime("%x")))
    files["notes.md"] += "## Checksecs\n```\n"
    for b in bins.values():
        checksecs = b"".join([subprocess.check_output(
            "pwn checksec %s" % f, shell=True, stderr=subprocess.STDOUT) for f in b])

        files["notes.md"] += checksecs.decode()

    files["notes.md"] += "```\n---\n## Writeup\n\n\n**Written by *0xB0tm4n***\n"

    return files


def cli() -> int:
    parser = argparse.ArgumentParser(description='pwninit')
    parser.add_argument('-p', '--provider', action='store',
                        metavar='provider', type=provider_type, help='fetch chall from url')
    parser.add_argument('-u', '--utils', action='store',
                        metavar='utils', type=utils_type, help='scripts to run on the binary')
    args = parser.parse_args()

    path = Path().resolve()

    if args.provider:
        provider_name = args.provider[1]
        try:
            path = importlib.import_module(
                "pwninit.providers."+provider_name).run("".join(args.provider), path)
        except ModuleNotFoundError:
            log.warning("No providers named %s" % provider_name)

    if not path:
        return 1

    binaries = find_binaries(path)
    if len(binaries) == 0:
        log.warning("No binaries founded in %s " % path)
        return 1

    bins = sort_binaries(binaries)
    for bin in bins:
        if bins[bin]:
            log.success("%s founded: %s" % (bin, ", ".join(bins[bin])))

    if len(bins["libc"]) > 0 and len(bins["ld"]) == 0:
        if not fetch_ld(bins, path):
            log.warning("cannot fetch the ld corresponding to libc")

    if len(bins["libc"]) > 0 and len(bins["ld"]) > 0:
        patchelf(bins, path)

    files = init_files(path, bins)
    if args.utils:
        for util_name in args.utils:
            try:
                files = importlib.import_module(
                    "pwninit.utils."+util_name).run(files, bins, path)
            except ModuleNotFoundError:
                log.warning("No utils named %s" % util_name)

    files["exploit.py"] += "\n\ndef exploit(io, elf):\n    io.success('all good')"
    for file in files:
        open_file(path / file).write(files[file])

    return 0
