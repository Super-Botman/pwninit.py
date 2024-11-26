import argparse
from pathlib import Path
import re
import readelf
import shutil
import subprocess
import datetime
from pwn import *


def utils_type(value) -> list:
    return sum([value.replace(' ', '').split(',')], [])


def provider_type(value) -> list:
    url_pattern = r"(^https?:\/\/(?:www\.)?)([-a-zA-Z0-9@:%._\+~#=]{1,256})(\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$)"
    values = re.findall(url_pattern, value)[0]
    if len(values) == 3:
        return values
    else:
        raise argparse.ArgumentTypeError(
            'Invalid provider format. Expected a url.')


def find_binaries(dir) -> list:
    files = [os.path.join(dir, f) for f in os.listdir(
        dir) if os.path.isfile(os.path.join(dir, f))]

    binary_files = []
    for file in files:
        magic = read(file)[:4]
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
            elf = readelf.readelf(f)
            dynsym = elf.find_section_by_type(readelf.SHT.SHT_DYNSYM)
            dyn_section = elf.find_sections_by_type(readelf.SHT.SHT_DYNAMIC)
            if dyn_section[0].entries[1].d_tag == readelf.DT.DT_SONAME:
                soname = dyn_section[0].entries[1].value
        except:
            pass

        if "libc.so." in soname:
            binaries["libc"].append(f)
        elif dynsym and (
                dynsym.get_symbol("_dl_tls_setup") or
                dynsym.get_symbol("name_to_handle_at") or
                dynsym.get_symbol("_rtld_global")):
            binaries["ld"].append(f)
        else:
            binaries["challs"].append(f)

    return binaries


def fetch_ld(bins, path):
    for libc in bins["libc"]:
        lib_path = pwnlib.libcdb.download_libraries(libc)
        if lib_path is not None:
            ld_path = os.path.join(lib_path, 'ld-linux-x86-64.so.2')
            shutil.copy(ld_path, path)
            bins["ld"] = [str(path / 'ld-linux-x86-64.so.2')]


def open_file(path: Path):
    mode = "w"
    if path.is_file():
        mode = "w" if input(
            "Do you want to overwrite the content of %s ? [y,N]: " % os.path.basename(path)).lower() == "y" else "a"

    return open(path, mode)


def init_files(dir, bins) -> dict:
    files = {}
    files["exploit.py"] = (
        "from pwn import *\n\nCHALL=%s\n" % bins["challs"][0])

    if bins["libc"]:
        files["exploit.py"] += ("LIBC=%s\n" % bins["libc"][0])

    chall = os.path.basename(dir)
    files["notes.md"] = ("# [Pwn] %s | %s\n---\n" %
                         (chall, datetime.datetime.now().strftime("%x")))
    files["notes.md"] += "## Checksecs\n```\n"
    for b in bins.values():
        checksecs = b"".join([subprocess.check_output(
            "pwn checksec %s" % f, shell=True, stderr=subprocess.STDOUT) for f in b])

        files["notes.md"] += checksecs.decode()

    files["notes.md"] += "```\n---\n## Writeup\n\n\n**Written by *0xB0tm4n***\n"

    return files


def test():
    base = "/home/botman/Documents/projects/pwninit/test/bins/"
    pathes = [base+"challs", base+"libc", base+"ld"]

    for path in pathes:
        binaries = find_binaries(path)
        bins = sort_binaries(binaries)
        stats = []

        for b in bins:
            stats.append(len(bins[b]))

        print(path)
        print("libc, ld, challs", stats)
        print("")


def main() -> int:
    parser = argparse.ArgumentParser(description='pwninit')
    parser.add_argument('-p', '--provider', action='store',
                        metavar='provider', type=provider_type, help='fetch')
    parser.add_argument('-u', '--utils', action='store',
                        metavar='utils', type=utils_type, help='set utils')
    args = parser.parse_args()

    if args.provider:
        provider_name = args.provider[1].split('.')[-1]
        try:
            __import__(provider_name).main(args.provider)
        except:
            print("No providers named %s" % provider_name)

    # path = Path().resolve()
    path = Path("/home/botman/Documents/projects/pwninit/test/bof")
    binaries = find_binaries(path)
    bins = sort_binaries(binaries)
    if len(bins["libc"]) > 0 and len(bins["ld"]) == 0:
        fetch_ld(bins, path)

    files = init_files(path, bins)
    if args.utils:
        for util_name in args.utils:
            try:
                __import__(util_name).run(files, bins, dir)
            except:
                print("no utils named %s" % util_name)

    return 0


if __name__ == "__main__":
    exit(main())
