import argparse
import datetime
import os
import re
import shutil
import sys
from pathlib import Path

from mako.template import Template
from pwn import ELF, context, libcdb, log

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))
from .config import config
from .plugins import run_plugins, print_plugin_list

TOP_FLAGS = {"-p", "--provider", "-s", "--setup", "--list-plugins", '-l'}

def find_bins(dir: Path) -> list:
    files = [
        os.path.join(dir, f)
        for f in os.listdir(dir)
        if os.path.isfile(os.path.join(dir, f))
    ]

    binary_files = []
    for file in files:
        magic = open(file, "rb").read(4)
        if magic == b"\x7fELF":
            binary_files.append(file)

    return binary_files


def sort_bins(files: list) -> dict:
    bins = {}
    bins["libc"] = []
    bins["ld"] = []
    bins["challs"] = []

    elf = None

    for f in files:
        context.log_level = "error"
        elf = ELF(f, checksec=False)
        context.log_level = "info"

        soname_tag = elf.dynamic_by_tag("DT_SONAME")

        if soname_tag and (
            "libc.so.0" in soname_tag.soname or "libc.so.6" in soname_tag.soname
        ):
            bins["libc"].append(f)

        elif not elf.statically_linked and (
            "_dl_tls_setup" in elf.sym
            or "name_to_handle_at" in elf.sym
            or "_rtld_global" in elf.sym
        ):
            bins["ld"].append(f)

        else:
            bins["challs"].append(f)

        os.system("chmod +x %s" % f)

    return bins


def fetch_ld(bins: dict[str, list], path: Path):
    for libc in bins["libc"]:
        lib_path = libcdb.download_libraries(libc)
        if lib_path is not None:
            lib_path = Path(lib_path)
            ld_path = lib_path / "ld-linux-x86-64.so.2"
            shutil.copy(ld_path, path)
            bins["ld"] = [str(path / "ld-linux-x86-64.so.2")]
            return True
        else:
            return False


def patchelf(bins: dict, path: Path):
    os.system("patchelf --set-rpath %s %s" % (path, bins["challs"][0]))
    os.system(
        "patchelf --set-interpreter  %s %s"
        % (os.path.basename(bins["ld"][0]), bins["challs"][0])
    )


def open_file(path: Path):
    if path.is_file():
        filename = os.path.basename(path)
        overwrite = input(
            f"Do you want to overwrite the content of {filename} ? [Y,n]: "
        )
        if overwrite.lower() == "n":
            return False

    return open(path, "w")

def gen_files(path, bins) -> dict:
    pwninit_path = Path(os.path.dirname(os.path.realpath(__file__)))
    templates = pwninit_path / "templates"
    chall = os.path.basename(path)
    checksecs = []
    for b in bins.values():
        checksecs.append(
            [f"[*] {f}\n" + ELF(f, checksec=False).checksec(color=False) for f in b]
        )

    checksecs = "\n\n".join(sum(checksecs, []))

    files = {}

    # Render exploit.py using Mako
    exploit_template = Template(filename=str(templates / "exploit.py"))
    files["exploit.py"] = exploit_template.render(
        chall="./" + os.path.basename(bins["challs"][0]),
        libc="./" + os.path.basename(bins["libc"][0]) if bins["libc"] else None,
    )

    # Render notes.md using Mako
    notes_template = Template(filename=str(templates / "notes.md"))
    files["notes.md"] = notes_template.render(
        chall=chall,
        date=datetime.datetime.now().strftime("%d/%m/%Y"),
        checksecs=checksecs,
        author=config.get('author', 'pwner', 'PWNINIT_AUTHOR'),
    )

    return files


def process_binaries(path: Path) -> dict | None:
    bins = find_bins(path)
    if len(bins) == 0:
        return None

    sorted_bins = sort_bins(bins)
    for filename in sorted_bins:
        if sorted_bins[filename]:
            log.success("%s found: %s" % (filename, ", ".join(sorted_bins[filename])))
    return sorted_bins


def setup_libc_ld(sorted_bins: dict, path: Path) -> bool:
    if sorted_bins["libc"] and not sorted_bins["ld"]:
        log.info("Attempting to fetch ld for libc...")
        if not fetch_ld(sorted_bins, path):
            log.error("Cannot fetch the ld corresponding to libc")

    if sorted_bins["libc"] and sorted_bins["ld"]:
        try:
            patchelf(sorted_bins, Path(os.path.abspath(path)))
            log.success("Patched binary with libc and ld")
        except Exception as e:
            log.error("Error patching binary: %s" % str(e))
    return True


def write_output_files(files: dict, path: Path) -> bool:
    for file in files:
        try:
            f = open_file(path / file)
            if f:
                f.write(files[file])
                f.close()
                log.success("Created %s" % file)
        except Exception as e:
            log.error("Error creating %s: %s" % (file, str(e)))
    return True


def split_argv(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    provider = []
    setup = []
    top_args = []

    i = 0
    while i < len(argv):
        if argv[i] in ("-p", "--provider"):
            i += 1
            if i >= len(argv):
                log.error("-p requires a plugin name")
                break
            name = argv[i]
            i += 1
            plugin_args = []
            while i < len(argv) and argv[i] not in TOP_FLAGS:
                plugin_args.append(argv[i])
                i += 1
            provider.append((name, plugin_args))

        elif argv[i] in ("-s", "--setup"):
            i += 1
            if i >= len(argv):
                log.error("-u requires a plugin name")
                break
            name = argv[i]
            i += 1
            plugin_args = []
            while i < len(argv) and argv[i] not in TOP_FLAGS:
                plugin_args.append(argv[i])
                i += 1
            setup.append((name, plugin_args))

        else:
            top_args.append(argv[i])
            i += 1

    return top_args, provider, setup


def parse_top_args(top_args):
    parser = argparse.ArgumentParser(
        description="pwninit - CTF binary exploitation setup tool",
    )
    parser.add_argument("--list-plugins", '-l', help='list all available provider and setup functions', action="store_true")
    parser.add_argument("--provider", '-p')
    parser.add_argument("--setup", '-s')
    return parser.parse_args(top_args)


def parse_plugin_args(plugin, raw_args):
    parser = argparse.ArgumentParser(
        prog=plugin.name,
        description=plugin.description,
    )
    for a in plugin.args:
        a = dict(a)
        name = a.pop("name")
        short = a.pop("short", None)
        names = [short, name] if short else [name]
        parser.add_argument(*names, **a)

    return parser.parse_args(raw_args)

def parse_args():
    top_args, provider, setup = split_argv()
    args = parse_top_args(top_args)
    args.provider = provider
    args.setup = setup
    return args

def cli() -> int:
    args = parse_args()
    path = Path(".")

    if args.list_plugins:
        print_plugin_list()
        return 0

    if args.provider:
        for p in args.provider:
            ret = run_plugins(p, 'provide', path)
            if ret:
                path = ret

    sorted_bins = process_binaries(path)
    if sorted_bins:
        if not setup_libc_ld(sorted_bins, path):
            return 1
        files = gen_files(path, sorted_bins)

        if args.setup:
            for s in args.setup:
                ret = run_plugins(s, 'setup', sorted_bins)
                if ret:
                    files.update(ret)

        if not write_output_files(files, path):
            return 1

    else:
        log.info("No binaries found")
        files = gen_files(path, sorted_bins)
        if not write_output_files(files, path):
            return 1

    log.success("pwninit completed successfully")
    return 0
