import argparse
import datetime
import os
import shutil
import sys
import subprocess
from pathlib import Path

import magic as magic_lib
from mako.template import Template
from pwn import ELF, context, libcdb, log

from pwninit.config import config
from pwninit.kernel import decompress
from pwninit.plugins import print_plugin_list, run_plugins

TOP_FLAGS = {"-p", "--provider", "-s", "--setup", "--list-plugins", "-l"}

ARCHIVE_MIMES = {
    "application/x-cpio",
    "application/gzip",
    "application/x-gzip",
    "application/x-xz",
    "application/x-bzip2",
    "application/zstd",
    "application/x-lz4",
    "application/x-ext2",
    "application/x-ext4",
    "application/x-qemu-disk",
    "application/x-squashfs",
}

ARCHIVE_STRINGS = ["cpio", "squashfs", "filesystem", "disk image"]


def is_archive(path: str) -> bool:
    mime = magic_lib.from_file(path, mime=True)
    desc = magic_lib.from_file(path).lower()

    if mime in ARCHIVE_MIMES:
        return True

    if any(s in desc for s in ARCHIVE_STRINGS):
        return True

    try:
        data = open(path, "rb").read()
        decompressed = decompress(data, mime)
        if decompressed != data:
            inner_mime = magic_lib.from_buffer(decompressed, mime=True)
            inner_desc = magic_lib.from_buffer(decompressed).lower()
            return inner_mime in ARCHIVE_MIMES or any(s in inner_desc for s in ARCHIVE_STRINGS)
    except Exception:
        pass

    return False


def find_bins(dir: Path) -> dict:
    files = [
        Path(dir) / f
        for f in os.listdir(dir)
        if os.path.isfile(os.path.join(dir, f))
    ]

    result = {"elf": [], "vmlinuz": None, "archive": None}

    for file in files:
        data = open(file, "rb").read()

        if data[:4] == b"\x7fELF":
            result["elf"].append(str(file))

        if data[0x202:0x206] == b"HdrS":
            result["vmlinuz"] = str(file)
            status = log.progress(f"converting {file} to elf")
            subprocess.run(
                ["vmlinux-to-elf", file, f'{file}.elf'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            status.success('done')

        if is_archive(str(file)):
            result["archive"] = str(file)

    return result


def sort_bins(files: dict) -> dict:
    bins = {"libc": [], "ld": [], "challs": []}
    is_kernel = bool(files["vmlinuz"])

    for f in files["elf"]:
        context.log_level = "error"
        elf = ELF(f, checksec=False)
        context.log_level = "info"

        soname = (elf.dynamic_by_tag("DT_SONAME") or {}).get("soname", "")

        if soname and ("libc.so.0" in soname or "libc.so.6" in soname):
            bins["libc"].append(f)

        elif not elf.statically_linked and any(
            sym in elf.sym
            for sym in ("_dl_tls_setup", "name_to_handle_at", "_rtld_global")
        ):
            bins["ld"].append(f)

        else:
            if is_kernel and f.endswith(".ko"):
                bins["challs"] = [f]
            elif not (is_kernel and bins["challs"] and bins["challs"][0].endswith(".ko")):
                bins["challs"].append(f)

        os.chmod(f, 0o755)

    return bins


def process_binaries(path: Path) -> dict | None:
    bins = find_bins(path)

    if not bins["elf"]:
        return None

    sorted_bins = sort_bins(bins)

    if bins["vmlinuz"]:
        sorted_bins["vmlinuz"] = [bins["vmlinuz"]]
    if bins["archive"]:
        sorted_bins["archive"] = [bins["archive"]]

    for key, val in sorted_bins.items():
        if val:
            log.success("%s found: %s" % (key, ", ".join(val)))

    return sorted_bins


def fetch_ld(bins: dict, path: Path) -> bool:
    for libc in bins["libc"]:
        lib_path = libcdb.download_libraries(libc)
        if lib_path is None:
            continue
        ld_src = Path(lib_path) / "ld-linux-x86-64.so.2"
        ld_dst = path / "ld-linux-x86-64.so.2"
        shutil.copy(ld_src, ld_dst)
        bins["ld"] = [str(ld_dst)]
        return True
    return False


def patchelf(bins: dict, path: Path):
    chall = bins["challs"][0]
    os.system("patchelf --set-rpath %s %s" % (path, chall))
    os.system("patchelf --set-interpreter %s %s" % (os.path.basename(bins["ld"][0]), chall))


def open_file(path: Path):
    if path.is_file():
        overwrite = input(f"Do you want to overwrite {path.name}? [Y,n]: ")
        if overwrite.lower() == "n":
            return None
    return open(path, "w")


def gen_files(path: Path, bins: dict) -> dict:
    templates = Path(os.path.dirname(os.path.realpath(__file__))) / "templates"
    chall = os.path.basename(path)

    checksecs = []
    for group in bins.values():
        for f in (group or []):
            try:
                checksecs.append(f"[*] {f}\n" + ELF(f, checksec=False).checksec(color=False))
            except Exception:
                pass
    checksecs_str = "\n\n".join(checksecs)

    files = {}

    files["exploit.py"] = Template(filename=str(templates / "exploit.py")).render(
        chall="./" + os.path.basename(bins["challs"][0]),
        libc="./" + os.path.basename(bins["libc"][0]) if bins.get("libc") else None,
        archive="./" + os.path.basename(bins["archive"][0]) if bins.get("archive") else None,
        vmlinuz="./" + os.path.basename(bins["vmlinuz"][0]) if bins.get("vmlinuz") else None,
    )

    files["notes.md"] = Template(filename=str(templates / "notes.md")).render(
        chall=chall,
        date=datetime.datetime.now().strftime("%d/%m/%Y"),
        checksecs=checksecs_str,
        author=config.get("author", "pwner", "PWNINIT_AUTHOR"),
    )

    if bins.get("vmlinuz"):
        files["exploit.c"] = Template(filename=str(templates / "exploit.c")).render(
            kernel_module = os.path.basename(bins["challs"][0].split('.ko')[0])
        )
        files["Makefile"] = Template(filename=str(templates / "Makefile")).render()

    return files


def setup_libc_ld(sorted_bins: dict, path: Path) -> bool:
    if sorted_bins["libc"] and not sorted_bins["ld"]:
        log.info("Attempting to fetch ld for libc...")
        if not fetch_ld(sorted_bins, path):
            log.error("Cannot fetch ld corresponding to libc")
            return False

    if sorted_bins["libc"] and sorted_bins["ld"]:
        try:
            patchelf(sorted_bins, Path(os.path.abspath(path)))
            log.success("Patched binary with libc and ld")
        except Exception as e:
            log.error("Error patching binary: %s" % e)
            return False

    return True


def write_output_files(files: dict, path: Path) -> bool:
    for filename, content in files.items():
        try:
            f = open_file(path / filename)
            if f:
                f.write(content)
                f.close()
                log.success("Created %s" % filename)
        except Exception as e:
            log.error("Error creating %s: %s" % (filename, e))
    return True


def split_argv(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    provider, setup, top_args = [], [], []
    i = 0

    while i < len(argv):
        if argv[i] in ("-p", "--provider", "-s", "--setup"):
            flag = argv[i]
            i += 1
            if i >= len(argv):
                log.error("%s requires a plugin name" % flag)
                break
            name = argv[i]
            i += 1
            plugin_args = []
            while i < len(argv) and argv[i] not in TOP_FLAGS:
                plugin_args.append(argv[i])
                i += 1
            (provider if flag in ("-p", "--provider") else setup).append((name, plugin_args))
        else:
            top_args.append(argv[i])
            i += 1

    return top_args, provider, setup


def parse_top_args(top_args):
    parser = argparse.ArgumentParser(description="pwninit - CTF binary exploitation setup tool")
    parser.add_argument("--list-plugins", "-l", action="store_true", help="list all available plugins")
    parser.add_argument("--provider", "-p")
    parser.add_argument("--setup", "-s")
    return parser.parse_args(top_args)


def parse_plugin_args(plugin, raw_args):
    parser = argparse.ArgumentParser(prog=plugin.name, description=plugin.description)
    for a in plugin.args:
        a = dict(a)
        name = a.pop("name")
        short = a.pop("short", None)
        parser.add_argument(*([short, name] if short else [name]), **a)
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

    for p in args.provider or []:
        ret = run_plugins(p, "provide", path)
        if ret:
            path = ret

    sorted_bins = process_binaries(path)
    if not sorted_bins:
        log.info("No binaries found")
        return 1

    is_kernel = bool(sorted_bins.get("vmlinuz"))

    if not is_kernel:
        if not setup_libc_ld(sorted_bins, path):
            return 1

    files = gen_files(path, sorted_bins)

    for s in args.setup or []:
        ret = run_plugins(s, "setup", sorted_bins)
        if ret:
            files.update(ret)

    if not write_output_files(files, path):
        return 1

    log.success("pwninit completed successfully")
    return 0
