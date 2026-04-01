import argparse
import datetime
import os
import shutil
import subprocess
import sys
import re
from pathlib import Path

import magic
import docker
from mako.template import Template
from pwn import ELF, context, libcdb, log

from pwninit.config import config
from pwninit.kernel import decompress
from pwninit.plugins import print_plugin_list, run_plugins

QEMU_DEFAULT = [
    "qemu-system-x86_64",
    "-no-reboot", "-cpu", "max",
    "-net", "none",
    "-serial", "mon:stdio",
    "-display", "none",
    "-monitor", "none",
    "-append", "console=ttyS0",
]

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

ELF_MIMES = {
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-pie-executable",
    "application/x-object",
}

KERNEL_STRINGS = ["linux kernel", "bzimage", "zimage"]

SHELL_MIMES = {"text/x-shellscript"}

def is_archive(path: str) -> bool:
    mime = magic.from_file(path, mime=True)
    desc = magic.from_file(path).lower()

    if mime in ARCHIVE_MIMES:
        return True

    if any(s in desc for s in ARCHIVE_STRINGS):
        return True

    try:
        data = open(path, "rb").read()
        decompressed = decompress(data, mime)
        if decompressed != data:
            inner_mime = magic.from_buffer(decompressed, mime=True)
            inner_desc = magic.from_buffer(decompressed).lower()
            return inner_mime in ARCHIVE_MIMES or any(s in inner_desc for s in ARCHIVE_STRINGS)
    except Exception:
        pass

    return False

def is_elf(path: str) -> bool:
    return magic.from_file(path, mime=True) in ELF_MIMES

def is_kernel(path: str) -> bool:
    return any(s in magic.from_file(path).lower() for s in KERNEL_STRINGS)

def is_shell(path: str) -> bool:
    mime = magic.from_file(path, mime=True)
    if mime not in SHELL_MIMES:
        return False
    desc = magic.from_file(path).lower()
    return not any(s in desc for s in ("bash", "zsh", "fish", "csh"))

def ls(dir: Path) -> dict:
    files = [
        Path(dir) / f
        for f in os.listdir(dir)
        if os.path.isfile(os.path.join(dir, f))
    ]

    result = {"elf": [], "kernel": [], "archive": [], "shell": []}

    for file in files:
        path = str(file)

        if is_elf(path):
            result["elf"].append(path)

        elif is_kernel(path):
            result["kernel"].append(path)
            if not os.path.isfile(f"{file}.elf"):
                status = log.progress(f"converting {file} to elf")
                subprocess.run(
                    ["vmlinux-to-elf", file, f"{file}.elf"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                status.success("done")

        elif is_archive(path):
            result["archive"].append(path)

        elif is_shell(path):
            result["shell"].append(path)

    return result

def sort_bins(files: dict) -> dict:
    bins = {"libc": [], "ld": [], "challs": []}
    is_kernel = bool(files["kernel"])

    for f in files["elf"]:
        context.log_level = "error"
        elf = ELF(f, checksec=False)
        context.log_level = "info"

        soname = getattr(elf.dynamic_by_tag("DT_SONAME"), "soname", "")

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
    files = ls(path)

    for key, val in files.items():
        if val:
            log.success("%s found: %s" % (key, ", ".join(val)))


    if not files["elf"] and not files['kernel']:
        return None
    else:
        files["elf"] = sort_bins(files)
        for key, val in files["elf"].items():
            if val:
                log.success("%s: %s" % (key, ", ".join(val)))

    return files


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

def relpath(files, type):
    return "./" + os.path.basename(files[type][0]) if files.get(type) else None

def patch_run(path: str) -> int:
    with open(path, "r") as f:
        lines = f.readlines()

    start = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*qemu-system-\S+", line):
            start = i
            break

    if start is None:
        return 0

    end = start
    for i in range(start, len(lines)):
        end = i
        if not lines[i].rstrip().endswith("\\"):
            break

    cmd_lines = [l.rstrip("\n") for l in lines[start:end + 1]]

    if any('"$@"' in l for l in cmd_lines):
        return 1

    indent = "    "
    for l in cmd_lines[1:]:
        m = re.match(r"^(\s+)", l)
        if m:
            indent = m.group(1)
            break

    last = cmd_lines[-1].rstrip()
    if not last.endswith("\\"):
        last += " \\"
    cmd_lines[-1] = last

    cmd_lines.append(f'{indent}"$@"')

    result = lines[:start] + [l + "\n" for l in cmd_lines] + lines[end + 1:]

    with open(path, "w") as f:
        f.writelines(result)

    return 2

def gen_files(path: Path, bins: dict) -> dict:
    templates = Path(os.path.dirname(os.path.realpath(__file__))) / "templates"
    chall = os.path.basename(path)
    files = {}

    checksecs = []
    for group in bins.values():
        for f in (group or []):
            try:
                checksecs.append(f"[*] {f}\n" + ELF(f, checksec=False).checksec(color=False))
            except Exception:
                pass
    checksecs_str = "\n\n".join(checksecs)

    archive = relpath(bins, "archive")
    kernel = relpath(bins, "kernel")
    qemu = None
    if archive or kernel:
        QEMU_DEFAULT.append('-kernel')
        QEMU_DEFAULT.append(relpath(files, "kernel"))
        QEMU_DEFAULT.append('-initrd')
        QEMU_DEFAULT.append(relpath(files, "archive"))
        qemu = QEMU_DEFAULT

        for f in bins["shell"]:
            ret = patch_run(f)
            if ret==1:
                log.info(f'already patched {f}')
                qemu = [f]

            if ret==2:
                log.success(f'patched {f}')
                qemu = [f]

    files["exploit.py"] = Template(filename=str(templates / "exploit.py")).render(
        binary=relpath(bins["elf"], "challs"),
        libc=relpath(bins["elf"], "libc"),
        archive=archive,
        kernel=kernel,
        qemu=qemu
    )

    files["notes.md"] = Template(filename=str(templates / "notes.md")).render(
        chall=chall,
        date=datetime.datetime.now().strftime("%d/%m/%Y"),
        checksecs=checksecs_str,
        author=config.get("author", "pwner", "PWNINIT_AUTHOR"),
    )

    if bins.get("kernel"):
        kernel_module = relpath(bins['elf'], 'challs')
        if kernel_module:
            kernel_module = kernel_module.split('.ko')[0][2:]

        files["exploit.c"] = Template(filename=str(templates / "exploit.c")).render(
            kernel_module = kernel_module
        )
        files["Makefile"] = Template(filename=str(templates / "Makefile")).render()

    return files


def setup_libc_ld(bins: dict, path: Path) -> bool:
    sorted_bins = bins["elf"]
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
    
    client = docker.from_env()
    name = path.resolve().name
    image_tag = f"pwninit-{name}:latest"
    try:
        image, build_logs = client.images.build(
            path=str(path), tag=image_tag, rm=True, forcerm=True
        )
        for _ in build_logs:
            pass
        log.success('Built docker image')
    except docker.errors.APIError:
        pass
    except Exception as e:
        log.warning(f"Build failed: {str(e)}")
        raise

    is_kernel = bool(sorted_bins.get("kernel"))

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
