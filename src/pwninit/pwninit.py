import argparse
import datetime
import os
import shutil
import subprocess
import sys
import re
import typing
from pathlib import Path

import magic
from mako.template import Template
from pwn import ELF, context, libcdb, log, parse_ldd_output

from pwninit.config import config
from pwninit.kernel import decompress
from pwninit.plugins import print_plugin_list, run_plugins, Plugin

QEMU_DEFAULT = [
    "qemu-system-x86_64",
    "-no-reboot", "-cpu", "max",
    "-net", "none",
    "-serial", "mon:stdio",
    "-display", "none",
    "-monitor", "none",
    "-append", "console=ttyS0",
]

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
            return inner_mime in ARCHIVE_MIMES or any(
                s in inner_desc for s in ARCHIVE_STRINGS
            )
    except Exception:
        pass

    return False


def is_elf(path: str) -> bool:
    return magic.from_file(path, mime=True) in ELF_MIMES


def is_lib(path: str) -> bool:
    return magic.from_file(path, mime=True) == "application/x-sharedlib"


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
        Path(dir) / f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f))
    ]

    result = {"elf": [], "kernel": [], "archive": [], "shell": []}

    for file in files:
        path = str(file)

        if is_elf(path):
            result["elf"].append(path)

        elif is_kernel(path):
            result["kernel"].append(path)

        elif is_archive(path):
            result["archive"].append(path)

        elif is_shell(path):
            result["shell"].append(path)

    return result


def sort_bins(files: dict) -> dict:
    bins = {"libc": [], "ld": [], "challs": [], "libs": []}
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

        elif is_kernel and f.endswith(".ko"):
            bins["challs"] = [f]

        elif is_lib(f):
            bins["libs"].append(f)

        else:
            bins["challs"].append(f)

        os.chmod(f, 0o755)

    return bins

def run_command(cmd: str, args: list, cwd=None) -> tuple:
    args = [cmd] + args
    try:
        proc = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    except Exception as exception:
        return "", str(exception)

    return proc.stdout, proc.stderr

def process_elf(files: dict):
    files["elf"] = sort_bins(files)
    for key, val in files["elf"].items():
        if val:
            log.success("%s: %s" % (key, ", ".join(val)))
    
def process_kernel(files: dict):
    for file in files["kernel"]:
        if not os.path.isfile(f"{file}.elf"):
            status = log.progress(f"converting {file} to elf")
            run_command("vmlinux-to-elf", [file, f"{file}.elf"])
            status.success("done")
    
def process_binaries(path: Path) -> dict | None:
    files = ls(path)

    for key, val in files.items():
        if val and key != "elf":
            log.success("%s found: %s" % (key, ", ".join(val)))

    if files["elf"]:
        process_elf(files)

    if files["kernel"]:
        process_kernel(files)

    return files


def fetch_libs(bins: dict) -> bool:
    if not bins["libc"]:
        return False

    libc = bins["libc"][0]
    blacklist = set(
        os.path.basename(l) for l in bins["libs"] + bins["ld"] + bins["libc"]
    )

    lib_path = libcdb.download_libraries(libc)
    if lib_path is None:
        log.warn("libcdb couldn't find libraries for this libc")
        return False

    lib_path = Path(lib_path)

    chall = bins["challs"][0]
    ldd_out, _ = run_command("ldd", [chall])
    needed = set(os.path.basename(p) for p in parse_ldd_output(ldd_out) if 'libc.so.6' not in p)
    need_ld = not bins["ld"]

    ld_fetched = False
    for f in lib_path.iterdir():
        if not f.is_file():
            continue

        if f.name in blacklist and 'libc.so.6' not in f.name:
            log.info(f"skipping {f.name} (already present)")
            continue

        is_ld = "ld-linux" in f.name or f.name.startswith("ld-")

        if f.name not in needed and not (is_ld and need_ld):
            continue

        if ld_fetched and is_ld:
            continue

        dst = Path(".") / f.name
        shutil.copy(f, dst)
        os.chmod(dst, 0o755)
        log.success(f"fetched {f.name}")

        if is_ld:
            ld_fetched = True
            bins["ld"].append(str(dst))
        else:
            bins["libs"].append(str(dst))

    return bool(bins["ld"])


def patch_elf(bins: dict):
    chall = bins["challs"][0]

    run_command("patchelf", ["--force-rpath", "--set-rpath", "--no-sort", ".", chall])
    run_command(
        "patchelf",
        ["--set-interpreter", os.path.basename(bins["ld"][0]), chall],
    )


def open_file(path: Path) -> None | typing.IO:
    return open(path, "w") if path.is_file() and input(f"Do you want to overwrite {path.name}? [Y,n]: ").lower() != "n" else None

def relpath(files, type) -> None | str:
    return "./" + os.path.basename(files[type][0]) if files.get(type) else None

def patch_run(path: str) -> bool:
    with open(path, "r") as f:
        lines = f.readlines()

    start = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*qemu-system-\S+", line):
            start = i
            break

    if start is None:
        return False

    end = start
    for i in range(start, len(lines)):
        end = i
        if not lines[i].rstrip().endswith("\\"):
            break

    cmd_lines = [l.rstrip("\n") for l in lines[start : end + 1]]

    if any('"$@"' in l for l in cmd_lines):
        log.info(f"already patched {path}")
        return True

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

    result = lines[:start] + [l + "\n" for l in cmd_lines] + lines[end + 1 :]

    with open(path, "w") as f:
        f.writelines(result)

    log.success(f"patched {path}")
    return True


def gen_files(path: Path, bins: dict) -> dict:
    templates = Path(os.path.dirname(os.path.realpath(__file__))) / "templates"
    chall = os.path.basename(path)
    files = {}

    checksecs = []
    for group in bins["elf"].values():
        for f in group or []:
            checksecs.append(
                f"[*] {f}\n" + ELF(f, checksec=False).checksec(color=False)
            )

    checksecs_str = "\n\n".join(checksecs)

    archive = relpath(bins, "archive")
    kernel = relpath(bins, "kernel")
    qemu = None

    if archive or kernel:
        QEMU_DEFAULT.append("-kernel")
        QEMU_DEFAULT.append(relpath(files, "kernel"))
        QEMU_DEFAULT.append("-initrd")
        QEMU_DEFAULT.append(relpath(files, "archive"))
        qemu = QEMU_DEFAULT

    if bins["shell"] and patch_run(bins["shell"][0]):
        qemu = bins["shell"][0]

    files["exploit.py"] = Template(filename=str(templates / "exploit.py")).render(
        binary=relpath(bins["elf"], "challs"),
        libc=relpath(bins["elf"], "libc"),
        libs=["./"+os.path.basename(l) for l in bins["elf"]["libs"]],
        archive=archive,
        kernel=kernel,
        qemu=qemu,
    )

    files["notes.md"] = Template(filename=str(templates / "notes.md")).render(
        chall=os.path.basename(os.getcwd()),
        date=datetime.datetime.now().strftime("%d/%m/%Y"),
        checksecs=checksecs_str,
        author=config.get("author", "pwner", "PWNINIT_AUTHOR"),
    )

    if bins.get("kernel"):
        kernel_module = relpath(bins["elf"], "challs")
        if kernel_module:
            kernel_module = kernel_module.partition(".")[0][2:]

        files["exploit.c"] = Template(filename=str(templates / "exploit.c")).render(
            kernel_module=kernel_module
        )
        files["Makefile"] = Template(filename=str(templates / "Makefile")).render()

    return files


def setup_libc_ld(bins: dict, path: Path) -> bool:
    sorted_bins = bins["elf"]
    p = log.progress("fetching libs")

    if not fetch_libs(sorted_bins):
        p.failure("cannot fetch libs")
    else:
        p.success("done")

    if not sorted_bins["ld"]:
        log.error("no ld found or fetched")
        return False
    
    patch_elf(sorted_bins)

    p = log.progress("unstriping libs")
    log_level = context.log_level
    context.log_level = "error"
    for l in sorted_bins["libc"] + sorted_bins["libs"]:
        libcdb.unstrip_libc(l)
    context.log_level = log_level
    p.success("done")

    log.success("patched binary with libc and ld")
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


def split_argv() -> tuple:
    argv = sys.argv[1:]
    provider_args, setup_args, top_args = [], [], []
    i = 0
    
    provider = -1
    setup = -1
    for arg in argv:
        if arg in ("-p", "--provider", ):
            provider += 1
            provider_args.append([])
            continue
        elif arg in ("-s", "--setup"):
            setup += 1
            setup_args.append([])
            continue
        elif arg in ("--list-plugins", "-l", "--help", "-h"):
            top_args.append(arg)
            setup, provider = False, False
            continue

        if provider >= 0:
            provider_args[provider].append(arg)

        elif setup >= 0:
            setup_args[setup].append(arg)

    return top_args, provider_args, setup_args


def parse_top_args(top_args: list) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="pwninit - CTF binary exploitation setup tool"
    )
    parser.add_argument(
        "--list-plugins",
        "-l",
        action="store_true",
        help="list all available plugins",
    )
    parser.add_argument("--provider", "-p")
    parser.add_argument("--setup", "-s")
    return parser.parse_args(top_args)


def parse_args() -> argparse.Namespace:
    top, provider, setup = split_argv()
    args = parse_top_args(top)
    args.provider = provider
    args.setup = setup
    return args

def build_docker(path: Path):
    build = input(f"Do you want to build the docker image ? [y,N]: ")

    if (path / "Dockerfile").exists() and build.lower() != 'y':
        return

    name = path.resolve().name
    image_tag = f"pwninit-{name}:latest".lower()
    try:
        subprocess.run(
            ["docker", "build", "--load", "-t", image_tag, "."],
            cwd=str(path),
            check=True,
            capture_output=True,
            env={**os.environ, "DOCKER_BUILDKIT": "1"},
        )
        log.success("Built docker image")
    except subprocess.CalledProcessError as e:
        log.warning(f"Build failed: {e.stderr.decode()}")
        raise


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
        log.info("no binaries found")
        sorted_bins = {"elf": {}, "kernel": [], "archive": [], "shell": []}

    is_kernel = bool(sorted_bins.get("kernel"))
    is_libc = bool(sorted_bins.get('libc'))
    if is_libc and not setup_libc_ld(sorted_bins, path):
        return 1 

    files = gen_files(path, sorted_bins)
    for s in args.setup or []:
        ret = run_plugins(s, "setup", sorted_bins)
        files.update(ret if ret else {})

    if not write_output_files(files, path):
        return 1

    log.success("pwninit completed successfully")
    return 0
