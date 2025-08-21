import argparse
import re
import shutil
import datetime
import importlib
import os
from pathlib import Path
from pwn import libcdb, ELF, log, context
from .config import config


def utils_type(value: str) -> list:
    return sum([value.replace(' ', '').split(',')], [])


def provider_type(value: str) -> list:
    url_pattern = r"(^https?:\/\/(?:www\.)?)([-a-zA-Z0-9@:%._\+~#=]{1,256})(\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$)"
    values = re.findall(url_pattern, value)

    if len(values) != 0 and len(values[0]) == 3:
        return values[0]
    else:
        return ["", value, ""]


def find_bins(dir: Path) -> list:
    files = [os.path.join(dir, f) for f in os.listdir(
        dir) if os.path.isfile(os.path.join(dir, f))]

    binary_files = []
    for file in files:
        magic = open(file, "rb").read(4)
        if magic == b'\x7fELF':
            binary_files.append(file)

    return binary_files


def sort_bins(files: list) -> dict:
    bins = {}
    bins["libc"] = []
    bins["ld"] = []
    bins["challs"] = []

    elf = None

    for f in files:
        print(f)
        context.log_level = "error"
        elf = ELF(f, checksec=False)
        context.log_level = "info"

        soname_tag = elf.dynamic_by_tag("DT_SONAME")

        if soname_tag and ("libc.so.0" in soname_tag.soname or
                           "libc.so.6" in soname_tag.soname):
            bins["libc"].append(f)

        elif not elf.statically_linked and (
                "_dl_tls_setup" in elf.sym or
                "name_to_handle_at" in elf.sym or
                "_rtld_global" in elf.sym):
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
            ld_path = lib_path / 'ld-linux-x86-64.so.2'
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
    if path.is_file():
        filename = os.path.basename(path)
        overwrite = input(
            f"Do you want to overwrite the content of {filename} ? [Y,n]: ")
        if overwrite.lower() == "n":
            return False

    return open(path, "w")


def gen_files(path, bins) -> dict:
    pwninit_path = Path(os.path.dirname(os.path.realpath(__file__)))
    templates = pwninit_path / "templates"
    chall = os.path.basename(path)
    checksecs = []
    for b in bins.values():
        checksecs.append([f"[*] {f}\n" +
                          ELF(f, checksec=False).checksec(color=False) for f in b])

    checksecs = "\n\n".join(sum(checksecs, []))

    files = {}

    files["exploit.py"] = open(templates / "exploit.py", "r").read().format(
        bins["challs"][0],
        bins["libc"][0] if bins["libc"] else ""
    )

    files["notes.md"] = open(templates / "notes.md", "r").read().format(
        chall, datetime.datetime.now().strftime("%d/%m/%Y"),
        checksecs, config.get_author()
    )

    return files


def parse_args():
    parser = argparse.ArgumentParser(description='pwninit')
    parser.add_argument('-p', '--provider', action='store',
                        metavar='provider', type=provider_type, help='fetch chall from url')
    parser.add_argument('-u', '--utils', action='store',
                        metavar='utils', type=utils_type, help='scripts to run on the binary')
    return parser.parse_args()


def run_provider(args, path: Path) -> Path:
    if not args.provider:
        return path

    provider_name = args.provider[1]
    try:
        return importlib.import_module(
            "pwninit.providers."+provider_name).run("".join(args.provider), path)
    except ModuleNotFoundError:
        log.error("Provider '%s' not found" % provider_name)
    except Exception as e:
        log.error("Error running provider '%s': %s" % (provider_name, str(e)))


def process_binaries(path: Path) -> dict:
    bins = find_bins(path)
    if len(bins) == 0:
        log.error("No bins founded in %s " % path)

    sorted_bins = sort_bins(bins)
    for filename in sorted_bins:
        if sorted_bins[filename]:
            log.success("%s founded: %s" %
                        (filename, ", ".join(sorted_bins[filename])))
    return sorted_bins


def setup_libc_ld(sorted_bins: dict, path: Path) -> bool:
    if sorted_bins["libc"] and not sorted_bins["ld"]:
        log.info("Attempting to fetch ld for libc...")
        if not fetch_ld(sorted_bins, path):
            log.error("Cannot fetch the ld corresponding to libc")

    if sorted_bins["libc"] and sorted_bins["ld"]:
        try:
            patchelf(sorted_bins, path)
            log.success("Patched binary with libc and ld")
        except Exception as e:
            log.error("Error patching binary: %s" % str(e))
    return True


def run_utilities(args, files: dict, sorted_bins: dict, path: Path) -> dict:
    if not args.utils:
        return files

    for util_name in args.utils:
        try:
            files = importlib.import_module(
                "pwninit.utils."+util_name).run(files, sorted_bins, path)
        except ModuleNotFoundError:
            log.error("Utility '%s' not found" % util_name)
        except Exception as e:
            log.error("Error running utility '%s': %s" % (util_name, str(e)))
    return files


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


def cli() -> int:
    args = parse_args()

    path = run_provider(args, Path("."))
    if not path:
        return 1

    sorted_bins = process_binaries(path)
    if not sorted_bins:
        return 1

    if not setup_libc_ld(sorted_bins, path):
        return 1

    files = gen_files(path, sorted_bins)

    files = run_utilities(args, files, sorted_bins, path)
    if files is None:
        return 1

    if not write_output_files(files, path):
        return 1

    log.success("pwninit completed successfully")
    return 0
