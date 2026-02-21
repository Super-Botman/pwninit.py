import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import tempfile
from argparse import Namespace
from io import BytesIO
from pathlib import Path

import lz4.frame
import magic
import zstandard
from pwn import log


def decompress(data: bytes, mime: str) -> bytes:
    match mime:
        case "application/gzip" | "application/x-gzip":
            return gzip.decompress(data)
        case "application/x-xz":
            return lzma.decompress(data)
        case "application/x-bzip2":
            return bz2.decompress(data)
        case "application/zstd":
            return zstandard.ZstdDecompressor().decompress(data)
        case "application/x-lz4":
            return lz4.frame.decompress(data)
        case _:
            return data

def recompress(data: bytes, mime: str) -> bytes:
    match mime:
        case "application/gzip" | "application/x-gzip":
            return gzip.compress(data)
        case "application/x-xz":
            return lzma.compress(data)
        case "application/x-bzip2":
            return bz2.compress(data)
        case "application/zstd":
            return zstandard.ZstdCompressor().compress(data)
        case "application/x-lz4":
            return lz4.frame.compress(data)
        case _:
            return data

def inject(image: str, exploit: str, dest: str = "./") -> bool:
    path = Path(image)
    exploit_path = Path(exploit)
    mime = magic.from_file(image, mime=True)
    
    # --- disk image (raw, qcow2, vmdk...) ---
    if mime in ("application/octet-stream",) or path.suffix in (".img", ".qcow2", ".vmdk", ".vdi"):
        log.success("Detected disk image, using guestfish")
        subprocess.run([
            "guestfish", "-a", image, "-m", "/dev/sda1",
            "copy-in", exploit, dest
        ], check=True)
        return True

    # --- squashfs ---
    if mime == "application/x-squashfs" or "squashfs" in magic.from_file(image).lower():
        log.success("Detected squashfs")
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["unsquashfs", "-d", f"{tmp}/sq", image], check=True)
            shutil.copy(exploit, f"{tmp}/sq/{dest}/{exploit_path.name}")
            subprocess.run(["mksquashfs", f"{tmp}/sq", image + ".new"], check=True)
        shutil.move(image + ".new", image)
        return True

    # --- ext2/ext4 ---
    if mime in ("application/x-ext2", "application/x-ext4"):
        log.succcess("Detected ext image, using guestfish")
        subprocess.run([
            "guestfish", "-a", image, "-m", "/dev/sda",
            "copy-in", exploit, dest
        ], check=True)
        return True

    # --- compressed or raw cpio (initramfs) ---
    data = path.read_bytes()
    decompressed = decompress(data, mime)
    inner_mime = magic.from_buffer(decompressed, mime=True)

    if "cpio" in inner_mime or "cpio" in magic.from_buffer(decompressed).lower():
        log.info(f"Detected cpio initramfs (compression: {mime})")
        with tempfile.TemporaryDirectory() as tmp:
            cpio_path = Path(tmp) / "initramfs.cpio"
            cpio_path.write_bytes(decompressed)

            extract_dir = Path(tmp) / "fs"
            extract_dir.mkdir()

            subprocess.run(
                ["cpio", "-idv"],
                input=decompressed,
                cwd=extract_dir,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            shutil.copy(exploit, extract_dir / dest)
            os.chmod(extract_dir / dest, 0o755)

            result = subprocess.run(
                ["find", ".", "-print0"],
                cwd=extract_dir,
                capture_output=True,
                check=True,
            )
            new_cpio = subprocess.run(
                ["cpio", "--null", "-ov", "--format=newc"],
                input=result.stdout,
                cwd=extract_dir,
                capture_output=True,
                check=True,
            ).stdout

            path.write_bytes(recompress(new_cpio, mime))
        return True

    return False
