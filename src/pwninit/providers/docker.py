import docker
import tarfile
import os
from io import BytesIO
from pwn import log
from pathlib import Path


def extract_lib(container, lib, progress):
    progress.status("Extracting %s" % lib)
    archive_generator, _ = container.get_archive(lib)
    file_data = b''.join(archive_generator)

    tar_data = BytesIO(file_data)
    with tarfile.open(fileobj=tar_data) as tar:
        tar.extractall(path="./", filter='data')

    progress.status("%s extracted" % lib)


def run(name, path):
    client = docker.from_env()
    image_name = open(path / "Dockerfile",
                      "r").readline().replace("FROM ", "")[:-1]

    container = client.containers.create(
        image_name, command=["tail", "-f", "/dev/null"])
    container.start()

    libs = container.exec_run("ldd /bin/ls").output.decode()
    lib_dir = [l.split("=>")[-1].split(" ")[1]
               for l in libs.split("\n") if "libc" in l][0]
    lib_dir = Path(os.path.dirname(lib_dir))

    log.success("lib dir founded: %s" % lib_dir)

    progress = log.progress("Extracting libs")

    extract_lib(container, lib_dir / "libc.so.6", progress)
    extract_lib(container, lib_dir / "ld-linux-x86-64.so.2", progress)
    container.kill()
    container.remove()

    progress.success("libs extracted")

    return path


run("", Path("."))
