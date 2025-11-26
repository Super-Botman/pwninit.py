import docker
import tarfile
import os
from io import BytesIO
from pwn import log
from pathlib import Path


def extract_lib(container, lib, progress, name):
    progress.status("Extracting %s" % lib)
    archive_generator, _ = container.get_archive(lib)
    file_data = b''.join(archive_generator)

    tar_data = BytesIO(file_data)
    with tarfile.open(fileobj=tar_data) as tar:
        tar.extractall(path=name, filter='data')

    progress.status("%s extracted" % lib)


def run(_, path):
    client = docker.from_env()
    # Build Docker image from Dockerfile
    image = f"{os.path.basename(os.getcwd()).lower()}_pwninit"

    p = log.progress("Building image %s" % image)
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        client.images.build(path=str(path), tag=image)

    p.success("Image %s built" % image)

    container = client.containers.create(
        image, command=["tail", "-f", "/dev/null"])
    container.start()

    libs = container.exec_run("ldd /bin/ls").output.decode()
    lib_dir = [l.split("=>")[-1].split(" ")[1]
               for l in libs.split("\n") if "libc" in l][0]
    lib_dir = Path(os.path.dirname(lib_dir))

    log.success("lib dir founded: %s" % lib_dir)

    progress = log.progress("Extracting libs")

    files = ["libc.so.6", "ld-linux-x86-64.so.2"]
    for f in files:
        real_path = container.exec_run(
            "ls -la %s" % (lib_dir / f)).output.decode()

        if "->" in real_path:
            real_path = real_path.split("-> ")[-1][:-1]
        else:
            real_path = f
        extract_lib(container, lib_dir / real_path, progress, f)

    container.kill()
    container.remove()

    progress.success("libs extracted")

    return path


run("", Path("."))
