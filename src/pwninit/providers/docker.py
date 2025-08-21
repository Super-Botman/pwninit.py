import docker
import tarfile
from io import BytesIO
from pwn import log


def run(name, path):
    client = docker.from_env()
    image_name = open(path / "Dockerfile",
                      "r").readline().replace("FROM ", "")[:-1]

    image = client.images.pull(image_name)
    libs = client.containers.run(
        image_name, 'ldd /bin/ls').replace(b' ', b'').split(b'\n')[:-1]
    libs = [lib.decode()[1:].split('=>')[-1].split('(')[0] for lib in libs]
    libs = list(dict.fromkeys(libs))

    log.success("libs founded: %s" % "".join(libs))

    container = client.containers.create(image_name)
    for lib in libs:
        extracting = log.progress("Extracting %s" % lib)
        archive_generator, stats = container.get_archive(lib)
        file_data = b''.join(archive_generator)

        tar_data = BytesIO(file_data)
        with tarfile.open(fileobj=tar_data) as tar:
            tar.extractall(path=path, filter='data')

        extracting.success("%s extracted" % lib)

    return path
