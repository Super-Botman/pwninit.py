from pwninit.plugins import Plugin, arg
from pathlib import Path
import docker
import tarfile
import os
from io import BytesIO
from pwn import log


def extract_lib(container, lib, progress):
    progress.status("Extracting %s" % lib)
    archive_generator, _ = container.get_archive(lib)
    file_data = b"".join(archive_generator)

    tar_data = BytesIO(file_data)
    with tarfile.open(fileobj=tar_data) as tar:
        members = tar.getmembers()
        if members:
            member = members[0]
            member_file = tar.extractfile(member)
            if member_file:
                output_path = Path(os.path.basename(str(lib)))
                with open(output_path, "wb") as f:
                    f.write(member_file.read())
                progress.status("%s extracted to %s" % (lib, output_path))
            else:
                progress.failure("Failed to extract file from %s" % lib)
        else:
            progress.failure("No files found in archive for %s" % lib)


class Plugin(Plugin):
    name = "docker"
    description = "Build Dockerfile and extract libc/ld from the container"
    provide_args = [
        arg("--dockerfile", help="Path to Dockerfile directory", default="."),
        arg("--tag", help="Docker image tag override", default=None),
    ]

    def provide(self, args, path):
        client = docker.from_env()
        progress = log.progress("Docker provider")

        dockerfile_path = Path(args.dockerfile)
        name = dockerfile_path.resolve().name
        image_tag = args.tag or f"pwninit-{name}:latest"

        progress.status("Building image")
        try:
            image, build_logs = client.images.build(
                path=str(dockerfile_path), tag=image_tag, rm=True, forcerm=True
            )
            for _ in build_logs:
                pass
        except Exception as e:
            progress.failure(f"Build failed: {str(e)}")
            raise

        progress.status("Starting container")
        container = client.containers.create(image_tag, command=["tail", "-f", "/dev/null"])
        container.start()

        progress.status("Locating libc")
        common_paths = [
            "/lib/x86_64-linux-gnu",
            "/lib64",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
        ]

        libc_path = None
        ld_path = None

        for common_path in common_paths:
            result = container.exec_run(
                ["sh", "-c", f"test -f {common_path}/libc.so.6 && echo found"]
            )
            if b"found" in result.output:
                libc_path = f"{common_path}/libc.so.6"
                break

        if not libc_path:
            progress.status("Searching filesystem for libc")
            result = container.exec_run(
                ["sh", "-c",
                 "find /lib /usr/lib /lib64 /usr/lib64 -name 'libc.so.6' 2>/dev/null | head -1"]
            )
            if result.output and result.exit_code == 0:
                libc_path = result.output.decode().strip()

        if not libc_path:
            progress.failure("Could not locate libc.so.6")
            raise Exception("Could not locate libc.so.6 in container")

        lib_dir = Path(os.path.dirname(libc_path))

        progress.status("Locating ld-linux")
        ld_names = [
            "ld-linux-x86-64.so.2",
            "ld-linux-x86-64.so.*",
            "ld-linux.so.2",
            "ld-*.so",
        ]

        for ld_name in ld_names:
            result = container.exec_run(
                ["sh", "-c", f"ls {lib_dir}/{ld_name} 2>/dev/null | head -1"]
            )
            if result.output and result.exit_code == 0:
                ld_path = result.output.decode().strip()
                if ld_path:
                    break

        if not ld_path:
            progress.failure("Could not locate ld-linux")
            raise Exception("Could not locate ld-linux in container")

        extract_lib(container, libc_path, progress)
        extract_lib(container, ld_path, progress)

        progress.status("Cleaning up")
        container.kill()
        container.remove()

        try:
            client.images.remove(image_tag, force=True)
        except Exception:
            pass

        progress.success("Done")
        return path
