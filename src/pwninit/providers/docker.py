import docker
import tarfile
import os
from io import BytesIO
from pwn import log
from pathlib import Path


def extract_lib(container, lib, progress):
    progress.status("Extracting %s" % lib)
    archive_generator, _ = container.get_archive(lib)
    file_data = b"".join(archive_generator)

    tar_data = BytesIO(file_data)
    with tarfile.open(fileobj=tar_data) as tar:
        # Get the first (and only) member from the archive
        members = tar.getmembers()
        if members:
            member = members[0]
            # Extract to current directory
            member_file = tar.extractfile(member)
            if member_file:
                # Write the file with just the basename (clean name)
                output_path = Path(os.path.basename(str(lib)))
                with open(output_path, "wb") as f:
                    f.write(member_file.read())
                progress.status("%s extracted to %s" % (lib, output_path))
            else:
                progress.failure("Failed to extract file from %s" % lib)
        else:
            progress.failure("No files found in archive for %s" % lib)


def run(name, path):
    client = docker.from_env()

    progress = log.progress("Docker provider")

    # Build the Dockerfile
    progress.status("Building image")
    image_tag = f"pwninit-{name}:latest"

    try:
        image, build_logs = client.images.build(
            path=str(path), tag=image_tag, rm=True, forcerm=True
        )
        # Consume build logs
        for _ in build_logs:
            pass
    except Exception as e:
        progress.failure(f"Build failed: {str(e)}")
        raise

    # Create and start container
    progress.status("Starting container")
    container = client.containers.create(image_tag, command=["tail", "-f", "/dev/null"])
    container.start()

    # Find libc path
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
            [
                "sh",
                "-c",
                "find /lib /usr/lib /lib64 /usr/lib64 -name 'libc.so.6' 2>/dev/null | head -1",
            ]
        )
        if result.output and result.exit_code == 0:
            libc_path = result.output.decode().strip()

    if not libc_path:
        progress.failure("Could not locate libc.so.6")
        raise Exception("Could not locate libc.so.6 in container")

    lib_dir = Path(os.path.dirname(libc_path))

    # Find ld-linux
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

    # Extract libraries
    extract_lib(container, libc_path, progress)
    extract_lib(container, ld_path, progress)

    # Cleanup
    progress.status("Cleaning up")
    container.kill()
    container.remove()

    try:
        client.images.remove(image_tag, force=True)
    except Exception:
        pass

    progress.success("Done")

    return path
