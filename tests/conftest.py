from pwninit import IOContext, Config, Args
import os
import shutil
import subprocess
from pathlib import Path

import docker
import pytest
from pwninit import IOContext, Config, Args
from pwninit.pwninit import process_elf, ls

RESOURCES = Path(__file__).parent / "resources"
RESOURCE_FILES = ["chall", "Dockerfile", "libc.so.6", "ld-linux-x86-64.so.2", "run"]

client = docker.from_env()

# Consider utilizing pytest-order plugin instead of this manual hook if dependencies get complex
collect_order = [
    "tests/test_context.py",
    "tests/test_io.py",
    "tests/test_pwncontext.py",
    "tests/test_pwninit.py",
]


def pytest_collection_modifyitems(session, config, items):
    def sort_key(item):
        path = str(item.fspath)
        for i, f in enumerate(collect_order):
            if path.endswith(f):
                return i
        return 999

    items.sort(key=sort_key)


@pytest.fixture(scope="session")
def shared_path(tmp_path_factory):
    p = tmp_path_factory.mktemp("shared")
    for f in RESOURCE_FILES:
        shutil.copy(RESOURCES / f, p / f)
    return p


@pytest.fixture()
def isolated_path(tmp_path, monkeypatch):
    """Replaces manual _make_tmp_dir. Pytest automatically cleans tmp_path."""
    for f in RESOURCE_FILES:
        shutil.copy(RESOURCES / f, tmp_path / f)

    # monkeypatch safely restores the working directory after the test
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture()
def bins(isolated_path):
    files = ls(isolated_path)
    process_elf(files)
    return files


@pytest.fixture()
def bins_no_libc(isolated_path):
    (isolated_path / "libc.so.6").unlink()
    files = ls(isolated_path)
    process_elf(files)
    return files


@pytest.fixture()
def bins_no_patchelf(isolated_path, monkeypatch):
    files = ls(isolated_path)
    process_elf(files)
    monkeypatch.setenv("PATH", "")
    return files


@pytest.fixture()
def ioctx(bins):
    # FIX: Extract the actual string path from the list, not the stringified list
    chall_path = bins["elf"]["challs"][0] if bins["elf"]["challs"] else ""
    libc_path = bins["elf"]["libc"][0] if bins["elf"]["libc"] else ""

    ioctx = IOContext(Args(), Config(binary=str(chall_path), libc=str(libc_path)))
    yield ioctx
    ioctx.close()


@pytest.fixture()
def docker_setup(shared_path):
    """Cleaned up cleanup logic using Docker SDK to prevent container leaks in CI environments."""
    name = shared_path.resolve().name
    image_tag = f"pwninit-{name}:latest".lower()

    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"

    subprocess.run(
        ["docker", "buildx", "build", "--load", "-t", image_tag, "."],
        cwd=str(shared_path),
        env=env,
        check=True,
    )

    yield image_tag

    try:
        containers = client.containers.list(all=True, filters={"ancestor": image_tag})
        for c in containers:
            c.remove(force=True)
        client.images.remove(image_tag, force=True)
    except docker.errors.APIError as exc:
        print(f"Cleanup warning: {exc}")
