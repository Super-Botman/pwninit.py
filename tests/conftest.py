import shutil
import subprocess
import tempfile
import pytest
from pathlib import Path

RESOURCES = Path(__file__).parent / "resources"
RESOURCE_FILES = ["chall", "Dockerfile", "libc.so.6", "ld-linux-x86-64.so.2"]

def _make_tmp_dir() -> Path:
    p = Path(tempfile.mkdtemp())
    for f in RESOURCE_FILES:
        shutil.copy(RESOURCES / f, p / f)
    return p


@pytest.fixture(scope="session")
def shared_path(tmp_path_factory):
    p = tmp_path_factory.mktemp("shared")
    for f in RESOURCE_FILES:
        shutil.copy(RESOURCES / f, p / f)
    return p


@pytest.fixture()
def isolated_path():
    p = _make_tmp_dir()
    yield p
    shutil.rmtree(p, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def docker_setup(shared_path):
    name = shared_path.resolve().name
    image_tag = f"pwninit-{name}:latest".lower()
    subprocess.run(
        ["docker", "build", "--load", "-t", image_tag, "."],
        cwd=str(shared_path),
        check=True,
        capture_output=True,
        env={"DOCKER_BUILDKIT": "1"},
    )

    yield

    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"ancestor={image_tag}"],
        capture_output=True, text=True,
    )
    container_id = result.stdout.strip()
    if container_id:
        subprocess.run(["docker", "stop", container_id])
    subprocess.run(["docker", "image", "rm", "--force", image_tag])
