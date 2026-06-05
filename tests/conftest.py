import io
import pytest
import shutil
import tempfile
import subprocess
from pathlib import Path
from pwninit.pwninit import build_docker

path = Path(tempfile.mkdtemp())
files = ["chall", "Dockerfile", "libc.so.6", "ld-linux-x86-64.so.2"]

for f in files:
    shutil.copy(f"tests/ressources/{f}", path / f)

@pytest.fixture(scope="session", autouse=True)
def docker_setup():
    name = path.resolve().name
    image_tag = f"pwninit-{name}:latest".lower()
    subprocess.run(
        ["docker", "build", "--load", "-t", image_tag, "."],
        cwd=str(path),
        check=True,
        capture_output=True,
        env={"DOCKER_BUILDKIT": "1"},
    )

    yield

    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"ancestor={image_tag}"],
        capture_output=True, text=True
    )
    container_id = result.stdout.strip()
    if container_id:
      subprocess.run(["docker", "stop", container_id])
    subprocess.run(["docker", "image", "rm", "--force", image_tag])

    
