import os
import docker
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

RESOURCES = Path(__file__).parent / "resources"
RESOURCE_FILES = [
    "chall",
    "Dockerfile",
    "libc.so.6",
    "ld-linux-x86-64.so.2",
    "run"
]
client = docker.from_env()


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


@pytest.fixture()
def docker_setup(shared_path):
    name = shared_path.resolve().name
    image_tag = f"pwninit-{name}:latest".lower()

    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"

    subprocess.run(
        [
            "docker",
            "buildx",
            "build",
            "--load",
            "-t",
            image_tag,
            ".",
        ],
        cwd=str(shared_path),
        env=env,
        check=True,
    )

    try:
        client.images.get(image_tag)
    except docker.errors.ImageNotFound:
        raise RuntimeError(f"Docker image {image_tag} was not built correctly")

    yield image_tag

    try:
        result = subprocess.run(
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                f"ancestor={image_tag}",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

        container_ids = [
            cid.strip()
            for cid in result.stdout.splitlines()
            if cid.strip()
        ]

        if container_ids:
            subprocess.run(
                ["docker", "rm", "-f", *container_ids],
                check=False,
                capture_output=True,
            )

        subprocess.run(
            ["docker", "image", "rm", "-f", image_tag],
            check=False,
            capture_output=True,
        )

    except Exception as exc:
        print(f"Cleanup warning: {exc}")
