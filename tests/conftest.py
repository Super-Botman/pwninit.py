import os
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
]


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

    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"

    try:
        build = subprocess.run(
            ["docker", "build", "-t", image_tag, "."],
            cwd=str(shared_path),
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print("=== docker build stdout ===")
        print(e.stdout)
        print("=== docker build stderr ===")
        print(e.stderr)
        raise

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
