import io
import logging
import os
import subprocess
import threading
from pathlib import Path

import pytest
from pwninit.pwninit import *
from pwn import ELF


@pytest.fixture()
def bins(isolated_path):
    os.chdir(isolated_path)
    files = ls(isolated_path)
    process_elf(files)
    return files


@pytest.fixture()
def bins_no_libc(isolated_path):
    (isolated_path / "libc.so.6").unlink()
    os.chdir(isolated_path)
    files = ls(isolated_path)
    process_elf(files)
    return files


@pytest.fixture()
def bins_no_patchelf(isolated_path, monkeypatch):
    os.chdir(isolated_path)
    files = ls(isolated_path)
    process_elf(files)
    monkeypatch.setenv("PATH", "")
    return files


def test_docker(shared_path, monkeypatch, caplog, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))

    with caplog.at_level(logging.INFO):
        t = threading.Thread(target=build_docker, args=(shared_path,))
        t.start()
        t.join(timeout=30)

    out = capsys.readouterr().out
    assert "Do you want" in out

    assert "Building docker image" in caplog.text
    assert "Building docker image: done" in caplog.text


def test_process_bins(shared_path):
    files = ls(shared_path)
    assert f"{shared_path}/ld-linux-x86-64.so.2" in files["elf"]
    assert f"{shared_path}/libc.so.6" in files["elf"]
    assert f"{shared_path}/chall" in files["elf"]

    process_elf(files)
    assert files["elf"] == {
        "challs": [f"{shared_path}/chall"],
        "ld":     [f"{shared_path}/ld-linux-x86-64.so.2"],
        "libc":   [f"{shared_path}/libc.so.6"],
        "libs":   [],
    }


def test_setup_libc_ld_returns_true(bins):
    assert setup_libc_ld(bins, Path(".")) is True


def test_setup_libc_ld_ld_fetched(bins):
    setup_libc_ld(bins, Path("."))

    b = bins["elf"]
    assert b["ld"], "ld should be populated after fetch"
    assert Path(b["ld"][0]).exists(), f"ld file missing at {b['ld'][0]}"


def test_setup_libc_ld_rpath(bins):
    setup_libc_ld(bins, Path("."))

    elf = ELF(bins["elf"]["challs"][0], checksec=False)
    assert elf.rpath == b"."


def test_setup_libc_ld_interpreter(bins):
    setup_libc_ld(bins, Path("."))

    b = bins["elf"]
    ld_name = Path(b["ld"][0]).name

    out = subprocess.run(
        ["patchelf", "--print-interpreter", b["challs"][0]],
        capture_output=True, text=True,
    )
    assert Path(out.stdout.strip()).name == ld_name


def test_setup_libc_ld_unstripped(bins):
    setup_libc_ld(bins, Path("."))

    b = bins["elf"]
    for lib in b["libc"] + b["libs"]:
        out = subprocess.run(["nm", "-D", lib], capture_output=True, text=True)
        assert out.returncode == 0, f"nm failed on {lib}"
        assert out.stdout.strip(), f"{lib} appears still stripped"


def test_setup_libc_ld_no_libc(bins_no_libc):
    assert setup_libc_ld(bins_no_libc, Path(".")) is False


def test_setup_libc_ld_patchelf_missing(bins_no_patchelf):
    result = setup_libc_ld(bins_no_patchelf, Path("."))

    if result:
        elf = ELF(bins_no_patchelf["elf"]["challs"][0], checksec=False)
        assert elf.rpath != "."
