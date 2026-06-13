import io
import logging
import subprocess
import threading
from pathlib import Path

from pwninit.pwninit import build_docker, process_elf, setup_libc_ld, ls
from pwn import ELF


def test_docker(shared_path, monkeypatch, caplog, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))

    with caplog.at_level(logging.INFO):
        # Passing daemon=True ensures the test runner won't hang if the thread fails
        t = threading.Thread(target=build_docker, args=(shared_path,), daemon=True)
        t.start()
        t.join(timeout=30)

    out, err = capsys.readouterr()
    assert "Do you want" in out
    assert "Building docker image" in caplog.text
    assert "Building docker image: done" in caplog.text


def test_process_bins(isolated_path):
    # Now uses the improved isolated_path fixture naturally
    files = ls(isolated_path)

    assert str(isolated_path / "ld-linux-x86-64.so.2") in files["elf"]
    assert str(isolated_path / "chall") in files["elf"]

    process_elf(files)

    # Clean assertions against exact path objects
    assert files["elf"]["challs"] == [str(isolated_path / "chall")]
    assert files["elf"]["ld"] == [str(isolated_path / "ld-linux-x86-64.so.2")]


def test_setup_libc_ld_returns_true(bins):
    assert setup_libc_ld(bins, Path(".")) is True


def test_setup_libc_ld_ld_fetched(bins):
    setup_libc_ld(bins, Path("."))
    ld_path = Path(bins["elf"]["ld"][0])

    assert ld_path.exists(), f"ld file missing at {ld_path}"


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
        capture_output=True,
        text=True,
        check=True,
    )
    assert Path(out.stdout.strip()).name == ld_name


def test_setup_libc_ld_no_libc(bins_no_libc):
    assert setup_libc_ld(bins_no_libc, Path(".")) is False


def test_setup_libc_ld_patchelf_missing(bins_no_patchelf):
    if setup_libc_ld(bins_no_patchelf, Path(".")):
        elf = ELF(bins_no_patchelf["elf"]["challs"][0], checksec=False)
        assert elf.rpath != b"."  # Note: rpath returns bytes in pwntools
