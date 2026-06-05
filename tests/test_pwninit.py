import io
import threading
import logging
import pytest
from pathlib import Path
from pwninit.pwninit import *
from pwninit import Args
from conftest import path

    
def test_docker(monkeypatch, caplog, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))

    with caplog.at_level(logging.INFO):
        t = threading.Thread(target=build_docker, args=(path,))
        t.start()
        t.join(timeout=30)

    out = capsys.readouterr().out
    assert "Do you want" in out  # this one is a print(), stays in capsys

    assert "Building docker image" in caplog.text
    assert "Building docker image: done" in caplog.text

def test_process_bins():
    files = ls(path)
    assert files == {
        "elf": [
            f"{path}/ld-linux-x86-64.so.2",
            f"{path}/libc.so.6",
            f"{path}/chall"
        ],
        "kernel": [],
        "archive": [],
        "shell": [],
    }

    process_elf(files)
    assert files["elf"] == {
        "challs": [
            f"{path}/chall",
        ],
        "ld": [
            f"{path}/ld-linux-x86-64.so.2",
        ],
        "libc": [
            f"{path}/libc.so.6",
        ],
        "libs": [],
    }
