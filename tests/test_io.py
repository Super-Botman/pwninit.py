from unittest.mock import MagicMock
import pytest
import socket
import random
import threading
from time import sleep
from pwninit import IOContext, Config, Args, NC
from pwn import PwnlibException, listen

HOST = "localhost"
PORT = random.randrange(1024, 49151)

def echo_serv():
    with socket.create_server((HOST, PORT), reuse_port=True) as s:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(1024)
            conn.sendall(data)
            conn.close()
        s.close()

def test_IOContext_init():
    # Test creation of instances
    with pytest.raises(PwnlibException) as initinfo_empty:
        ioctx = IOContext(Args(), Config())
    with pytest.raises(PwnlibException) as initinfo_invalid:
        ioctx = IOContext(Args(), Config(chall="invalid"))

    assert "Must specify argv or executable" in str(initinfo_empty.value)
    assert "does not exist" in str(initinfo_invalid.value)


def test_connect():
    # Test IO
    ioctx = IOContext(Args(), Config(chall="ls"))

    assert ioctx.recv().endswith(b'\n')
    with pytest.raises(EOFError):
        ioctx.recv(timeout=0.2)

    
    # Test socket
    t = threading.Thread(target=echo_serv)
    t.start()
    ioctx = IOContext(Args(remote=NC(HOST, PORT)), Config())

    ioctx.prompt("TEST1")
    assert ioctx.recv() == b"TEST1\n"
    ioctx.close()

    t = threading.Thread(target=echo_serv)
    t.start()
    ioctx.reconnect()
    ioctx.prompt("TEST2")
    assert ioctx.recv() == b"TEST2\n"
    ioctx.close()


def test_local_arg():
    ioctx = IOContext(
        Args(
          remote=NC(HOST, PORT),
          local=True
        ),
        Config(
          chall=["bash", "-c", f"echo 'TEST3' | nc -lnvp {PORT}"]
        )
    )
    assert ioctx.proc
    assert (ioctx.proc is not ioctx.conn)

    assert ioctx.rl() == b"TEST3\n"
    ioctx.close()

def test_docker_arg(monkeypatch, shared_path, docker_setup):
    mock_attach = MagicMock()
    monkeypatch.chdir(shared_path)
    monkeypatch.setattr("pwn.gdb.attach", mock_attach)

    ioctx = IOContext(
        Args(
            docker=True,
            remote=NC(HOST, 5000),
            debug=True
        ),
        Config(
           binary=f"chall",
           docker_bin="run"
        )
    )
    mock_attach.assert_called_once()
    assert b"TEST4" in ioctx.rl()
    ioctx.sl("TEST5")
    assert b"TEST5" in ioctx.rl()
    ioctx.close()
