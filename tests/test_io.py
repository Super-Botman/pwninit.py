import socket
import threading
import sys
import pytest
from unittest.mock import MagicMock
from pwninit import IOContext, Config, Args, NC
from pwn import PwnlibException

HOST = "localhost"

@pytest.fixture()
def port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]

@pytest.fixture()
def echo_server():
    """Spawns an echo server on a guaranteed free ephemeral port."""
    host = "localhost"
    with socket.create_server((host, 0), reuse_port=True) as s:
        port = s.getsockname()[1]
        stop_event = threading.Event()

        def run_server():
            s.settimeout(0.5)
            while not stop_event.is_set():
                try:
                    conn, _ = s.accept()
                    with conn:
                        data = conn.recv(1024)
                        if data:
                            conn.sendall(data)
                except socket.timeout:
                    continue

        t = threading.Thread(target=run_server)
        t.start()
        
        yield host, port
        
        stop_event.set()
        t.join()


def test_IOContext_init():
    with pytest.raises(PwnlibException, match="Must specify argv or executable"):
        IOContext(Args(), Config())
    with pytest.raises(PwnlibException, match="does not exist"):
        IOContext(Args(), Config(chall="invalid"))


def test_connect(echo_server):
    ioctx = IOContext(Args(), Config(chall="ls"))

    assert ioctx.recv().endswith(b'\n')
    with pytest.raises(EOFError):
        ioctx.recv(timeout=0.2)
    ioctx.close()

    # Leverage the dynamic fixture instead of global variables
    host, port = echo_server
    ioctx = IOContext(Args(remote=NC(host, port)), Config())

    ioctx.prompt("TEST1")
    assert ioctx.recv() == b"TEST1\n"
    ioctx.close()

    ioctx.reconnect()
    ioctx.prompt("TEST2")
    assert ioctx.recv() == b"TEST2\n"
    ioctx.close()


def test_local_arg(port):
    python_listener = (
        f"import socket, time; "
        f"s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); "
        f"s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
        f"s.bind(('{HOST}', {port})); "
        f"s.listen(1); "
        f"c, a = s.accept(); "
        f"c.sendall(b'TEST3\\n'); "
        f"time.sleep(0.2);"
    )
    ioctx = IOContext(
        Args(remote=NC(HOST, port), local=True),
        Config(chall=["python3", "-c", python_listener])
    )
    assert ioctx.proc
    assert ioctx.proc is not ioctx.conn
    assert ioctx.rl() == b"TEST3\n"
    ioctx.close()


@pytest.mark.skipif(sys.platform == "linux", reason="broken on CI")
def test_docker_arg(monkeypatch, shared_path, docker_setup):
    mock_attach = MagicMock()
    monkeypatch.chdir(shared_path)
    monkeypatch.setattr("pwn.gdb.attach", mock_attach)

    ioctx = IOContext(
        Args(docker=True, remote=NC("localhost", 5000), debug=True),
        Config(binary="chall", docker_bin="run")
    )
    mock_attach.assert_called_once()
    assert b"TEST4" in ioctx.rl()
    ioctx.sl("TEST5")
    assert b"TEST5" in ioctx.rl()
    ioctx.close()
