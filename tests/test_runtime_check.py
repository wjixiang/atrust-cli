import importlib.util
from pathlib import Path
import socket
import threading

import pytest

spec = importlib.util.spec_from_file_location('runtime_check', Path(__file__).resolve().parents[1]/'scripts/runtime/check-connection.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


@pytest.mark.parametrize('reply,success', [(b'notice\r\nSSH-2.0-test\r\n', True), (b'HTTP/1.1 200 OK\r\n', False)])
def test_ssh_probe_requires_protocol_identification_without_auth(reply, success):
    received = []
    failures = []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    def server():
        try:
            with listener.accept()[0] as sock:
                sock.settimeout(3)
                assert check.read_exact(sock, 3) == b'\x05\x01\x00'
                sock.sendall(b'\x05\x00')
                assert check.read_exact(sock, 4) == b'\x05\x01\x00\x03'
                length = check.read_exact(sock, 1)[0]
                received.append(check.read_exact(sock, length))
                received.append(check.read_exact(sock, 2))
                sock.sendall(b'\x05\x00\x00\x01'+b'\0'*6)
                for byte in reply:
                    sock.sendall(bytes([byte]))
        except BaseException as exc:
            failures.append(exc)
        finally:
            listener.close()
    thread = threading.Thread(target=server)
    thread.start()
    try:
        if success:
            assert check.ssh_probe(listener.getsockname()[1], 'intranet.invalid', 22)
        else:
            with pytest.raises(ValueError, match='no SSH protocol'):
                check.ssh_probe(listener.getsockname()[1], 'intranet.invalid', 22)
    finally:
        thread.join(5)
    assert not thread.is_alive()
    assert not failures
    assert received == [b'intranet.invalid', b'\0\x16']
