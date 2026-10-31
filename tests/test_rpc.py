"""Round-trip test: mock Thrift server <-> ThriftPipeClient.

Validates the hand-rolled TBinaryProtocol encoding/decoding without a
running aTrust installation.
"""

from __future__ import annotations

import socket
import struct
import threading
from pathlib import Path

from atrust_cli.thrift import ThriftPipeClient

T_STOP = 0
T_BOOL = 2
T_I32 = 8
T_STRING = 11
T_MAP = 13
VERSION_1 = 0x80010000
MSG_CALL = 1
MSG_REPLY = 2


class MockServer(threading.Thread):
    """Serves GetStatus (map<string,string>) and IsRpcStatusNormal (bool)."""

    def __init__(self, path: Path) -> None:
        super().__init__(daemon=True)
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(path))
        self.sock.listen(4)
        self.sock.settimeout(0.2)
        self._stopped = threading.Event()

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self._serve(conn)
            finally:
                conn.close()

    def stop(self) -> None:
        self._stopped.set()

    def _serve(self, conn: socket.socket) -> None:
        data = b""
        while len(data) < 4:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        # request: strict header, name, seqid, args struct (skipped)
        ver_type = struct.unpack(">i", data[:4])[0]
        assert ver_type & 0xFFFF0000 == VERSION_1
        assert (ver_type & 0xFF) == MSG_CALL
        pos = 4
        (nlen,) = struct.unpack(">i", data[pos:pos + 4]); pos += 4
        name = data[pos:pos + nlen].decode(); pos += nlen
        (seqid,) = struct.unpack(">i", data[pos:pos + 4])

        resp = bytearray()
        resp += struct.pack(">I", VERSION_1 | MSG_REPLY)
        resp += struct.pack(">i", len(name)) + name.encode()
        resp += struct.pack(">i", seqid)
        if name == "GetStatus":
            resp.append(T_MAP)
            resp += struct.pack(">h", 0)               # result field id 0
            resp.append(T_STRING); resp.append(T_STRING)
            resp += struct.pack(">i", 1)               # one map entry
            resp += struct.pack(">i", 6) + b"status"
            resp += struct.pack(">i", 1) + b"3"
        elif name == "IsRpcStatusNormal":
            resp.append(T_BOOL)
            resp += struct.pack(">h", 0)
            resp.append(1)
        else:
            raise AssertionError(f"unexpected method {name}")
        resp.append(T_STOP)
        conn.sendall(bytes(resp))


def test_roundtrip(tmp_path: Path) -> None:
    sock_path = tmp_path / "mock-core"
    server = MockServer(sock_path)
    server.start()
    try:
        client = ThriftPipeClient(sock_path, "SdpCoreService", timeout=2.0)
        assert client.call("GetStatus", None, T_MAP) == {"status": "3"}
        assert client.call("IsRpcStatusNormal", None, T_BOOL) is True
        assert client._seq == 2
    finally:
        server.stop()
        server.join(timeout=2)
