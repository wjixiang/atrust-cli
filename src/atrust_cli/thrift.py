"""Minimal Apache Thrift TBinaryProtocol client over a Unix stream socket.

The aTrust client exposes its internal RPC services (SdpCoreService,
SdpDaemonService, ...) as Thrift servers on named pipes in
``/usr/share/sangfor/.aTrust/var/run/`` using TBufferedTransport +
TBinaryProtocol — the nodejs ``thrift`` package defaults.  This module
implements just enough of the wire protocol to make one-shot CALL/REPLY
round trips, with a generic decoder so unknown result structs decode
into plain Python values.

Field identifiers and argument signatures were recovered from the
generated JS clients shipped in
``/usr/share/sangfor/aTrust/resources/app/src/service/thrift/*.js``.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import Any

VERSION_1 = 0x80010000

# Thrift type ids (TType)
T_STOP = 0
T_BOOL = 2
T_BYTE = 3
T_DOUBLE = 4
T_I16 = 6
T_I32 = 8
T_I64 = 10
T_STRING = 11
T_STRUCT = 12
T_MAP = 13
T_SET = 14
T_LIST = 15

TYPE_NAMES = {
    T_STOP: "STOP", T_BOOL: "BOOL", T_BYTE: "BYTE", T_DOUBLE: "DOUBLE",
    T_I16: "I16", T_I32: "I32", T_I64: "I64", T_STRING: "STRING",
    T_STRUCT: "STRUCT", T_MAP: "MAP", T_SET: "SET", T_LIST: "LIST",
}

MSG_CALL = 1
MSG_REPLY = 2
MSG_EXCEPTION = 3


class ThriftError(Exception):
    """Protocol or transport failure while talking to an aTrust pipe."""


class _Writer:
    __slots__ = ("buf",)

    def __init__(self) -> None:
        self.buf = bytearray()

    def i32(self, v: int) -> None:
        self.buf += struct.pack(">i", v)

    def i16(self, v: int) -> None:
        self.buf += struct.pack(">h", v)

    def i64(self, v: int) -> None:
        self.buf += struct.pack(">q", v)

    def byte(self, v: int) -> None:
        self.buf += struct.pack(">b", v)

    def double(self, v: float) -> None:
        self.buf += struct.pack(">d", v)

    def string(self, s: str) -> None:
        raw = s.encode("utf-8")
        self.buf += struct.pack(">i", len(raw)) + raw

    def field_begin(self, ftype: int, fid: int) -> None:
        self.byte(ftype)
        self.i16(fid)

    def field_stop(self) -> None:
        self.buf.append(T_STOP)


class _Reader:
    __slots__ = ("sock", "buf")

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def _need(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ThriftError("connection closed mid-message")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def byte(self) -> int:
        return struct.unpack(">b", self._need(1))[0]

    def i16(self) -> int:
        return struct.unpack(">h", self._need(2))[0]

    def i32(self) -> int:
        return struct.unpack(">i", self._need(4))[0]

    def i64(self) -> int:
        return struct.unpack(">q", self._need(8))[0]

    def double(self) -> float:
        return struct.unpack(">d", self._need(8))[0]

    def string(self) -> str:
        n = self.i32()
        if n < 0 or n > 64 * 1024 * 1024:
            raise ThriftError(f"implausible string length {n}")
        return self._need(n).decode("utf-8", errors="replace")

    # generic decoding ---------------------------------------------------
    def value(self, ttype: int) -> Any:
        if ttype == T_BOOL:
            return self.byte() != 0
        if ttype == T_BYTE:
            return self.byte()
        if ttype == T_I16:
            return self.i16()
        if ttype == T_I32:
            return self.i32()
        if ttype == T_I64:
            return self.i64()
        if ttype == T_DOUBLE:
            return self.double()
        if ttype == T_STRING:
            return self.string()
        if ttype == T_STRUCT:
            out: dict[str, Any] = {}
            while True:
                ft = self.byte()
                if ft == T_STOP:
                    break
                fid = self.i16()
                out[str(fid)] = self.value(ft)
            return out
        if ttype == T_MAP:
            kt, vt = self.byte(), self.byte()
            n = self.i32()
            if n < 0 or n > 1 << 22:
                raise ThriftError(f"implausible map size {n}")
            return {self.value(kt): self.value(vt) for _ in range(n)}
        if ttype in (T_LIST, T_SET):
            et = self.byte()
            n = self.i32()
            if n < 0 or n > 1 << 22:
                raise ThriftError(f"implausible sequence size {n}")
            return [self.value(et) for _ in range(n)]
        raise ThriftError(f"cannot decode thrift type {ttype}")


class ThriftPipeClient:
    """One-shot Thrift CALL over a unix socket, generic reply decoding."""

    def __init__(self, socket_path: str | Path, service: str,
                 timeout: float = 3.0) -> None:
        self.socket_path = Path(socket_path)
        self.service = service
        self.timeout = timeout
        self._seq = 0

    def call(self, method: str, args: dict[int, tuple[int, Any]] | None = None,
             result_type: int = T_STRUCT) -> Any:
        """Invoke ``service.method`` and return the decoded ``success`` value.

        ``args`` maps field-id -> (thrift type, value); ``None`` sends an
        empty args struct.  ``result_type`` is the thrift type of field 0
        (success) in the ``*_result`` struct — T_STRUCT means "decode
        generically" (returns dict keyed by field id).
        """
        self._seq += 1
        w = _Writer()
        # version header has the high bit set — pack unsigned (same wire bytes)
        w.buf += struct.pack(">I", VERSION_1 | MSG_CALL)
        w.string(method)
        w.i32(self._seq)
        for fid, (ftype, value) in sorted((args or {}).items()):
            w.field_begin(ftype, fid)
            _write_value(w, ftype, value)
        w.field_stop()

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(str(self.socket_path))
        except OSError as exc:
            raise ThriftError(
                f"cannot connect to {self.socket_path.name}: {exc}") from exc
        try:
            sock.sendall(bytes(w.buf))
            return self._read_reply(sock, method, result_type)
        finally:
            sock.close()

    def _read_reply(self, sock: socket.socket, method: str,
                    result_type: int) -> Any:
        r = _Reader(sock)
        head = r.i32()
        if head < 0:
            if head & 0xFFFF0000 != VERSION_1:
                raise ThriftError(f"bad thrift version header {head:#x}")
            msg_type = head & 0xFF
            name = r.string()
            r.i32()  # seqid
        else:  # old (non-strict) message header
            if head > 1 << 21:
                raise ThriftError(f"implausible reply name length {head}")
            name = r._need(head).decode("utf-8", errors="replace")
            msg_type = r.byte()
            r.i32()
        if msg_type == MSG_EXCEPTION:
            exc = r.value(T_STRUCT)
            raise ThriftError(f"thrift exception calling {name or method}: {exc}")
        if msg_type != MSG_REPLY:
            raise ThriftError(f"unexpected message type {msg_type} for {method}")

        success: Any = None
        while True:
            ftype = r.byte()
            if ftype == T_STOP:
                break
            fid = r.i16()
            if fid == 0:
                success = r.value(result_type if result_type != T_STRUCT else T_STRUCT)
            else:
                r.value(ftype)  # drain errors/extra fields
        return success


def _write_value(w: _Writer, ftype: int, value: Any) -> None:
    if ftype == T_BOOL:
        w.byte(1 if value else 0)
    elif ftype == T_BYTE:
        w.byte(int(value))
    elif ftype == T_I16:
        w.i16(int(value))
    elif ftype == T_I32:
        w.i32(int(value))
    elif ftype == T_I64:
        w.i64(int(value))
    elif ftype == T_DOUBLE:
        w.double(float(value))
    elif ftype == T_STRING:
        w.string(str(value))
    else:
        raise ThriftError(f"cannot encode argument of type {ftype}")
