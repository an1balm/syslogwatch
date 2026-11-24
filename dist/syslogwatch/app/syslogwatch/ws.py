"""Cliente WebSocket mínimo (RFC 6455) sobre la biblioteca estándar.

Sólo lo que hace falta para hablar con Home Assistant: handshake, tramas de texto
con fragmentación, ping/pong y cierre. Nada de extensiones ni compresión.

Se implementa a mano porque el add-on tiene que arrancar sin instalar paquetes
(el SDK de Python de HA no trae cliente WebSocket) y porque así los tests pueden
ejercitar el protocolo sin red.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

_DATA_OPS = (OP_CONTINUATION, OP_TEXT, OP_BINARY)
_CONTROL_OPS = (OP_CLOSE, OP_PING, OP_PONG)


class WebSocketError(Exception):
    """Fallo genérico del canal."""


class HandshakeError(WebSocketError):
    """El servidor no aceptó la conexión como WebSocket."""


class ProtocolError(WebSocketError):
    """Trama inválida: opcode desconocido, longitudes imposibles, fragmentación rota."""


def accept_key(key: str) -> str:
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _encode_frame(opcode: int, payload: bytes, fin: bool = True, mask: bool = True) -> bytes:
    first = (0x80 if fin else 0x00) | opcode
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00
    if length < 126:
        header = struct.pack("!BB", first, mask_bit | length)
    elif length < (1 << 16):
        header = struct.pack("!BBH", first, mask_bit | 126, length)
    else:
        header = struct.pack("!BBQ", first, mask_bit | 127, length)
    if not mask:
        return header + payload
    key = os.urandom(4)
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return header + key + masked


class WebSocket:
    """Conexión WebSocket ya establecida (cliente)."""

    def __init__(self, sock: socket.socket, pending: bytes = b""):
        self.sock = sock
        self._buffer = pending
        self._closed = False

    # -- construcción ----------------------------------------------------
    @classmethod
    def connect(
        cls,
        url: str,
        timeout: float = 10.0,
        extra_headers: Optional[dict] = None,
    ) -> "WebSocket":
        target = parse_ws_url(url)
        sock = socket.create_connection((target.host, target.port), timeout=timeout)
        key = send_handshake(sock, target, extra_headers)
        response, pending = _read_handshake(sock)
        validate_handshake(sock, response, key)
        return cls(sock, pending)

    # -- envío -----------------------------------------------------------
    def send_text(self, text: str) -> None:
        self._send(OP_TEXT, text.encode("utf-8"))

    def send_ping(self, payload: bytes = b"") -> None:
        self._send(OP_PING, payload)

    def _send(self, opcode: int, payload: bytes) -> None:
        if self._closed:
            raise WebSocketError("el canal está cerrado")
        self.sock.sendall(_encode_frame(opcode, payload))

    # -- recepción -------------------------------------------------------
    def _read_exact(self, count: int) -> bytes:
        while len(self._buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WebSocketError("conexión cerrada por el servidor")
            self._buffer += chunk
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    def _read_frame(self) -> Tuple[bool, int, bytes]:
        header = self._read_exact(2)
        first, second = header[0], header[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        if length > 8 * 1024 * 1024:
            raise ProtocolError(f"trama demasiado grande: {length} bytes")
        mask_key = self._read_exact(4) if masked else b""
        payload = self._read_exact(length) if length else b""
        if masked:
            payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        return fin, opcode, payload

    def _control(self, fin: bool, opcode: int, payload: bytes) -> Optional[bytes]:
        """Gestiona ping/pong/close. Devuelve la carga del close o ``None``."""
        if not fin or len(payload) > 125:
            raise ProtocolError("trama de control inválida")
        if opcode == OP_PING:
            self._send(OP_PONG, payload)
            return None
        if opcode == OP_PONG:
            return None
        self._closed = True
        code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
        return struct.pack("!H", code)

    def recv(self) -> Tuple[str, bytes]:
        """Devuelve (tipo, datos). Reensambla fragmentos y contesta a los ping."""
        assembler = _Assembler()
        while True:
            fin, opcode, payload = self._read_frame()
            if opcode in _CONTROL_OPS:
                close_payload = self._control(fin, opcode, payload)
                if close_payload is not None:
                    return "close", close_payload
                continue
            if opcode not in _DATA_OPS:
                raise ProtocolError(f"opcode desconocido: {opcode}")
            kind, data = assembler.feed(fin, opcode, payload)
            if kind is not None:
                return kind, data

    def close(self, code: int = 1000, reason: str = "") -> None:
        if not self._closed:
            try:
                self._send(OP_CLOSE, struct.pack("!H", code) + reason.encode("utf-8"))
            except OSError:
                pass
            self._closed = True
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc) -> None:
        self.close()



class Target:
    """Destino ya resuelto de la conexión."""

    def __init__(self, host: str, port: int, path: str):
        self.host = host
        self.port = port
        self.path = path


class _Assembler:
    """Junta fragmentos y detecta secuencias inválidas."""

    def __init__(self):
        self.opcode: Optional[int] = None
        self.parts: List[bytes] = []

    def feed(self, fin: bool, opcode: int, payload: bytes) -> Tuple[Optional[str], bytes]:
        if opcode == OP_CONTINUATION:
            if self.opcode is None:
                raise ProtocolError("continuación sin trama inicial")
        else:
            if self.opcode is not None:
                raise ProtocolError("nueva trama de datos dentro de una fragmentada")
            self.opcode = opcode
        self.parts.append(payload)
        if not fin:
            return None, b""
        kind = "text" if self.opcode == OP_TEXT else "binary"
        data = b"".join(self.parts)
        self.opcode, self.parts = None, []
        return kind, data


def parse_ws_url(url: str) -> Target:
    parts = urlsplit(url)
    if parts.scheme not in ("ws", "http"):
        raise HandshakeError(f"esquema no soportado: {parts.scheme}")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(parts.hostname or "127.0.0.1", parts.port or 80, path)


def send_handshake(sock: socket.socket, target: Target, extra_headers: Optional[dict] = None) -> str:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {target.path} HTTP/1.1",
        f"Host: {target.host}:{target.port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    for name, value in (extra_headers or {}).items():
        lines.append(f"{name}: {value}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
    return key


def validate_handshake(sock: socket.socket, response: str, key: str) -> None:
    status = _status_code(response)
    if status != 101:
        sock.close()
        raise HandshakeError(f"respuesta inesperada (HTTP {status or '??'})")
    if accept_key(key).lower() not in response.lower():
        sock.close()
        raise HandshakeError("Sec-WebSocket-Accept no coincide")


def _status_code(response: str) -> int:
    parts = (response.split("\r\n", 1)[0] or "").split()
    if len(parts) > 1 and parts[1].isdigit():
        return int(parts[1])
    return 0


def _read_handshake(sock: socket.socket) -> Tuple[str, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            raise HandshakeError("cabecera de respuesta demasiado grande")
    head, _, pending = data.partition(b"\r\n\r\n")
    return head.decode("latin-1"), pending
