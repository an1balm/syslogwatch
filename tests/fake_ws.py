"""Servidor WebSocket de mentira para los tests: habla el protocolo de verdad."""

import base64
import hashlib
import socket
import struct
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _accept(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def read_frame(sock: socket.socket):
    """Lee una trama del cliente (van enmascaradas) y devuelve (fin, opcode, payload)."""
    header = _recv_exact(sock, 2)
    first, second = header[0], header[1]
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    key = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("el cliente cerró")
        data += chunk
    return data


def send_frame(sock: socket.socket, opcode: int, payload: bytes, fin: bool = True, mask: bool = False):
    first = (0x80 if fin else 0) | opcode
    mask_bit = 0x80 if mask else 0
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", first, mask_bit | length)
    elif length < 1 << 16:
        header = struct.pack("!BBH", first, mask_bit | 126, length)
    else:
        header = struct.pack("!BBQ", first, mask_bit | 127, length)
    if mask:
        key = b"\x01\x02\x03\x04"
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        sock.sendall(header + key + payload)
    else:
        sock.sendall(header + payload)


class FakeWsServer:
    """Acepta ``connections`` clientes y ejecuta ``handler(server, conn)`` en cada uno."""

    def __init__(self, handler, connections: int = 1, status_line: str = "HTTP/1.1 101 Switching Protocols"):
        self.handler = handler
        self.connections = connections
        self.status_line = status_line
        self.received = []          # (opcode, payload) de cada cliente
        self.handshakes = 0
        self.errors = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self._threads = []
        self._stopped = False

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}/api/websocket"

    def start(self):
        self._acceptor = threading.Thread(target=self._accept_loop, daemon=True)
        self._acceptor.start()
        return self

    def _accept_loop(self):
        accepted = 0
        while accepted < self.connections and not self._stopped:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                return
            except OSError:
                return
            accepted += 1
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _serve(self, conn: socket.socket):
        try:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk
            key = ""
            for line in request.decode("latin-1").splitlines():
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            self.handshakes += 1
            response = (
                f"{self.status_line}\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {_accept(key)}\r\n\r\n"
            )
            conn.sendall(response.encode("latin-1"))
            self.handler(self, conn)
        except Exception as error:  # noqa: BLE001 - el test decide qué mirar
            self.errors.append(error)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def next_client_frame(self, conn: socket.socket, timeout: float = 3.0):
        conn.settimeout(timeout)
        return read_frame(conn)

    def stop(self):
        self._stopped = True
        try:
            self.sock.close()
        except OSError:
            pass
        for thread in self._threads:
            thread.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
