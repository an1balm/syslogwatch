import time

import pytest

from fake_ws import FakeWsServer, read_frame, send_frame
from syslogwatch.ws import (
    OP_BINARY,
    OP_CLOSE,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    HandshakeError,
    ProtocolError,
    WebSocket,
    accept_key,
)


def test_accept_key_matches_the_rfc_example():
    assert accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_connect_completes_the_handshake_and_sends_text():
    def handler(server, conn):
        server.received.append(server.next_client_frame(conn))

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            ws.send_text("hola")
    _fin, opcode, payload = server.received[0]
    assert opcode == OP_TEXT
    assert payload == b"hola"


def test_client_frames_are_masked():
    captured = {}

    def handler(server, conn):
        raw = conn.recv(2)  # cabecera: el bit de máscara debe estar puesto
        captured["second"] = raw[1]

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            ws.send_text("x")
        time.sleep(0.2)
    assert captured["second"] & 0x80


def test_recv_returns_text_and_reassembles_fragments():
    def handler(server, conn):
        send_frame(conn, OP_TEXT, b"parte1 ", fin=False)
        send_frame(conn, 0x0, b"parte2 ", fin=False)
        send_frame(conn, 0x0, b"parte3", fin=True)

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            kind, payload = ws.recv()
    assert kind == "text"
    assert payload == b"parte1 parte2 parte3"


def test_ping_is_answered_with_pong_and_does_not_break_the_stream():
    def handler(server, conn):
        send_frame(conn, OP_PING, b"latiendo")
        _fin, opcode, payload = read_frame(conn)  # el pong del cliente
        server.received.append((_fin, opcode, payload))
        send_frame(conn, OP_TEXT, b"despues del ping")

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            kind, payload = ws.recv()
    assert (kind, payload) == ("text", b"despues del ping")
    assert server.received[0][1:] == (OP_PONG, b"latiendo")


def test_close_frame_is_reported_with_its_code():
    def handler(server, conn):
        send_frame(conn, OP_CLOSE, b"\x03\xe8")  # 1000

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            kind, payload = ws.recv()
    assert kind == "close"
    assert payload == b"\x03\xe8"


def test_binary_frames_are_distinguished():
    def handler(server, conn):
        send_frame(conn, OP_BINARY, b"\x00\x01")

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            assert ws.recv() == ("binary", b"\x00\x01")


@pytest.mark.parametrize("size", [125, 126, 70000])
def test_payload_lengths_across_the_three_encodings(size):
    payload = b"a" * size

    def handler(server, conn):
        send_frame(conn, OP_TEXT, payload)

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            assert ws.recv() == ("text", payload)


def test_a_non_101_response_raises_handshake_error():
    with FakeWsServer(lambda server, conn: None, status_line="HTTP/1.1 404 Not Found") as server:
        with pytest.raises(HandshakeError):
            WebSocket.connect(server.url)


def test_a_wrong_accept_header_raises_handshake_error():
    def handler(server, conn):
        pass

    original = FakeWsServer._serve

    class Liar(FakeWsServer):
        def _serve(self, conn):
            request = conn.recv(4096)
            key = ""
            for line in request.decode("latin-1").splitlines():
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            conn.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: bWFsYQ==\r\n\r\n"
                ).encode("latin-1")
            )

    with Liar(handler) as server:
        with pytest.raises(HandshakeError):
            WebSocket.connect(server.url)


def test_continuation_without_a_start_is_a_protocol_error():
    def handler(server, conn):
        send_frame(conn, 0x0, b"huerfano", fin=True)

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            with pytest.raises(ProtocolError):
                ws.recv()


def test_unknown_opcode_is_a_protocol_error():
    def handler(server, conn):
        send_frame(conn, 0x3, b"raro")

    with FakeWsServer(handler) as server:
        with WebSocket.connect(server.url) as ws:
            with pytest.raises(ProtocolError):
                ws.recv()


def test_sending_after_close_raises():
    def handler(server, conn):
        time.sleep(0.2)

    with FakeWsServer(handler) as server:
        ws = WebSocket.connect(server.url)
        ws.close()
        with pytest.raises(Exception):
            ws.send_text("tarde")
