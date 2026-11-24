import json
import threading

import pytest

from fake_ws import FakeWsServer, read_frame, send_frame
from syslogwatch.ha_source import (
    AuthError,
    HaError,
    HomeAssistantStream,
    SubscriptionError,
    derive_ws_url,
    event_to_entry,
    event_to_ha_event,
    run_stream,
)
from syslogwatch.parse import parse_line
from syslogwatch.store import Store
from syslogwatch.ws import OP_CLOSE, OP_TEXT

TOKEN = "token-de-prueba"


def _send_json(conn, payload):
    send_frame(conn, OP_TEXT, json.dumps(payload).encode())


def _read_json(conn):
    _fin, _op, payload = read_frame(conn)
    return json.loads(payload)


def ha_server(
    events=(),
    auth_ok=True,
    subscribe_ok=True,
    event_type="syslog_receiver_message",
    close_after=None,
    seen=None,
):
    """Handler que replica la conversación real de HA por WebSocket."""

    def handler(server, conn):
        _send_json(conn, {"type": "auth_required", "ha_version": "2026.11.2"})
        auth = _read_json(conn)
        if seen is not None:
            seen.append(auth)
        if not auth_ok:
            _send_json(conn, {"type": "auth_invalid", "message": "Invalid access token"})
            return
        assert auth["type"] == "auth"
        _send_json(conn, {"type": "auth_ok", "ha_version": "2026.11.2"})

        request = _read_json(conn)
        if seen is not None:
            seen.append(request)
        assert request["type"] == "subscribe_events"
        assert request["event_type"] == event_type
        if not subscribe_ok:
            _send_json(conn, {"id": request["id"], "type": "result", "success": False,
                              "error": {"code": "unknown_event", "message": "no such event"}})
            return
        _send_json(conn, {"id": request["id"], "type": "result", "success": True, "result": None})

        for index, data in enumerate(events):
            if close_after is not None and index == close_after:
                send_frame(conn, OP_CLOSE, b"\x03\xe8")
                return
            _send_json(
                conn,
                {
                    "id": request["id"],
                    "type": "event",
                    "event": {
                        "event_type": event_type,
                        "data": data,
                        "time_fired": "2026-11-24T15:16:47+01:00",
                    },
                },
            )

    return handler


# -- url y mapeo ---------------------------------------------------------

def test_ws_url_is_derived_from_the_core_url():
    assert derive_ws_url("http://supervisor/core") == "ws://supervisor/core/api/websocket"
    assert derive_ws_url("http://192.168.1.219:8123/") == "ws://192.168.1.219:8123/api/websocket"
    assert derive_ws_url("ws://ha.local:8123") == "ws://ha.local:8123/api/websocket"


def test_https_is_rejected_with_a_clear_message():
    with pytest.raises(Exception) as error:
        derive_ws_url("https://ha.example.com")
    assert "esquema" in str(error.value)


def test_event_mapping_keeps_source_ip_and_message():
    event = {"data": {"message": "Nov 24 15:20:00 daemon.err dhcpd: no free leases",
                      "source_ip": "192.168.1.1", "severity": None},
             "time_fired": "2026-11-24T15:20:00+01:00"}
    ha_event = event_to_ha_event(event)
    assert ha_event.message.startswith("Nov 24")
    assert ha_event.source_ip == "192.168.1.1"
    assert ha_event.severity is None
    entry = event_to_entry(event)
    assert entry.severity == 3  # del texto, porque el receptor no manda severidad
    assert entry.app == "dhcpd"


def test_event_without_message_is_ignored():
    assert event_to_ha_event({"data": {"source_ip": "192.168.1.1"}}) is None
    assert event_to_entry({"data": {}}) is None


def test_explicit_severity_from_the_event_overrides_the_text():
    event = {"data": {"message": "Nov 24 15:20:00 algo sin nivel", "source_ip": "192.168.1.1", "severity": 2}}
    assert event_to_entry(event).severity == 2


def test_severity_values_out_of_range_are_ignored():
    event = {"data": {"message": "Nov 24 15:20:00 algo", "source_ip": "192.168.1.1", "severity": 9}}
    assert event_to_entry(event).severity == 5


# -- protocolo -----------------------------------------------------------

def test_stream_authenticates_subscribes_and_yields_events():
    events = [
        {"message": "Nov 24 15:16:47 user.info zcmdModuleCfg: beRaInfoIntfSetStatsUpdate()", "source_ip": "192.168.1.1"},
        {"message": "Nov 24 15:20:00 daemon.err dhcpd: no free leases", "source_ip": "192.168.1.1"},
    ]
    seen = []
    with FakeWsServer(ha_server(events, seen=seen)) as server:
        with HomeAssistantStream(server.url.replace("/api/websocket", ""), TOKEN) as stream:
            received = [event for event in stream.events(max_events=2)]
    assert len(received) == 2
    assert seen[0] == {"type": "auth", "access_token": TOKEN}
    assert seen[1]["event_type"] == "syslog_receiver_message"


def test_a_wrong_token_raises_auth_error():
    with FakeWsServer(ha_server(auth_ok=False)) as server:
        with pytest.raises(AuthError):
            HomeAssistantStream(server.url.replace("/api/websocket", ""), "malo").open()


def test_rejected_subscription_raises_subscription_error():
    with FakeWsServer(ha_server(subscribe_ok=False)) as server:
        with pytest.raises(SubscriptionError):
            HomeAssistantStream(server.url.replace("/api/websocket", ""), TOKEN).open()


def test_unexpected_first_message_is_an_ha_error():
    def handler(server, conn):
        _send_json(conn, {"type": "cosa_rara"})

    with FakeWsServer(handler) as server:
        with pytest.raises(HaError):
            HomeAssistantStream(server.url.replace("/api/websocket", ""), TOKEN).open()


# -- bucle con reconexión ------------------------------------------------

def test_run_stream_reconnects_and_keeps_storing(tmp_path):
    events = [{"message": "Nov 24 15:20:00 daemon.err dhcpd: no free leases", "source_ip": "192.168.1.1"}]
    inner = ha_server(events)
    stop = threading.Event()

    def handler(server, conn):
        if server.handshakes == 1:
            _send_json(conn, {"type": "auth_required"})
            _read_json(conn)
            _send_json(conn, {"type": "auth_ok"})
            send_frame(conn, OP_CLOSE, b"\x03\xe8")  # HA se cae antes de suscribir
            return
        inner(server, conn)

    store = Store(tmp_path / "t.db")
    with FakeWsServer(handler, connections=2) as server:
        reconnects = run_stream(
            server.url.replace("/api/websocket", ""),
            TOKEN,
            on_entry=lambda entry: (store.add([entry]), stop.set()),
            stop=stop,
            sleep=lambda seconds: None,
        )
    total = store.count()
    store.close()
    assert reconnects == 1
    assert total == 1


def test_run_stream_stops_when_the_stop_event_is_set(tmp_path):
    stop = threading.Event()
    stop.set()

    def fail(*args, **kwargs):  # no debe ni intentarse
        raise AssertionError("no debería conectar")

    assert run_stream("http://127.0.0.1:1", TOKEN, on_entry=lambda e: None, stop=stop,
                      stream_factory=fail) == 0


def test_run_stream_reports_auth_failure_and_gives_up():
    with FakeWsServer(ha_server(auth_ok=False)) as server:
        with pytest.raises(AuthError):
            run_stream(server.url.replace("/api/websocket", ""), "malo", on_entry=lambda e: None,
                       sleep=lambda seconds: None)


def test_entries_reach_the_store_from_the_event_bus(tmp_path):
    events = [
        {"message": "Nov 24 15:20:00 daemon.err dhcpd: DHCPDISCOVER from aa: no free leases", "source_ip": "192.168.1.1"},
        {"message": "Nov 24 15:21:00 kern.err kernel: nf_conntrack: table full, dropping packet", "source_ip": "192.168.1.1"},
    ]
    store = Store(tmp_path / "e.db")
    with FakeWsServer(ha_server(events)) as server:
        run_stream(server.url.replace("/api/websocket", ""), TOKEN,
                   on_entry=lambda entry: store.add([entry]), max_events=2, sleep=lambda s: None)
    assert store.count() == 2
    store.close()
