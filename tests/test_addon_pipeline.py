"""Cadena completa tal como correrá en HA: bus de eventos → SQLite → informe."""

import json

from fake_ws import FakeWsServer, read_frame, send_frame
from syslogwatch.addon_main import Options, ReportService
from syslogwatch.ha_source import run_stream
from syslogwatch.store import Store
from syslogwatch.ws import OP_TEXT

TOKEN = "token-del-supervisor"


def _send_json(conn, payload):
    send_frame(conn, OP_TEXT, json.dumps(payload).encode())


def _read_json(conn):
    _fin, _op, payload = read_frame(conn)
    return json.loads(payload)


def _ha_with(events):
    """Simula el syslog_receiver de HA emitiendo los mensajes reales de esta red."""

    def handler(server, conn):
        _send_json(conn, {"type": "auth_required", "ha_version": "2026.11.2"})
        assert _read_json(conn)["access_token"] == TOKEN
        _send_json(conn, {"type": "auth_ok"})
        request = _read_json(conn)
        assert request["event_type"] == "syslog_receiver_message"
        _send_json(conn, {"id": request["id"], "type": "result", "success": True, "result": None})
        for data in events:
            _send_json(conn, {"id": request["id"], "type": "event",
                              "event": {"event_type": "syslog_receiver_message",
                                        "data": data, "time_fired": "2026-11-24T15:20:00+01:00"}})

    return handler


EVENTS = [
    {"message": "Nov 24 15:16:47 user.info zcmdModuleCfg: zcmdTr181MtParmAttrQry: no request to retrieve mapping parameter",
     "source_ip": "192.168.1.1"},
    {"message": "Nov 24 15:10:49 kernel: [expireEntryBlockList 208]BLOCK LIST STA EXPIRES (0) :[72][8f][c1][2c][2c][5f]",
     "source_ip": "192.168.1.153"},
    {"message": "Nov 24 15:20:00 daemon.err dhcpd: DHCPDISCOVER from 3c:22:fb:11:22:33: no free leases",
     "source_ip": "192.168.1.1"},
    {"message": "Nov 24 15:21:00 kern.err kernel: nf_conntrack: table full, dropping packet",
     "source_ip": "192.168.1.1"},
    {"message": "Nov 24 15:22:00 daemon.warning hostapd: wlan0: STA aa:bb:cc:dd:ee:ff WPA: 4-Way Handshake failed",
     "source_ip": "192.168.1.153"},
]


def test_from_ha_event_bus_to_ranked_report(tmp_path):
    options = Options(data_dir=str(tmp_path), web=False, since_hours=24, top=10)
    store = Store(options.db_path)
    try:
        with FakeWsServer(_ha_with(EVENTS)) as server:
            # HA ofrece el WebSocket en /api/websocket; el add-on construye la URL desde la base
            base = server.url.replace("/api/websocket", "")
            run_stream(base, TOKEN, on_entry=lambda entry: store.add([entry]), max_events=len(EVENTS),
                       sleep=lambda seconds: None)

        assert store.count() == len(EVENTS)
        service = ReportService(store, options, logger=lambda message: None)
        report = service.build()

        titles = [finding.rule.title for finding in report.findings]
        assert "Pool DHCP agotado: clientes sin IP" in titles
        assert "Tabla de conexiones llena (paquetes descartados)" in titles
        # el ruido conocido no debe colarse arriba
        assert report.findings[0].score > 60
        assert "192.168.1.153" in report.devices

        html = service.refresh()
        assert "Pool DHCP agotado" in html and "Por qué falla" in html
        assert (tmp_path / "informe.md").exists()
    finally:
        store.close()


def test_health_and_panel_agree_after_ingesting(tmp_path):
    options = Options(data_dir=str(tmp_path), web=False)
    store = Store(options.db_path)
    try:
        with FakeWsServer(_ha_with(EVENTS[:2])) as server:
            base = server.url.replace("/api/websocket", "")
            run_stream(base, TOKEN, on_entry=lambda entry: store.add([entry]), max_events=2,
                       sleep=lambda seconds: None)
        service = ReportService(store, options, logger=lambda m: None)
        service.refresh()
        health = service.health()
        assert health["eventos"] == 2
        assert set(health["por_dispositivo"]) == {"192.168.1.1", "192.168.1.153"}
        assert "Syslogwatch" in service.read_html()
    finally:
        store.close()
