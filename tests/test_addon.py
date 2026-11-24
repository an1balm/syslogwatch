import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta

import pytest

from syslogwatch.addon_main import (
    Options,
    OptionsError,
    ReportService,
    build_server,
    load_options,
    parse_iso,
    parse_options,
    severity_allowed,
)
from syslogwatch.parse import parse_line
from syslogwatch.store import Store


def _entry(text, ip="192.168.1.1"):
    return parse_line(text, source_ip=ip)


def _service(tmp_path, **overrides):
    options = Options(data_dir=str(tmp_path), web=False, **overrides)
    store = Store(options.db_path)
    return ReportService(store, options, logger=lambda message: None), store, options


# -- opciones ------------------------------------------------------------

def test_defaults_are_sensible():
    options = parse_options({})
    assert options.since_hours == 24
    assert options.top == 15
    assert options.web is True
    assert options.event_type == "syslog_receiver_message"
    assert options.ingress_port == 8099


def test_overrides_and_string_booleans_are_accepted():
    options = parse_options({"since_hours": "48", "web": "false", "top": 5})
    assert options.since_hours == 48
    assert options.web is False
    assert options.top == 5


def test_out_of_range_values_explain_themselves():
    with pytest.raises(OptionsError) as error:
        parse_options({"since_hours": 0})
    assert "since_hours" in str(error.value)
    with pytest.raises(OptionsError):
        parse_options({"web": "quizá"})
    with pytest.raises(OptionsError):
        parse_options({"top": "muchos"})


def test_unknown_keys_are_ignored(tmp_path):
    path = tmp_path / "options.json"
    path.write_text(json.dumps({"since_hours": 12, "campo_futuro": 1}), encoding="utf-8")
    assert load_options(path).since_hours == 12


def test_missing_options_file_falls_back_to_defaults(tmp_path):
    assert load_options(tmp_path / "no-existe.json") == Options()


def test_broken_options_file_raises_options_error(tmp_path):
    path = tmp_path / "options.json"
    path.write_text("{roto", encoding="utf-8")
    with pytest.raises(OptionsError):
        load_options(path)


def test_paths_live_under_the_data_directory(tmp_path):
    options = Options(data_dir=str(tmp_path))
    assert options.db_path == tmp_path / "eventos.db"
    assert options.report_path == tmp_path / "informe.html"


def test_iso_dates_are_parsed_or_ignored():
    assert parse_iso("2026-11-24T15:20:00+01:00").hour == 15
    assert parse_iso(None) is None
    assert parse_iso("ayer") is None


def test_severity_filter_keeps_what_is_severe_enough():
    err = _entry("Nov 24 15:20:00 kern.err kernel: nf_conntrack: table full")
    info = _entry("Nov 24 15:20:01 user.info zcmdModuleCfg: beRaInfo")
    assert severity_allowed(err, 3)
    assert not severity_allowed(info, 3)


# -- servicio de informes ------------------------------------------------

def test_refresh_writes_html_and_markdown(tmp_path):
    service, store, options = _service(tmp_path)
    store.add([_entry("Nov 24 15:20:00 daemon.err dhcpd: no free leases")])
    html = service.refresh()
    assert "Pool DHCP agotado" in html
    assert options.report_path.exists()
    assert (tmp_path / "informe.md").read_text(encoding="utf-8").startswith("# Syslogwatch")
    store.close()


def test_health_reports_counts_and_timestamps(tmp_path):
    service, store, _ = _service(tmp_path)
    store.add([_entry("Nov 24 15:20:00 daemon.err dhcpd: no free leases")])
    service.refresh()
    health = service.health()
    assert health["ok"] is True
    assert health["eventos"] == 1
    assert health["por_dispositivo"] == {"192.168.1.1": 1}
    assert health["ultimo_mensaje"] and health["informe_generado"]
    store.close()


def test_window_limits_what_the_report_looks_at(tmp_path):
    service, store, _ = _service(tmp_path, since_hours=1)
    old = datetime.now() - timedelta(days=3)
    # sin fecha en la línea: el almacén usa el momento de recepción, que aquí es antiguo
    store.add([_entry("no free leases en el pool desde ayer")], received_at=old)
    store.add([_entry("Nov 24 15:22:00 kern.err kernel: nf_conntrack: table full")])
    report = service.build()
    assert report.window == "últimas 1 h"
    assert report.total_events == 1
    assert all(f.rule.id != "dhcp-pool-exhausted" for f in report.findings)
    store.close()


def test_a_failing_refresh_records_the_error_without_crashing(tmp_path, monkeypatch):
    service, store, _ = _service(tmp_path)

    def broken(*args, **kwargs):
        raise OSError("disco lleno")

    monkeypatch.setattr("pathlib.Path.write_text", broken)
    with pytest.raises(OSError):
        service.refresh()
    assert "disco lleno" in service.last_error
    assert service.health()["ok"] is False
    store.close()


def test_read_html_before_the_first_report_is_a_placeholder(tmp_path):
    service, store, _ = _service(tmp_path)
    assert "Generando el primer informe" in service.read_html()
    store.close()


def test_periodic_refresh_can_be_stopped(tmp_path):
    import threading

    service, store, _ = _service(tmp_path, refresh_minutes=1)
    stop = threading.Event()
    stop.set()
    started = time.time()
    service.run_periodic(stop)
    assert time.time() - started < 1
    store.close()


# -- servidor de Ingress -------------------------------------------------

def _get(server, path):
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, response.read().decode("utf-8")


def test_root_serves_the_report(tmp_path):
    service, store, _ = _service(tmp_path)
    store.add([_entry("Nov 24 15:20:00 daemon.err dhcpd: no free leases")])
    service.refresh()
    server = build_server(service, port=0, bind="127.0.0.1")
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        status, body = _get(server, "/")
        assert status == 200
        assert "Syslogwatch" in body
        status, body = _get(server, "/healthz")
        assert status == 200 and json.loads(body)["eventos"] == 1
        with pytest.raises(urllib.error.HTTPError) as error:
            _get(server, "/no-existe")
        assert error.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_regenerar_rebuilds_and_redirects(tmp_path):
    service, store, _ = _service(tmp_path)
    server = build_server(service, port=0, bind="127.0.0.1")
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/regenerar", method="GET"
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200  # urllib sigue la redirección
            assert "Syslogwatch" in response.read().decode("utf-8")
        assert service.last_built is not None
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_head_request_is_not_implemented_and_returns_an_error_status(tmp_path):
    service, store, _ = _service(tmp_path)
    server = build_server(service, port=0, bind="127.0.0.1")
    import threading

    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_address[1]}/", method="HEAD"
            )
            urllib.request.urlopen(request, timeout=5).read()
        assert error.value.code == 501
    finally:
        server.shutdown()
        server.server_close()
        store.close()


def test_periodic_loop_refreshes_then_stops(tmp_path):
    import threading

    service, store, _ = _service(tmp_path, refresh_minutes=1)
    calls = []
    ticks = {"n": 0}

    class FakeStop(threading.Event):
        def wait(self, timeout=None):
            ticks["n"] += 1
            if ticks["n"] > 1:  # el segundo tick pide parar
                self.set()
            return self.is_set()

    original = service.refresh
    service.refresh = lambda: calls.append(1) or original()
    service.run_periodic(FakeStop())
    assert calls == [1]
    store.close()


def test_start_ingest_without_a_token_does_not_launch_anything(tmp_path):
    from syslogwatch.addon_main import start_ingest

    service, store, options = _service(tmp_path)
    messages = []
    assert start_ingest(store, options, threading.Event(), messages.append, token="") is None
    assert "SUPERVISOR_TOKEN" in messages[0]
    store.close()


def test_start_ingest_launches_the_stream_thread(tmp_path):
    from syslogwatch.addon_main import start_ingest

    service, store, options = _service(tmp_path, min_severity=3)
    started = {}

    class FakeThread:
        def __init__(self, target=None, args=(), kwargs=None, name=None, daemon=None):
            started.update(target=target, args=args, kwargs=kwargs or {}, name=name)

        def start(self):
            started["started"] = True

    thread = start_ingest(store, options, threading.Event(), lambda m: None, token="abc",
                          thread_factory=FakeThread)
    assert started["started"] is True
    assert started["kwargs"]["event_type"] == "syslog_receiver_message"
    assert thread is not None

    # el filtro de severidad se aplica antes de escribir
    on_entry = started["kwargs"]["on_entry"]
    on_entry(_entry("Nov 24 15:20:00 user.info zcmdModuleCfg: beRaInfo"))
    on_entry(_entry("Nov 24 15:20:01 kern.err kernel: nf_conntrack: table full"))
    assert store.count() == 1
    store.close()
