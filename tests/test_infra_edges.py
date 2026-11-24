"""Bordes de almacén, fuentes, CLI e informe."""

import socket
import time
from datetime import datetime, timedelta

import pytest

from syslogwatch.cli import main, parse_duration
from syslogwatch.parse import parse_line
from syslogwatch.report import Report, band, render_html, render_markdown, to_json
from syslogwatch.rank import aggregate
from syslogwatch.sources import FileSource, UdpSource
from syslogwatch.store import Store


# -- store --------------------------------------------------------------

def test_in_memory_store_never_touches_the_disk():
    store = Store(":memory:")
    assert store.path == ":memory:"
    assert store.count() == 0
    store.add([parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")])
    assert store.count() == 1
    store.close()


def test_add_with_no_entries_returns_zero(tmp_path):
    store = Store(tmp_path / "t.db")
    assert store.add([]) == 0


def test_since_datetime_filters_exactly(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add([parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")])
    future = datetime.now() + timedelta(hours=1)
    assert store.entries(since=future) == []
    past = datetime.now() - timedelta(hours=1)
    assert len(store.entries(since=past)) == 1


def test_stats_counts_each_severity_name(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add(
        [
            parse_line("Nov 24 15:20:00 kern.err kernel: Out of memory: Killed process 9", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:01 kern.crit kernel: hardware error PCIe bus error", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:02 user.info zcmdModuleCfg: beRaInfo", source_ip="192.168.1.1"),
        ]
    )
    stats = store.stats()
    assert stats["by_severity"] == {"err": 1, "crit": 1, "info": 1}
    assert stats["total"] == 3


def test_store_is_usable_as_a_context_manager(tmp_path):
    with Store(tmp_path / "t.db") as store:
        store.add([parse_line("texto", source_ip="192.168.1.1")])
    with pytest.raises(Exception):
        store.count()


# -- sources ------------------------------------------------------------

def test_udp_source_context_manager_starts_and_stops():
    with UdpSource(port=0, bind="127.0.0.1") as source:
        assert source.port > 0
    source.stop()  # idempotente


def test_invalid_utf8_payload_does_not_kill_the_listener():
    received = []
    source = UdpSource(port=0, bind="127.0.0.1", on_entry=received.append)
    source.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"Nov 24 15:20:00 kernel: \xff\xfe basura", ("127.0.0.1", source.port))
        deadline = time.time() + 3
        while not received and time.time() < deadline:
            time.sleep(0.02)
    finally:
        source.stop()
    assert received and "basura" in received[0].message


def test_a_failing_consumer_is_counted_and_does_not_stop_the_listener():
    def broken(entry):
        raise RuntimeError("consumidor roto")

    source = UdpSource(port=0, bind="127.0.0.1", on_entry=broken)
    source.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"Nov 24 15:20:00 daemon.err dhcpd: no free leases", ("127.0.0.1", source.port))
        deadline = time.time() + 3
        while source.dropped == 0 and time.time() < deadline:
            time.sleep(0.02)
    finally:
        source.stop()
    assert source.dropped == 1
    assert source.received == 1


def test_file_source_propagates_a_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        FileSource(tmp_path / "no-existe.log").entries()


# -- cli ----------------------------------------------------------------

def test_durations_are_parsed_and_bad_ones_rejected():
    assert parse_duration("30m") == timedelta(minutes=30)
    assert parse_duration("7d") == timedelta(days=7)
    with pytest.raises(Exception):
        parse_duration("dos horas")


def test_analyze_on_an_empty_database_explains_instead_of_printing_nothing(tmp_path, capsys):
    assert main(["analyze", "--db", str(tmp_path / "vacio.db"), "--no-web"]) == 1
    assert "No hay eventos" in capsys.readouterr().err


def test_stats_on_an_empty_database(tmp_path, capsys):
    assert main(["stats", "--db", str(tmp_path / "vacio.db")]) == 0
    assert "Sin eventos" in capsys.readouterr().out


def test_ingest_reports_a_missing_file(tmp_path, capsys):
    assert main(["ingest", "--file", str(tmp_path / "nada.log"), "--db", str(tmp_path / "t.db")]) == 1
    assert "no encontrado" in capsys.readouterr().err.lower()


def test_bad_since_argument_exits_with_usage(tmp_path):
    with pytest.raises(SystemExit):
        main(["analyze", "--since", "ayer", "--db", str(tmp_path / "t.db")])


def test_echo_mode_prints_each_message(tmp_path, capsys):
    from syslogwatch.cli import _make_sink

    store = Store(tmp_path / "e.db")
    on_entry, flush = _make_sink(store, echo=True)
    on_entry(parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"))
    flush()
    assert "no free leases" in capsys.readouterr().out
    assert store.count() == 1
    store.close()


def test_batch_flush_triggers_every_25_messages(tmp_path):
    from syslogwatch.cli import _make_sink

    store = Store(tmp_path / "b.db")
    on_entry, flush = _make_sink(store, echo=False)
    for i in range(25):
        on_entry(parse_line("Nov 24 15:20:%02d daemon.err dhcpd: no free leases %d" % (i, i), source_ip="192.168.1.1"))
    assert store.count() == 25  # escrito sin esperar al flush final
    flush()
    store.close()


# -- informe ------------------------------------------------------------

def test_band_thresholds():
    assert band(100) == "CRÍTICO"
    assert band(80) == "CRÍTICO"
    assert band(79) == "ALTO"
    assert band(60) == "ALTO"
    assert band(40) == "MEDIO"
    assert band(20) == "BAJO"
    assert band(19) == "RUIDO"
    assert band(0) == "RUIDO"


def test_report_without_findings_says_so_in_every_format():
    report = Report(findings=[], total_events=0, window="últimas 24 h")
    assert "Sin mensajes" in render_markdown(report)
    assert "Sin mensajes" in render_html(report)
    assert to_json(report).count("findings") == 1


def test_report_collects_devices_from_findings_when_not_given():
    findings = aggregate(
        [
            parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.153"),
        ]
    )
    report = Report(findings=findings, total_events=2)
    assert report.devices == ["192.168.1.1", "192.168.1.153"]


def test_json_marks_the_degraded_state():
    import json

    report = Report(findings=[], total_events=0, degraded=True)
    assert json.loads(to_json(report))["degraded"] is True


def test_store_creates_nested_directories(tmp_path):
    nested = tmp_path / "a" / "b" / "eventos.db"
    store = Store(nested)
    store.add([parse_line("texto", source_ip="192.168.1.1")])
    assert nested.exists()
    store.close()


def test_since_a_negative_window_returns_nothing(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add([parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")])
    assert store.entries(since=timedelta(hours=-1)) == []
    store.close()


def test_markdown_numbers_findings_from_one_and_uses_a_dash_without_devices():
    finding = aggregate([parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")])[0]
    finding.devices = []
    md = render_markdown(Report(findings=[finding], total_events=1, devices=[]))
    assert "### 1. Pool DHCP agotado" in md
    assert "| — |" in md  # sin dispositivos, guion largo en la tabla


def test_second_add_reports_only_the_new_rows(tmp_path):
    store = Store(tmp_path / "t.db")
    first = [parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")]
    store.add(first)
    again = store.add([parse_line("Nov 24 15:20:01 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")])
    assert again == 1  # no cuenta lo ya insertado
    store.close()


def test_tables_number_from_one_and_escape_quotes():
    finding = aggregate([parse_line('Nov 24 15:20:00 daemon.err app: valor "raro" & <b>', source_ip="192.168.1.1")])[0]
    report = Report(findings=[finding], total_events=1)
    md = render_markdown(report)
    html = render_html(report)
    assert "| 1 | **" in md
    assert '<td class="num">1</td>' in html
    assert "&quot;raro&quot;" in html


def test_missing_devices_render_as_a_dash_in_html():
    finding = aggregate([parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")])[0]
    finding.devices = []
    assert "—" in render_html(Report(findings=[finding], total_events=1, devices=[]))


def test_json_keeps_non_ascii_readable():
    finding = aggregate([parse_line("Nov 24 15:20:00 kern.crit kernel: Out of memory: Killed process 9", source_ip="192.168.1.1")])[0]
    assert '"band": "CRÍTICO"' in to_json(Report(findings=[finding], total_events=1))
