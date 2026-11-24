import json

from syslogwatch.cli import main


LOG = """Nov 24 15:10:49 kernel: [expireEntryBlockList 208]BLOCK LIST STA EXPIRES (0) :[72][8f][c1][2c][2c][5f]
Nov 24 15:16:47 user.info zcmdModuleCfg: zcmdTr181MtParmAttrQry: no request to retrieve mapping parameter
Nov 24 15:20:00 daemon.err dhcpd: DHCPDISCOVER from 00:11:22:33:44:55: no free leases
Nov 24 15:20:30 daemon.err dhcpd: DHCPDISCOVER from 00:11:22:33:44:66: no free leases
Nov 24 15:22:10 kern.crit kernel: Out of memory: Killed process 1188 (hostapd)
"""


def _ingest(tmp_path):
    path = tmp_path / "syslog.log"
    path.write_text(LOG, encoding="utf-8")
    db = tmp_path / "events.db"
    assert main(["ingest", "--file", str(path), "--db", str(db), "--source-ip", "192.168.1.1"]) == 0
    return db


def test_ingest_stores_every_line(tmp_path):
    db = _ingest(tmp_path)
    assert main(["stats", "--db", str(db)]) == 0


def test_analyze_json_reports_the_top_finding_first(tmp_path, capsys):
    db = _ingest(tmp_path)
    assert main(["analyze", "--db", str(db), "--format", "json", "--no-web"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_events"] == 5
    assert payload["findings"][0]["rule_id"] == "kernel-out-of-memory"
    assert any(f["rule_id"] == "dhcp-pool-exhausted" for f in payload["findings"])


def test_analyze_markdown_can_be_written_to_a_file(tmp_path):
    db = _ingest(tmp_path)
    out = tmp_path / "informe.md"
    assert main(["analyze", "--db", str(db), "--format", "markdown", "--no-web", "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# Syslogwatch")


def test_analyze_html_writes_a_standalone_page(tmp_path):
    db = _ingest(tmp_path)
    out = tmp_path / "informe.html"
    assert main(["analyze", "--db", str(db), "--format", "html", "--no-web", "-o", str(out)]) == 0
    assert "<!DOCTYPE html>" in out.read_text(encoding="utf-8")


def test_top_limits_the_number_of_findings(tmp_path, capsys):
    db = _ingest(tmp_path)
    assert main(["analyze", "--db", str(db), "--format", "json", "--no-web", "--top", "1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["findings"]) == 1


def test_listen_with_a_duration_returns_cleanly(tmp_path):
    db = tmp_path / "events.db"
    assert main(["listen", "--port", "0", "--bind", "127.0.0.1", "--db", str(db), "--duration", "0.2"]) == 0


def test_demo_loads_a_realistic_corpus(tmp_path, capsys):
    db = tmp_path / "demo.db"
    assert main(["demo", "--db", str(db)]) == 0
    assert main(["analyze", "--db", str(db), "--format", "json", "--no-web"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["findings"]) >= 4
