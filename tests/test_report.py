import json

from syslogwatch.enrich import Reference
from syslogwatch.parse import parse_line
from syslogwatch.rank import aggregate
from syslogwatch.report import Report, render_html, render_markdown, to_json


def _report(*texts, ip="192.168.1.1", **kwargs):
    entries = [parse_line(t, source_ip=ip) for t in texts]
    findings = aggregate(entries)
    return Report(
        findings=findings,
        total_events=len(entries),
        window="últimas 24 h",
        devices=sorted({e.device for e in entries}),
        **kwargs,
    )


def test_markdown_has_title_window_and_ranking_table():
    report = _report(
        "Nov 24 15:20:00 kern.crit kernel: Out of memory: Killed process 9",
        "Nov 24 15:20:01 user.info zcmdModuleCfg: CONFIG: Saving config - OK",
    )
    md = render_markdown(report)
    assert md.startswith("# Syslogwatch")
    assert "últimas 24 h" in md
    assert "| # | Importancia | Hallazgo |" in md


def test_findings_are_listed_in_score_order_with_cause_and_fix():
    report = _report(
        "Nov 24 15:20:00 user.info zcmdModuleCfg: CONFIG: Saving config - OK",
        "Nov 24 15:20:01 kern.crit kernel: Out of memory: Killed process 9",
    )
    md = render_markdown(report)
    assert md.index("Sin memoria") < md.index("Guardado de configuración")
    assert "**Por qué falla.**" in md
    assert "**Cómo se resuelve.**" in md


def test_references_are_rendered_as_links():
    report = _report("Nov 24 15:20:00 daemon.err dhcpd: no free leases")
    report.findings[0].references = [
        Reference("catalogo", "RFC 3927", "https://datatracker.ietf.org/doc/html/rfc3927")
    ]
    md = render_markdown(report)
    assert "[RFC 3927 (catalogo)](https://datatracker.ietf.org/doc/html/rfc3927)" in md


def test_escaping_protects_table_cells_and_html():
    from syslogwatch.report import _md_escape

    assert _md_escape("a | b <c>") == "a \\| b &lt;c&gt;"
    report = _report("Nov 24 15:20:00 user.err app: value <bad> | pipe inside message")
    html_out = render_html(report)
    assert "&lt;bad&gt;" in html_out
    assert "<bad>" not in html_out


def test_json_report_contains_scores_and_rule_ids():
    report = _report("Nov 24 15:20:00 kern.crit kernel: Out of memory: Killed process 9")
    payload = json.loads(to_json(report))
    assert payload["findings"][0]["rule_id"] == "kernel-out-of-memory"
    assert payload["findings"][0]["score"] > 0
    assert payload["total_events"] == 1


def test_html_is_self_contained_and_lists_every_finding():
    report = _report(
        "Nov 24 15:20:00 kern.crit kernel: Out of memory: Killed process 9",
        "Nov 24 15:20:01 user.info zcmdModuleCfg: CONFIG: Saving config - OK",
    )
    page = render_html(report)
    assert page.lstrip().startswith("<!DOCTYPE html>")
    assert "<style>" in page
    assert page.count('class="finding"') == 2


def test_degraded_flag_is_reported_when_external_lookup_failed():
    report = _report("Nov 24 15:20:00 daemon.err dhcpd: no free leases", degraded=True)
    md = render_markdown(report)
    assert "sin conexión" in md.lower() or "no se pudo" in md.lower()
