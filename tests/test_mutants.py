"""Más bordes: los últimos mutantes que sobrevivían."""

from syslogwatch.parse import parse_line
from syslogwatch.rank import (
    Finding,
    aggregate,
    frequency_score,
    severity_score,
    summarize,
)
from syslogwatch.rules import rule_by_id


def test_frequency_score_exact_values():
    assert frequency_score(0) == 0.0
    assert frequency_score(1) == 20.0
    assert frequency_score(3) == 40.0
    assert frequency_score(10_000) == 100.0


def test_severity_score_endpoints():
    assert severity_score(0) == 100
    assert severity_score(6) == 14
    assert severity_score(7) == 0
    assert severity_score(-3) == 100  # un valor fuera de rango se satura, no explota
    assert severity_score(42) == 0


def test_finding_severity_name_is_clamped():
    assert Finding(rule=rule_by_id("unclassified"), max_severity=2).severity_name == "crit"
    assert Finding(rule=rule_by_id("unclassified"), max_severity=99).severity_name == "debug"


def test_rfc5424_nil_host_and_app_become_none():
    entry = parse_line("1 2026-11-24T15:16:47Z - - - - - cuerpo", source_ip="192.168.1.219")
    assert entry.host is None
    assert entry.app is None
    assert entry.message == "cuerpo"


def test_equal_scores_are_ordered_by_count():
    findings = aggregate(
        [
            parse_line("Nov 24 15:20:00 user.info zcmdModuleCfg: beRaInfoIntfSetStatsUpdate()", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:01 user.info zcmdModuleCfg: beRaInfoIntfSetStatsUpdate()", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:02 user.info zcmdModuleCfg: CONFIG: Saving config - OK", source_ip="192.168.1.1"),
        ]
    )
    ids = [f.rule.id for f in findings]
    counts = [f.count for f in findings]
    assert counts == sorted(counts, reverse=True) or ids[0] == "zcmd-noise"


def test_summarize_orders_categories_by_volume():
    findings = aggregate(
        [
            parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:01 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:02 user.info zcmdModuleCfg: beRaInfoIntfSetStatsUpdate()", source_ip="192.168.1.1"),
        ]
    )
    summary = summarize(findings)
    assert list(summary)[0] == "dhcp"
    assert summary["dhcp"] == 2


def test_summarize_adds_counts_instead_of_overwriting():
    findings = aggregate(
        [
            parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:01 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"),
        ]
    )
    assert summarize(findings)["dhcp"] == 2


def test_severity_name_of_zero_is_emerg():
    assert Finding(rule=rule_by_id("unclassified"), max_severity=0).severity_name == "emerg"


def test_ties_in_score_are_broken_by_number_of_occurrences():
    """Dos reglas de igual peso: la que más se repite va primero."""
    lines = [
        f"Nov 24 15:2{i//60}:{i%60:02d} daemon.err dhcpd: no free leases" for i in range(40)
    ] + [
        f"Nov 24 15:3{i//60}:{i%60:02d} daemon.err kernel: EXT4-fs error (device mmcblk0p2) read-only"
        for i in range(80)
    ]
    findings = aggregate([parse_line(line, source_ip="192.168.1.1") for line in lines])
    disk = next(f for f in findings if f.rule.id == "disk-io-error")
    dhcp = next(f for f in findings if f.rule.id == "dhcp-pool-exhausted")
    assert disk.score == dhcp.score  # mismo peso y severidad: empatan
    assert findings[0].rule.id == "disk-io-error"  # y gana el que más aparece
