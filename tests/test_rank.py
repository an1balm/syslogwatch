from syslogwatch.parse import parse_line
from syslogwatch.rank import DEVICE_CRITICALITY, aggregate, score_finding, severity_score


def _e(text, ip="192.168.1.1"):
    return parse_line(text, source_ip=ip)


def test_severity_score_is_100_for_emerg_and_0_for_debug():
    assert severity_score(0) == 100
    assert severity_score(7) == 0
    assert severity_score(3) > severity_score(6)


def test_aggregate_groups_by_rule_and_counts_occurrences():
    lines = [
        _e("Nov 24 15:20:0%d daemon.err dhcpd: no free leases" % i) for i in range(3)
    ] + [
        _e("Nov 24 15:21:00 user.info zcmdModuleCfg: CONFIG: Saving config - OK")
    ]
    findings = aggregate(lines)
    by_id = {f.rule.id: f for f in findings}
    assert by_id["dhcp-pool-exhausted"].count == 3
    assert by_id["config-save-ok"].count == 1
    assert len(findings) == 2


def test_aggregate_keeps_samples_and_devices():
    findings = aggregate(
        [
            _e("Nov 24 15:20:00 kern.err kernel: nf_conntrack: table full, dropping packet", ip="192.168.1.1"),
            _e("Nov 24 15:20:01 kern.err kernel: nf_conntrack: table full, dropping packet", ip="192.168.1.153"),
            _e("Nov 24 15:20:02 kern.err kernel: nf_conntrack: table full, dropping packet", ip="192.168.1.1"),
        ]
    )
    finding = findings[0]
    assert finding.devices == ["192.168.1.1", "192.168.1.153"]
    assert len(finding.samples) == 1  # mensajes idénticos se muestran una vez
    assert finding.first_seen <= finding.last_seen


def test_a_critical_rule_outranks_an_informational_one_with_equal_count():
    findings = aggregate(
        [
            _e("Nov 24 15:20:00 kern.crit kernel: Out of memory: Killed process 1234"),
            _e("Nov 24 15:20:01 user.info zcmdModuleCfg: CONFIG: Saving config - OK"),
        ]
    )
    assert findings[0].rule.id == "kernel-out-of-memory"
    assert findings[0].score > findings[1].score


def test_device_criticality_multiplies_the_score():
    core = aggregate([_e("Nov 24 15:20:00 daemon.err dhcpd: no free leases", ip="192.168.1.1")])[0]
    unknown = aggregate([_e("Nov 24 15:20:00 daemon.err dhcpd: no free leases", ip="192.168.1.222")])[0]
    assert core.score > unknown.score
    assert DEVICE_CRITICALITY.get("192.168.1.1", 1.0) > DEVICE_CRITICALITY.get("192.168.1.222", 1.0)


def test_frequency_raises_the_score_but_cannot_beat_two_severity_steps():
    once = aggregate([_e("Nov 24 15:20:00 daemon.err dhcpd: no free leases")])[0]
    many = aggregate(
        [_e("Nov 24 15:20:%02d daemon.err dhcpd: no free leases" % i) for i in range(30)]
    )[0]
    assert many.score > once.score
    assert many.score <= 100


def test_score_finding_is_clamped_between_0_and_100():
    finding = aggregate(
        [_e("Nov 24 15:20:%02d kern.emerg kernel: Out of memory: Killed process 1" % i) for i in range(0, 30)]
    )[0]
    assert 0 <= score_finding(finding) <= 100
