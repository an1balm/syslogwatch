"""Tests de borde: matan los mutantes que sobreviven en los módulos centrales."""

from datetime import datetime, timedelta

from syslogwatch.parse import _apply_pri, _parse_bsd, _parse_rfc5424, _safe_year, parse_line
from syslogwatch.rank import MAX_SAMPLES, aggregate, summarize


# -- parse --------------------------------------------------------------

def test_safe_year_accepts_a_timestamp_exactly_one_day_ahead():
    now = datetime(2026, 11, 24, 15, 0, 0)
    result = _safe_year(11, 25, (15, 0, 0), now)
    assert result == datetime(2026, 11, 25, 15, 0, 0)


def test_safe_year_rolls_back_a_year_for_a_far_future_date():
    now = datetime(2026, 1, 2, 9, 0, 0)
    result = _safe_year(12, 31, (23, 0, 0), now)
    assert result == datetime(2025, 12, 31, 23, 0, 0)


def test_pri_191_is_the_last_valid_value_and_192_is_ignored():
    accepted = {}
    _apply_pri("<191>Nov 24 15:00:00 x", accepted)
    assert accepted == {"facility": 23, "severity": 7}

    rejected = {}
    _apply_pri("<192>Nov 24 15:00:00 x", rejected)
    assert rejected == {}


def test_parse_bsd_reports_whether_it_matched():
    entry = {}
    assert _parse_bsd("texto sin fecha", entry, datetime(2026, 11, 24)) is False
    assert entry == {}
    assert _parse_bsd("Nov 24 15:20:00 host app: msg", entry, datetime(2026, 11, 24)) is True


def test_parse_rfc5424_reports_whether_it_matched():
    entry = {}
    assert _parse_rfc5424("texto sin cabecera", entry) is False
    assert _parse_rfc5424("1 2026-11-24T15:16:47Z ha kernel - - - hola", entry) is True
    assert entry["message"] == "hola"


def test_rfc5424_tolerates_a_nil_timestamp():
    entry = parse_line("1 - ha kernel - - - sin hora", source_ip="192.168.1.219")
    assert entry is not None
    assert entry.ts is None
    assert entry.message == "sin hora"


# -- rank ---------------------------------------------------------------

def test_samples_are_capped_at_the_limit():
    texts = [f"Nov 24 15:20:0{i} user.err app: mensaje distinto {i}" for i in range(5)]
    findings = aggregate([parse_line(t, source_ip="192.168.1.1") for t in texts])
    assert len(findings[0].samples) == MAX_SAMPLES


def test_entries_without_timestamp_still_get_first_and_last_seen():
    entry = parse_line("texto suelto sin fecha", source_ip="192.168.1.1")
    finding = aggregate([entry], now=datetime(2026, 11, 24, 12, 0, 0))[0]
    assert finding.first_seen == datetime(2026, 11, 24, 12, 0, 0)
    assert finding.last_seen == finding.first_seen


def test_out_of_order_entries_get_min_and_max_timestamps():
    early = parse_line("Nov 24 10:00:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")
    late = parse_line("Nov 24 18:00:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")
    finding = aggregate([late, early])[0]
    assert finding.first_seen.hour == 10
    assert finding.last_seen.hour == 18


def test_findings_are_sorted_by_score_descending():
    findings = aggregate(
        [
            parse_line("Nov 24 15:20:00 user.info zcmdModuleCfg: CONFIG: Saving config - OK", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:01 kern.crit kernel: Out of memory: Killed process 9", source_ip="192.168.1.1"),
        ]
    )
    assert findings[0].score > findings[1].score


def test_summarize_counts_every_message_of_a_category():
    findings = aggregate(
        [
            parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:01 daemon.err dhcpd: no free leases", source_ip="192.168.1.1"),
            parse_line("Nov 24 15:20:02 daemon.err dhcpd: duplicate address 192.168.1.5 detected", source_ip="192.168.1.1"),
        ]
    )
    summary = summarize(findings)
    assert summary["dhcp"] == 3


def test_frequency_score_grows_with_count():
    one = aggregate([parse_line("Nov 24 15:20:00 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")])
    many = aggregate(
        [
            parse_line(f"Nov 24 15:20:{i:02d} daemon.err dhcpd: no free leases", source_ip="192.168.1.1")
            for i in range(10)
        ]
    )
    assert many[0].score > one[0].score
    assert many[0].last_seen - many[0].first_seen == timedelta(seconds=9)
