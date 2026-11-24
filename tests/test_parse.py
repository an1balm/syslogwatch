from datetime import datetime

from syslogwatch.parse import parse_line


def test_rfc3164_with_pri_parses_facility_severity_and_tag():
    e = parse_line(
        "<30>Nov 24 15:16:47 router1 zcmdModuleCfg[512]: beRaInfoIntfSetStatsUpdate()",
        source_ip="192.168.1.1",
    )
    assert e is not None
    assert e.facility == 3  # 30 // 8
    assert e.severity == 6  # 30 % 8 -> info
    assert e.host == "router1"
    assert e.app == "zcmdModuleCfg"
    assert e.pid == 512
    assert e.message == "beRaInfoIntfSetStatsUpdate()"
    assert (e.ts.month, e.ts.day, e.ts.hour, e.ts.minute, e.ts.second) == (11, 24, 15, 16, 47)
    assert e.ts.year == datetime.now().year  # syslog no lleva año: se asume el actual


def test_zyxel_facility_dot_severity_token_is_read_as_severity():
    e = parse_line(
        "Nov 24 15:16:47 user.info zcmdModuleCfg: zcmdTr181MtParmAttrQry: no request",
        source_ip="192.168.1.1",
    )
    assert e is not None
    assert e.facility == 1  # user
    assert e.severity == 6  # info
    assert e.app == "zcmdModuleCfg"
    assert e.message == "zcmdTr181MtParmAttrQry: no request"
    assert e.host is None  # el emisor no manda hostname...
    assert e.device == "192.168.1.1"  # ...así que el dispositivo es su IP


def test_covr_kernel_line_without_severity_defaults_to_notice():
    e = parse_line(
        "Nov 24 15:10:49 kernel: [expireEntryBlockList 208]BLOCK LIST STA EXPIRES (0)",
        source_ip="192.168.1.153",
    )
    assert e is not None
    assert e.app == "kernel"
    assert e.facility is None
    assert e.severity == 5  # notice: no hay nivel declarado
    assert e.message.startswith("[expireEntryBlockList")


def test_rfc5424_iso_timestamp_is_understood():
    e = parse_line(
        "<11>1 2026-11-24T15:16:47+01:00 ha kernel - - - disk error",
        source_ip="192.168.1.219",
    )
    assert e is not None
    assert e.severity == 3  # 11 % 8 -> err
    assert e.app == "kernel"
    assert e.message == "disk error"
    assert e.ts.year == 2026


def test_severity_helper_maps_rfc_names():
    e = parse_line("Nov 24 15:16:47 daemon.err dhcpd: no free leases", source_ip="192.168.1.1")
    assert e.severity == 3
    assert e.facility == 3
    assert e.severity_name == "err"


def test_unparseable_text_is_kept_as_message_not_dropped():
    e = parse_line("something completely unstructured", source_ip="10.0.0.9")
    assert e is not None
    assert e.message == "something completely unstructured"
    assert e.severity == 5
    assert e.ts is None


def test_blank_line_is_ignored():
    assert parse_line("   \n", source_ip="10.0.0.9") is None


def test_a_tag_repeated_inside_the_message_is_collapsed():
    # línea real del router Digi: «cron.info crond: crond: USER root pid …»
    e = parse_line("Nov 24 17:26:01 cron.info crond: crond: USER root pid 14989 cmd /usr/etc/quarterHour.sh",
                   source_ip="192.168.1.1")
    assert e.app == "crond"
    assert e.message == "USER root pid 14989 cmd /usr/etc/quarterHour.sh"
    assert e.facility == 9  # cron
