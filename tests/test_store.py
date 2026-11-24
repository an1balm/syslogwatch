from datetime import datetime, timedelta

from syslogwatch.parse import parse_line
from syslogwatch.store import Store


def _e(text, ip="192.168.1.1", now=None):
    return parse_line(text, source_ip=ip, now=now)


def test_add_and_count_entries(tmp_path):
    store = Store(tmp_path / "t.db")
    added = store.add(
        [
            _e("Nov 24 15:20:00 daemon.err dhcpd: no free leases"),
            _e("Nov 24 15:20:01 user.info zcmdModuleCfg: CONFIG: Saving config - OK"),
        ]
    )
    assert added == 2
    assert store.count() == 2


def test_identical_lines_are_stored_once(tmp_path):
    store = Store(tmp_path / "t.db")
    line = "Nov 24 15:20:00 daemon.err dhcpd: no free leases"
    store.add([_e(line), _e(line), _e(line)])
    assert store.count() == 1


def test_entries_round_trip_with_their_fields(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add([_e("Nov 24 15:20:00 kern.err kernel: nf_conntrack: table full, dropping packet")])
    entry = store.entries()[0]
    assert entry.severity == 3
    assert entry.facility == 0
    assert entry.app == "kernel"
    assert entry.source_ip == "192.168.1.1"
    assert entry.message.startswith("nf_conntrack")


def test_since_filter_uses_the_stored_timestamp(tmp_path):
    store = Store(tmp_path / "t.db")
    old = datetime.now() - timedelta(days=3)
    store.add([_e("Nov 24 15:20:00 daemon.err dhcpd: no free leases", now=old)])
    store.add([_e("Nov 24 15:22:00 kern.err kernel: Out of memory: Killed process 9")])
    recent = store.entries(since=timedelta(hours=1))
    assert len(recent) == 1
    assert recent[0].message.startswith("Out of memory")


def test_device_filter(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add(
        [
            _e("Nov 24 15:20:00 daemon.err dhcpd: no free leases", ip="192.168.1.1"),
            _e("Nov 24 15:20:00 daemon.err dhcpd: no free leases", ip="192.168.1.153"),
        ]
    )
    assert len(store.entries(device="192.168.1.153")) == 1


def test_stats_group_by_device_and_severity(tmp_path):
    store = Store(tmp_path / "t.db")
    store.add(
        [
            _e("Nov 24 15:20:00 daemon.err dhcpd: no free leases", ip="192.168.1.1"),
            _e("Nov 24 15:20:01 daemon.err dhcpd: no free leases", ip="192.168.1.1"),
            _e("Nov 24 15:20:02 user.info zcmdModuleCfg: beRaInfoIntfSetStatsUpdate()", ip="192.168.1.1"),
        ]
    )
    stats = store.stats()
    assert stats["total"] == 3
    assert stats["by_device"]["192.168.1.1"] == 3
    assert stats["by_severity"]["err"] == 2
    assert stats["oldest"] and stats["newest"]
