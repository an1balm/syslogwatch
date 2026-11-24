import socket
import time

from syslogwatch.sources import FileSource, UdpSource, allowed_by_filter


def test_udp_source_receives_a_datagram_and_parses_it():
    received = []
    source = UdpSource(port=0, bind="127.0.0.1", on_entry=received.append)
    source.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(
                b"Nov 24 15:20:00 daemon.err dhcpd: no free leases",
                ("127.0.0.1", source.port),
            )
        deadline = time.time() + 3
        while not received and time.time() < deadline:
            time.sleep(0.02)
    finally:
        source.stop()
    assert received, "no llegó ningún datagrama"
    assert received[0].message == "no free leases"
    assert received[0].severity == 3


def test_udp_source_ignores_senders_outside_the_allow_list():
    received = []
    source = UdpSource(port=0, bind="127.0.0.1", on_entry=received.append, allowed=["192.168.1.1"])
    source.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"Nov 24 15:20:00 daemon.err dhcpd: no free leases", ("127.0.0.1", source.port))
        time.sleep(0.3)
    finally:
        source.stop()
    assert received == []
    assert source.dropped == 1


def test_multiple_lines_in_one_datagram_become_several_entries():
    received = []
    source = UdpSource(port=0, bind="127.0.0.1", on_entry=received.append)
    source.start()
    try:
        payload = (
            b"Nov 24 15:20:00 daemon.err dhcpd: no free leases\n"
            b"Nov 24 15:20:01 kern.err kernel: Out of memory: Killed process 9"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, ("127.0.0.1", source.port))
        deadline = time.time() + 3
        while len(received) < 2 and time.time() < deadline:
            time.sleep(0.02)
    finally:
        source.stop()
    assert len(received) == 2


def test_allowed_by_filter_accepts_everything_when_empty():
    assert allowed_by_filter("10.0.0.1", [])
    assert allowed_by_filter("10.0.0.1", ["10.0.0.1"])
    assert not allowed_by_filter("10.0.0.2", ["10.0.0.1"])


def test_file_source_reads_a_log_file(tmp_path):
    path = tmp_path / "syslog.log"
    path.write_text(
        "Nov 24 15:20:00 daemon.err dhcpd: no free leases\n\nNov 24 15:20:02 user.info zcmdModuleCfg: beRaInfo\n",
        encoding="utf-8",
    )
    entries = list(FileSource(path).entries(source_ip="192.168.1.1"))
    assert len(entries) == 2
    assert entries[0].app == "dhcpd"
