import socket
import time

from syslogwatch.sources import UdpSource


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_forward_relays_the_original_line_and_keeps_storing_it():
    target_port = _free_udp_port()
    relayed = []
    store = []

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
        relay.bind(("127.0.0.1", target_port))
        relay.settimeout(3)
        source = UdpSource(
            port=0,
            bind="127.0.0.1",
            on_entry=store.append,
            forward=f"127.0.0.1:{target_port}",
        )
        source.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(b"Nov 24 15:20:00 daemon.err dhcpd: no free leases", ("127.0.0.1", source.port))
            payload, _ = relay.recvfrom(65535)
            relayed.append(payload.decode())
            deadline = time.time() + 3
            while not store and time.time() < deadline:
                time.sleep(0.02)
        finally:
            source.stop()

    assert relayed and relayed[0] == "Nov 24 15:20:00 daemon.err dhcpd: no free leases"
    assert len(store) == 1  # el reenvío no impide guardar
    assert source.forwarded == 1


def test_without_forward_nothing_is_relayed():
    source = UdpSource(port=0, bind="127.0.0.1")
    try:
        assert source.forward_to is None
        assert source.forwarded == 0
    finally:
        source.stop()
