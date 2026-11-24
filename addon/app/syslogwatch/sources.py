"""Fuentes de entrada: syslog por UDP (lo que emiten los routers) y ficheros de log.

El colector sólo normaliza y entrega; no decide nada más.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Union

from .parse import SyslogEntry, parse_line


def allowed_by_filter(source_ip: str, allowed: Sequence[str]) -> bool:
    """Lista vacía = aceptar todo. La comparación es por IP exacta, sin CIDR."""
    return not allowed or source_ip in allowed


def _parse_target(target: Optional[str]) -> Optional[tuple]:
    if not target:
        return None
    host, _, port = target.partition(":")
    return host or None, int(port or 514)


class UdpSource:
    """Escucha syslog UDP en un hilo aparte y entrega entradas ya parseadas."""

    def __init__(
        self,
        port: int = 514,
        bind: str = "0.0.0.0",
        on_entry: Optional[Callable[[SyslogEntry], None]] = None,
        allowed: Sequence[str] = (),
        forward: Optional[str] = None,
    ):
        self._on_entry = on_entry or (lambda entry: None)
        self.allowed = tuple(allowed)
        self.forward_to = _parse_target(forward)
        self.dropped = 0
        self.received = 0
        self.forwarded = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind, port))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]

    def start(self) -> "UdpSource":
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="syslogwatch-udp", daemon=True)
        self._thread.start()
        return self

    def _forward(self, text: str) -> None:
        if not self.forward_to:
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                relay.sendto(text.encode("utf-8"), self.forward_to)
            self.forwarded += 1
        except OSError:
            self.dropped += 1

    def _loop(self) -> None:
        while self._running:
            try:
                payload, address = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            source_ip = address[0]
            text = payload.decode("utf-8", "replace")
            for line in text.splitlines():
                entry = parse_line(line, source_ip=source_ip)
                if entry is None:
                    continue
                if not allowed_by_filter(source_ip, self.allowed):
                    self.dropped += 1
                    continue
                self.received += 1
                self._forward(line)
                try:
                    self._on_entry(entry)
                except Exception:  # noqa: BLE001 - un consumidor roto no puede tumbar el colector
                    self.dropped += 1

    def stop(self) -> None:
        self._running = False
        try:
            self.sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    def __enter__(self) -> "UdpSource":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


class FileSource:
    """Lee un fichero de log (syslog exportado, journal volcado a texto)."""

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)

    def lines(self) -> Iterable[str]:
        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line

    def entries(self, source_ip: str = "file") -> List[SyslogEntry]:
        result = []
        for line in self.lines():
            entry = parse_line(line, source_ip=source_ip)
            if entry is not None:
                result.append(entry)
        return result
