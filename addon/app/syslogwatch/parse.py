"""Parseo de líneas syslog a un modelo de dominio.

Acepta los tres formatos que llegan de verdad en esta red:

* RFC 3164 con ``<PRI>`` (``<30>Nov 24 15:16:47 host tag[pid]: msg``).
* El formato propio de Zyxel, con el nivel escrito como ``facility.severity``
  (``Nov 24 15:16:47 user.info zcmdModuleCfg: msg``).
* El de los D-Link COVR, sin nivel declarado (``Nov 24 15:10:49 kernel: msg``).

Todo lo que no encaja se conserva como mensaje suelto: perder una línea es peor
que clasificarla mal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

SEVERITY_NAMES = (
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
)

FACILITY_NAMES = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "ntp": 12,
    "audit": 13,
    "alert": 14,
    "clock": 15,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

DEFAULT_SEVERITY = 5  # notice: el emisor no declaró nivel

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_PRI_RE = re.compile(r"^<(\d{1,3})>")
_BSD_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$"
)
_RFC5424_RE = re.compile(
    r"^1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<sd>-|\[.*?\])\s*(?P<msg>.*)$"
)
_LEVEL_TOKEN_RE = re.compile(r"^(?P<fac>[a-z0-9]+)\.(?P<sev>emerg|alert|crit|err|warning|notice|info|debug)$")
_TAG_RE = re.compile(r"^(?P<app>[A-Za-z0-9_.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")


@dataclass(frozen=True)
class SyslogEntry:
    """Una línea syslog ya normalizada. Es inmutable: sale de la frontera hecha."""

    raw: str
    source_ip: str
    message: str
    severity: int = DEFAULT_SEVERITY
    facility: Optional[int] = None
    host: Optional[str] = None
    app: Optional[str] = None
    pid: Optional[int] = None
    ts: Optional[datetime] = None

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES[self.severity]

    @property
    def facility_name(self) -> Optional[str]:
        if self.facility is None:
            return None
        for name, value in FACILITY_NAMES.items():
            if value == self.facility:
                return name
        return str(self.facility)

    @property
    def device(self) -> str:
        return self.host or self.source_ip


def _safe_year(month: int, day: int, time_bits: tuple[int, int, int], now: datetime) -> Optional[datetime]:
    for year in (now.year, now.year - 1):
        try:
            candidate = datetime(year, month, day, *time_bits)
        except ValueError:  # 29 de febrero en un año no bisiesto
            continue
        if candidate - now <= timedelta(days=1):
            return candidate
    return None


def _split_program(rest: str, entry: dict) -> None:
    """Separa ``host tag[pid]:`` de ``msg`` dentro de la parte tras la fecha.

    ``rest`` llega ambiguo: puede empezar por hostname, por ``facility.severity``
    o directamente por el tag (``kernel: ...``). Se resuelve por forma, no por
    una lista de nombres conocidos.
    """
    rest = rest.strip()
    level = _LEVEL_TOKEN_RE.match(rest.split(" ", 1)[0] if rest else "")
    if level:
        entry["facility"] = FACILITY_NAMES.get(level.group("fac"), None)
        entry["severity"] = SEVERITY_NAMES.index(level.group("sev"))
        rest = rest[len(level.group(0)):].strip()

    if not rest:
        return

    if _TAG_RE.match(rest):
        _apply_tag(rest, entry)
        return

    head, _, tail = rest.partition(" ")
    if tail and _TAG_RE.match(tail):
        entry["host"] = head
        _apply_tag(tail, entry)
    else:
        # Sin tag reconocible no se inventa un hostname: la línea entera es mensaje.
        entry["message"] = rest


def _apply_tag(text: str, entry: dict) -> None:
    match = _TAG_RE.match(text.strip())
    if not match:
        entry["message"] = text.strip()
        return
    entry["app"] = match.group("app")
    if match.group("pid"):
        entry["pid"] = int(match.group("pid"))
    entry["message"] = match.group("msg").strip()


def _apply_pri(text: str, entry: dict) -> str:
    pri = _PRI_RE.match(text)
    if pri:
        value = int(pri.group(1))
        if value <= 191:
            entry["facility"] = value // 8
            entry["severity"] = value % 8
            return text[pri.end():].lstrip()
    return text


def _parse_rfc5424(rest: str, entry: dict) -> bool:
    match = _RFC5424_RE.match(rest)
    if not match:
        return False
    try:
        entry["ts"] = datetime.fromisoformat(match.group("ts").replace("Z", "+00:00"))
    except ValueError:
        entry["ts"] = None
    entry["host"] = None if match.group("host") == "-" else match.group("host")
    entry["app"] = None if match.group("app") == "-" else match.group("app")
    entry["message"] = match.group("msg").strip()
    return True


def _parse_bsd(rest: str, entry: dict, now: datetime) -> bool:
    match = _BSD_RE.match(rest)
    if not match:
        return False
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    entry["ts"] = _safe_year(
        _MONTHS[match.group("mon")], int(match.group("day")), (hour, minute, second), now
    )
    _split_program(match.group("rest"), entry)
    return True


def parse_line(text: str, source_ip: str, now: Optional[datetime] = None) -> Optional[SyslogEntry]:
    """Normaliza una línea. Devuelve ``None`` sólo si está vacía."""
    if text is None:
        return None
    raw = text.rstrip("\r\n")
    stripped = raw.strip()
    if not stripped:
        return None

    now = now or datetime.now()
    entry: dict = {
        "raw": raw,
        "source_ip": source_ip,
        "message": stripped,
        "severity": DEFAULT_SEVERITY,
        "facility": None,
        "host": None,
        "app": None,
        "pid": None,
        "ts": None,
    }

    rest = _apply_pri(stripped, entry)
    if _parse_rfc5424(rest, entry) or _parse_bsd(rest, entry, now):
        return SyslogEntry(**entry)

    _split_program(rest, entry)
    return SyslogEntry(**entry)


def parse_stream(lines, source_ip: str = "unknown", now: Optional[datetime] = None):
    """Genera entradas a partir de un iterable de líneas."""
    for line in lines:
        entry = parse_line(line, source_ip=source_ip, now=now)
        if entry is not None:
            yield entry
