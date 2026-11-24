"""Priorización: convierte entradas sueltas en hallazgos ordenados por importancia.

La fórmula es explícita para que se pueda discutir y ajustar:

    score = criticalidad_del_equipo * (0.50 * peso_regla
                                       + 0.35 * severidad_syslog
                                       + 0.15 * frecuencia)

* ``peso_regla``: gravedad intrínseca del patrón (0-100), definida en el catálogo.
* ``severidad_syslog``: 100 para ``emerg``, 0 para ``debug``.
* ``frecuencia``: 20·log2(1+repeticiones), saturada en 100: 1 vez → 20, 32 → 100.
* ``criticalidad``: cuánto duele que falle ese equipo (router > AP > desconocido).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence

from .parse import SyslogEntry
from .rules import Rule, match_rule

DEFAULT_CRITICALITY = 1.0

# Equipos de esta red, por IP: el router y el host de Home Assistant son el núcleo.
DEVICE_CRITICALITY: Dict[str, float] = {
    "192.168.1.1": 1.25,    # router ISP (Zyxel EX3301-T0)
    "192.168.1.219": 1.20,  # Home Assistant
    "192.168.1.100": 1.15,  # AdGuard Home / DHCP
    "192.168.1.125": 1.10,  # COVR-1100
    "192.168.1.153": 1.10,  # COVR-1100 (segunda IP)
    "192.168.1.102": 1.10,  # DAP-1620 sótano
}

MAX_SAMPLES = 3


def severity_score(severity: int) -> int:
    """0-7 syslog → 100 (emerg) … 0 (debug)."""
    return int(round((7 - max(0, min(7, severity))) / 7 * 100))


def frequency_score(count: int) -> float:
    return min(100.0, 20.0 * math.log2(1 + max(0, count)))


@dataclass
class Finding:
    rule: Rule
    count: int = 0
    max_severity: int = 7
    devices: List[str] = field(default_factory=list)
    samples: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    score: int = 0
    references: List = field(default_factory=list)

    @property
    def severity_name(self) -> str:
        return ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")[
            max(0, min(7, self.max_severity))
        ]


def device_factor(devices: Iterable[str], criticality: Optional[Dict[str, float]] = None) -> float:
    table = dict(DEVICE_CRITICALITY)
    if criticality:
        table.update(criticality)
    return max((table.get(d, DEFAULT_CRITICALITY) for d in devices), default=DEFAULT_CRITICALITY)


def score_finding(finding: Finding, criticality: Optional[Dict[str, float]] = None) -> int:
    raw = device_factor(finding.devices, criticality) * (
        0.50 * finding.rule.weight
        + 0.35 * severity_score(finding.max_severity)
        + 0.15 * frequency_score(finding.count)
    )
    return int(round(max(0.0, min(100.0, raw))))


def _register(groups: Dict[str, Finding], devices: Dict[str, set], entry: SyslogEntry, now: datetime) -> None:
    rule = match_rule(entry)
    finding = groups.get(rule.id)
    if finding is None:
        finding = groups[rule.id] = Finding(rule=rule)
        devices[rule.id] = set()
    finding.count += 1
    finding.max_severity = min(finding.max_severity, entry.severity)
    devices[rule.id].add(entry.device)
    message = entry.message.strip()
    if message and message not in finding.samples and len(finding.samples) < MAX_SAMPLES:
        finding.samples.append(message)
    stamp = entry.ts or now
    finding.first_seen = stamp if finding.first_seen is None else min(finding.first_seen, stamp)
    finding.last_seen = stamp if finding.last_seen is None else max(finding.last_seen, stamp)


def aggregate(
    entries: Iterable[SyslogEntry],
    criticality: Optional[Dict[str, float]] = None,
    now: Optional[datetime] = None,
) -> List[Finding]:
    """Agrupa por regla y devuelve los hallazgos de más a menos importante."""
    now = now or datetime.now()
    groups: Dict[str, Finding] = {}
    devices: Dict[str, set] = {}

    for entry in entries:
        _register(groups, devices, entry, now)

    for rule_id, finding in groups.items():
        finding.devices = sorted(devices[rule_id])
        finding.score = score_finding(finding, criticality)

    return sorted(groups.values(), key=lambda f: (-f.score, -f.count, f.rule.id))


def summarize(findings: Sequence[Finding]) -> Dict[str, int]:
    """Cuenta hallazgos por categoría y por banda de importancia."""
    summary: Dict[str, int] = {}
    for finding in findings:
        summary[finding.rule.category] = summary.get(finding.rule.category, 0) + finding.count
    return dict(sorted(summary.items(), key=lambda kv: -kv[1]))
