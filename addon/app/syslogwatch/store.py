"""Persistencia en SQLite: el histórico es la materia prima del análisis.

Se guardan los eventos crudos ya normalizados, nunca los hallazgos: así se puede
reescribir el catálogo de reglas y reclasificar ayer sin volver a recolectar.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from .parse import SyslogEntry

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip   TEXT NOT NULL,
    host        TEXT,
    app         TEXT,
    pid         INTEGER,
    facility    INTEGER,
    severity    INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    received_at TEXT NOT NULL,
    message     TEXT NOT NULL,
    raw         TEXT NOT NULL,
    UNIQUE (source_ip, ts, message)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_source ON events (source_ip);
"""


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        return value.isoformat(sep=" ")
    return value.astimezone(timezone.utc).replace(tzinfo=None).isoformat(sep=" ")


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class Store:
    """Almacén de eventos. Idempotente: insertar dos veces la misma línea no duplica."""

    def __init__(self, path: Union[str, Path] = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def add(self, entries: Iterable[SyslogEntry], received_at: Optional[datetime] = None) -> int:
        received_at = received_at or datetime.now()
        incoming = received_at.isoformat(sep=" ")
        rows = []
        for entry in entries:
            rows.append(
                (
                    entry.source_ip,
                    entry.host,
                    entry.app,
                    entry.pid,
                    entry.facility,
                    entry.severity,
                    _iso(entry.ts or received_at),
                    incoming,
                    entry.message,
                    entry.raw,
                )
            )
        if not rows:
            return 0
        before = self._conn.total_changes
        self._conn.executemany(
            "INSERT OR IGNORE INTO events "
            "(source_ip, host, app, pid, facility, severity, ts, received_at, message, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()
        return self._conn.total_changes - before

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def entries(
        self,
        since: Optional[Union[timedelta, datetime]] = None,
        device: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[SyslogEntry]:
        clauses, params = [], []
        if since is not None:
            threshold = datetime.now() - since if isinstance(since, timedelta) else since
            clauses.append("ts >= ?")
            params.append(_iso(threshold))
        if device:
            clauses.append("(source_ip = ? OR host = ?)")
            params.extend([device, device])
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        sql = f"SELECT source_ip, host, app, pid, facility, severity, ts, message, raw FROM events {where}ORDER BY ts"
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [
            SyslogEntry(
                raw=row[8],
                source_ip=row[0],
                host=row[1],
                app=row[2],
                pid=row[3],
                facility=row[4],
                severity=row[5],
                ts=_parse_iso(row[6]),
                message=row[7],
            )
            for row in self._conn.execute(sql, params)
        ]

    def stats(self) -> Dict:
        total = self.count()
        by_device = dict(self._conn.execute("SELECT source_ip, COUNT(*) FROM events GROUP BY source_ip"))
        by_severity = {}
        for severity, count in self._conn.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity"):
            from .parse import SEVERITY_NAMES

            by_severity[SEVERITY_NAMES[severity]] = count
        oldest, newest = self._conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        return {
            "total": total,
            "by_device": by_device,
            "by_severity": by_severity,
            "oldest": _parse_iso(oldest),
            "newest": _parse_iso(newest),
            "path": self.path,
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
