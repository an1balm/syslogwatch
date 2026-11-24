"""Interfaz de línea de comandos.

    syslogwatch listen  --port 514 --db eventos.db      # recoge syslog en vivo
    syslogwatch ingest  --file syslog.log --db eventos.db
    syslogwatch stats   --db eventos.db
    syslogwatch analyze --db eventos.db --format html -o informe.html
    syslogwatch demo    --db demo.db
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Sequence

from .enrich import ReferenceResolver
from .parse import parse_line
from .rank import aggregate
from .report import Report, render_html, render_markdown, to_json
from .samples import DEMO_CORPUS
from .sources import FileSource, UdpSource
from .store import Store

DEFAULT_DB = Path(os.environ.get("SYSLOGWATCH_DB", Path.home() / ".syslogwatch" / "events.db"))
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_duration(text: str) -> timedelta:
    match = _DURATION_RE.match(text or "")
    if not match:
        raise argparse.ArgumentTypeError(f"duración no válida: {text!r} (usa 30m, 24h, 7d)")
    return timedelta(**{_UNITS[match.group(2).lower()]: int(match.group(1))})


def _split_ips(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def cmd_ingest(args) -> int:
    entries = FileSource(args.file).entries(source_ip=args.source_ip)
    with Store(args.db) as store:
        added = store.add(entries)
    print(f"{len(entries)} líneas leídas, {added} nuevas en {args.db}", file=sys.stderr)
    return 0


def _make_sink(store: Store, echo: bool):
    """Devuelve (on_entry, flush): acumula en lote y escribe cada 25 mensajes."""
    buffer: List = []

    def flush() -> None:
        if buffer:
            store.add(buffer)
            buffer.clear()

    def on_entry(entry) -> None:
        buffer.append(entry)
        if echo:
            print(
                f"{entry.ts:%d-%b %H:%M:%S} {entry.device} [{entry.severity_name}] "
                f"{entry.app or '-'}: {entry.message}"
            )
        if len(buffer) >= 25:
            flush()

    return on_entry, flush


def _wait_until(deadline: Optional[float]) -> None:
    while deadline is None or time.time() < deadline:
        time.sleep(0.2)


def cmd_listen(args) -> int:
    store = Store(args.db)
    allowed = _split_ips(args.allowed)
    on_entry, flush = _make_sink(store, args.echo)

    source = UdpSource(
        port=args.port, bind=args.bind, on_entry=on_entry, allowed=allowed, forward=args.forward
    )
    source.start()
    print(
        f"Escuchando syslog UDP en {args.bind}:{source.port} -> {args.db}"
        f"{' (solo ' + ', '.join(allowed) + ')' if allowed else ''}",
        file=sys.stderr,
    )
    deadline = time.time() + args.duration if args.duration else None
    try:
        _wait_until(deadline)
    except KeyboardInterrupt:
        print("Parando por señal...", file=sys.stderr)
    finally:
        source.stop()
        flush()
        total = store.count()
        store.close()
    print(
        f"Recibidos {source.received} mensajes ({source.dropped} descartados); "
        f"{total} eventos en la base.",
        file=sys.stderr,
    )
    return 0


def cmd_stats(args) -> int:
    with Store(args.db) as store:
        stats = store.stats()
    if stats["total"] == 0:
        print(f"Sin eventos en {args.db}")
        return 0
    print(f"Base: {stats['path']}  eventos: {stats['total']}")
    print(f"Desde {stats['oldest']} hasta {stats['newest']}")
    print("Por dispositivo: " + ", ".join(f"{d}={n}" for d, n in sorted(stats["by_device"].items())))
    print("Por severidad: " + ", ".join(f"{s}={n}" for s, n in stats["by_severity"].items()))
    return 0


def cmd_demo(args) -> int:
    with Store(args.db) as store:
        entries = []
        for line in DEMO_CORPUS:
            source_ip = "192.168.1.153" if _is_covr(line) else "192.168.1.1"
            entry = parse_line(line, source_ip=source_ip)
            if entry is not None:
                entries.append(entry)
        added = store.add(entries)
    print(f"Cargados {added} eventos de demostración en {args.db}", file=sys.stderr)
    return 0


def _is_covr(line: str) -> bool:
    return "[expireEntryBlockList" in line or "br0:" in line or "wlan1: STA 42:5c" in line


def build_report(store: Store, since, top: int, use_web: bool, min_score: int, db_path) -> Report:
    entries = store.entries(since=since)
    findings = aggregate(entries)
    degraded = False
    queries: Sequence[str] = ()
    if use_web:
        cache = Path(db_path).expanduser().with_name("referencias.json")
        resolver = ReferenceResolver(cache_path=cache, min_score=min_score)
        resolver.resolve(findings)
        degraded = resolver.degraded
        queries = tuple(dict.fromkeys(resolver.queries))
    if top:
        findings = findings[:top]
    window = f"últimas {since}" if isinstance(since, timedelta) else "todo el histórico"
    return Report(
        findings=findings,
        total_events=len(entries),
        window=window,
        devices=sorted({e.device for e in entries}),
        degraded=degraded,
        queries=queries,
        stats=store.stats(),
    )


def cmd_analyze(args) -> int:
    with Store(args.db) as store:
        report = build_report(
            store,
            since=args.since,
            top=args.top,
            use_web=not args.no_web,
            min_score=args.min_score,
            db_path=args.db,
        )
    if not report.findings and report.total_events == 0:
        print(f"No hay eventos en {args.db}. Recoge primero con `listen` o carga `demo`.", file=sys.stderr)
        return 1
    renderers = {"markdown": render_markdown, "html": render_html, "json": to_json}
    output = renderers[args.format](report)
    if args.output:
        Path(args.output).expanduser().write_text(output, encoding="utf-8")
        print(f"Informe escrito en {args.output}", file=sys.stderr)
    else:
        print(output, end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="syslogwatch",
        description="Lee syslog, detecta patrones de error, los prioriza y busca referencias externas.",
    )
    subs = parser.add_subparsers(dest="command", required=True)

    listen = subs.add_parser("listen", help="escucha syslog UDP y guarda los eventos")
    listen.add_argument("--port", type=int, default=514)
    listen.add_argument("--bind", default="0.0.0.0")
    listen.add_argument("--allowed", default="", help="IPs emisoras permitidas, separadas por comas")
    listen.add_argument("--db", default=str(DEFAULT_DB))
    listen.add_argument("--duration", type=float, default=None, help="segundos antes de parar (pruebas)")
    listen.add_argument("--echo", action="store_true", help="imprime cada mensaje recibido")
    listen.add_argument(
        "--forward",
        default=None,
        help="reenvía cada línea tal cual a host:puerto (p. ej. el receptor syslog de Home Assistant)",
    )
    listen.set_defaults(func=cmd_listen)

    ingest = subs.add_parser("ingest", help="importa un fichero de log")
    ingest.add_argument("--file", required=True)
    ingest.add_argument("--source-ip", default="file")
    ingest.add_argument("--db", default=str(DEFAULT_DB))
    ingest.set_defaults(func=cmd_ingest)

    stats = subs.add_parser("stats", help="resumen de la base de eventos")
    stats.add_argument("--db", default=str(DEFAULT_DB))
    stats.set_defaults(func=cmd_stats)

    demo = subs.add_parser("demo", help="carga un corpus de ejemplo realista")
    demo.add_argument("--db", default=str(DEFAULT_DB))
    demo.set_defaults(func=cmd_demo)

    analyze = subs.add_parser("analyze", help="clasifica, prioriza y busca referencias")
    analyze.add_argument("--db", default=str(DEFAULT_DB))
    analyze.add_argument("--since", type=parse_duration, default=None, help="ventana: 1h, 24h, 7d")
    analyze.add_argument("--format", choices=("markdown", "html", "json"), default="markdown")
    analyze.add_argument("--top", type=int, default=15, help="máximo de hallazgos (0 = todos)")
    analyze.add_argument("--min-score", type=int, default=40, help="puntuación mínima para buscar fuera")
    analyze.add_argument("--no-web", action="store_true", help="no consultar fuentes externas")
    analyze.add_argument("-o", "--output", default=None)
    analyze.set_defaults(func=cmd_analyze)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except FileNotFoundError as error:
        print(f"Fichero no encontrado: {error.filename}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
