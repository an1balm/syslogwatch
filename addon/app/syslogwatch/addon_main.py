"""Arranque del add-on de Home Assistant: ingesta, informes y panel de Ingress.

No es un `listen` UDP: aquí los mensajes llegan por el bus de eventos de HA
(`syslog_receiver_message`), así que el add-on se apoya en el receptor que ya
funciona en la instalación.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, Optional
from urllib.parse import urlsplit

from .enrich import ReferenceResolver
from .ha_source import DEFAULT_EVENT, run_stream
from .parse import SyslogEntry
from .rank import aggregate
from .rules import RULES
from .report import Report, render_html, render_markdown
from .store import Store

VERSION = "0.1.5"

SUPERVISOR_URL = "http://supervisor/core"
SUPERVISOR_TOKEN_ENV = "SUPERVISOR_TOKEN"
OPTIONS_PATH = Path("/data/options.json")


class OptionsError(Exception):
    """Opción del add-on inválida."""


def _as_int(value, name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise OptionsError(f"{name} debe ser un número entero, no {value!r}")
    if not minimum <= number <= maximum:
        raise OptionsError(f"{name} fuera de rango ({minimum}-{maximum}): {number}")
    return number


def _as_bool(value, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    raise OptionsError(f"{name} debe ser true o false, no {value!r}")


@dataclass(frozen=True)
class Options:
    since_hours: int = 24
    top: int = 15
    min_score: int = 40
    min_severity: int = 7
    web: bool = True
    refresh_minutes: int = 30
    event_type: str = DEFAULT_EVENT
    ingress_port: int = 8099
    data_dir: str = "/data"

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "eventos.db"

    @property
    def report_path(self) -> Path:
        return Path(self.data_dir) / "informe.html"


def parse_options(raw: Optional[dict] = None) -> Options:
    raw = dict(raw or {})
    known = {field.name for field in Options.__dataclass_fields__.values()}
    unknown = set(raw) - known
    for name in unknown:
        raw.pop(name)  # HA puede añadir metadatos; no rompen nada
    options = Options(
        since_hours=_as_int(raw.get("since_hours", 24), "since_hours", 1, 720),
        top=_as_int(raw.get("top", 15), "top", 1, 100),
        min_score=_as_int(raw.get("min_score", 40), "min_score", 0, 100),
        min_severity=_as_int(raw.get("min_severity", 7), "min_severity", 0, 7),
        web=_as_bool(raw.get("web", True), "web"),
        refresh_minutes=_as_int(raw.get("refresh_minutes", 30), "refresh_minutes", 1, 1440),
        event_type=str(raw.get("event_type") or DEFAULT_EVENT),
        ingress_port=_as_int(raw.get("ingress_port", 8099), "ingress_port", 1024, 65535),
        data_dir=str(raw.get("data_dir") or "/data"),
    )
    return options


def load_options(path: Optional[Path] = None) -> Options:
    path = path or OPTIONS_PATH
    if not path.exists():
        return Options()
    try:
        return parse_options(json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, TypeError) as error:
        raise OptionsError(f"no se pudo leer {path}: {error}")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment


class ReportService:
    """Mantiene el informe en disco y lo regenera bajo demanda o por temporizador."""

    def __init__(self, store: Store, options: Options, logger: Callable[[str], None] = print):
        self.store = store
        self.options = options
        self.logger = logger
        self.last_built: Optional[datetime] = None
        self.last_findings = 0
        self.top_finding: Optional[str] = None
        self.last_error: Optional[str] = None
        self.degraded = False
        self._lock = threading.Lock()

    def build(self) -> Report:
        with self._lock:
            entries = self.store.entries(since=timedelta(hours=self.options.since_hours))
            findings = aggregate(entries)
            if self.options.web:
                cache = Path(self.options.data_dir) / "referencias.json"
                resolver = ReferenceResolver(cache_path=cache, min_score=self.options.min_score)
                resolver.resolve(findings)
                self.degraded = resolver.degraded
            report = Report(
                findings=findings[: self.options.top],
                total_events=len(entries),
                window=f"últimas {self.options.since_hours} h",
                devices=sorted({entry.device for entry in entries}),
                degraded=self.degraded,
            )
            self.last_built = datetime.now()
            self.last_findings = len(report.findings)
            self.top_finding = (
                f"{report.findings[0].rule.title} ({report.findings[0].score})"
                if report.findings else None
            )
            return report

    def refresh(self) -> str:
        try:
            report = self.build()
            html = render_html(report)
            self.options.report_path.write_text(html, encoding="utf-8")
            (Path(self.options.data_dir) / "informe.md").write_text(render_markdown(report), encoding="utf-8")
            self.last_error = None
            self.logger(f"informe regenerado: {len(report.findings)} hallazgos, {report.total_events} eventos")
            return html
        except Exception as error:  # noqa: BLE001 - el add-on no puede morir por un informe
            self.last_error = str(error)
            self.logger(f"error generando el informe: {error}")
            raise

    def read_html(self) -> str:
        try:
            return self.options.report_path.read_text(encoding="utf-8")
        except OSError:
            return "<!DOCTYPE html><html lang=es><body><p>Generando el primer informe…</p></body></html>"

    def run_periodic(self, stop: threading.Event, wait: Optional[Callable[[float], None]] = None) -> None:
        """Regenera cada `refresh_minutes`. El primer informe lo hace `main`."""
        sleep = wait or stop.wait
        while not stop.is_set():
            sleep(self.options.refresh_minutes * 60)
            if stop.is_set():
                break
            try:
                self.refresh()
            except Exception:  # noqa: BLE001 - ya queda registrado en last_error
                pass

    def health(self) -> Dict:
        stats = self.store.stats()
        return {
            "ok": self.last_error is None,
            "version": VERSION,
            "patrones": len(RULES),
            "eventos": stats["total"],
            "por_dispositivo": stats["by_device"],
            "ultimo_mensaje": stats["newest"].isoformat(sep=" ") if stats["newest"] else None,
            "hallazgos": self.last_findings,
            "prioridad_maxima": self.top_finding,
            "informe_generado": self.last_built.isoformat(sep=" ") if self.last_built else None,
            "ultimo_error": self.last_error,
            "busqueda_externa_degradada": self.degraded,
            "ventana_horas": self.options.since_hours,
        }


class IngressHandler(BaseHTTPRequestHandler):
    service: ReportService = None  # lo inyecta build_server
    server_version = "syslogwatch"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silencio: no ensuciar el log del add-on
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - nombre impuesto por BaseHTTPRequestHandler
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/healthz":
            payload = json.dumps(self.service.health(), ensure_ascii=False, indent=2)
            self._send(200, payload.encode("utf-8"), "application/json; charset=utf-8")
            return
        if path == "/regenerar":
            try:
                self.service.refresh()
            except Exception as error:  # noqa: BLE001
                self._send(500, str(error).encode("utf-8"), "text/plain; charset=utf-8")
                return
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in ("/", "/index.html", "/informe.html"):
            self._send(200, self.service.read_html().encode("utf-8"), "text/html; charset=utf-8")
            return
        self._send(404, b"no encontrado", "text/plain; charset=utf-8")


def build_server(service: ReportService, port: int, bind: str = "0.0.0.0") -> ThreadingHTTPServer:
    handler = type("BoundIngressHandler", (IngressHandler,), {"service": service})
    server = ThreadingHTTPServer((bind, port), handler)
    server.daemon_threads = True
    return server


def severity_allowed(entry: SyslogEntry, min_severity: int) -> bool:
    """0 = sólo emergencias, 7 = todo."""
    return entry.severity <= min_severity


def start_ingest(
    store: Store,
    options: Options,
    stop: threading.Event,
    logger: Callable[[str], None],
    token: Optional[str] = None,
    thread_factory=threading.Thread,
) -> Optional[threading.Thread]:
    """Lanza la suscripción al bus de HA. Sin token no hay nada que escuchar."""
    token = token if token is not None else os.environ.get(SUPERVISOR_TOKEN_ENV, "")
    if not token:
        logger("sin SUPERVISOR_TOKEN: el add-on no puede leer el bus de Home Assistant")
        return None

    def on_entry(entry: SyslogEntry) -> None:
        if severity_allowed(entry, options.min_severity):
            store.add([entry])

    thread = thread_factory(
        target=run_stream,
        args=(SUPERVISOR_URL, token),
        kwargs={"on_entry": on_entry, "event_type": options.event_type, "stop": stop, "log": logger},
        name="ha-stream",
        daemon=True,
    )
    thread.start()
    return thread


def main() -> int:  # pragma: no cover - lo arranca el contenedor
    logger = lambda message: print(f"[syslogwatch {VERSION}] {message}", flush=True)  # noqa: E731
    options = load_options()
    Path(options.data_dir).mkdir(parents=True, exist_ok=True)
    store = Store(options.db_path)
    service = ReportService(store, options, logger=logger)
    stop = threading.Event()

    start_ingest(store, options, stop, logger)
    threading.Thread(target=service.run_periodic, args=(stop,), name="reports", daemon=True).start()
    service.refresh()

    server = build_server(service, options.ingress_port)
    logger(f"panel en el puerto {options.ingress_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
        store.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
