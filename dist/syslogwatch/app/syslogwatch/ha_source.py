"""Fuente de eventos de Home Assistant por WebSocket.

Es lo que usa el add-on: se conecta al Core, se autentica con el token del
Supervisor y se suscribe a `syslog_receiver_message`, el evento que emite la
integración `syslog_receiver` por cada mensaje recibido. Así no hay que tocar
ningún router ni duplicar el receptor.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Sequence
from urllib.parse import urlsplit

from .parse import SyslogEntry, parse_line
from .ws import HandshakeError, WebSocket, WebSocketError

DEFAULT_EVENT = "syslog_receiver_message"


class HaError(Exception):
    """Fallo hablando con Home Assistant."""


class AuthError(HaError):
    """El token no vale (o el usuario lo revocó)."""


class SubscriptionError(HaError):
    """HA rechazó la suscripción al evento."""


@dataclass(frozen=True)
class HaEvent:
    message: str
    source_ip: str
    severity: Optional[int] = None
    time_fired: Optional[str] = None


def derive_ws_url(base_url: str) -> str:
    """`http://supervisor/core` → `ws://supervisor/core/websocket`."""
    parts = urlsplit(base_url.rstrip("/"))
    if parts.scheme not in ("http", "ws"):
        raise HandshakeError(
            f"esquema no soportado: {parts.scheme} (usa http://, p. ej. http://supervisor/core)"
        )
    host = parts.hostname or "127.0.0.1"
    netloc = f"{host}:{parts.port}" if parts.port else host
    path = (parts.path or "").rstrip("/") + "/api/websocket"
    return f"ws://{netloc}{path}"


def _severity_value(raw) -> Optional[int]:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int) and 0 <= raw <= 7:
        return raw
    return None


def event_to_ha_event(event: Dict) -> Optional[HaEvent]:
    data = (event or {}).get("data") or {}
    message = data.get("message")
    if not message:
        return None
    return HaEvent(
        message=str(message),
        source_ip=str(data.get("source_ip") or "desconocido"),
        severity=_severity_value(data.get("severity")),
        time_fired=event.get("time_fired"),
    )


def event_to_entry(event: Dict, now=None) -> Optional[SyslogEntry]:
    ha_event = event_to_ha_event(event)
    if ha_event is None:
        return None
    entry = parse_line(ha_event.message, source_ip=ha_event.source_ip, now=now)
    if entry is None or ha_event.severity is None:
        return entry
    from dataclasses import replace

    return replace(entry, severity=ha_event.severity)


class HomeAssistantStream:
    """Sesión autenticada contra HA; una instancia = una conexión."""

    def __init__(
        self,
        url: str,
        token: str,
        event_type: str = DEFAULT_EVENT,
        timeout: float = 15.0,
        first_id: int = 1,
    ):
        self.url = url
        self.token = token
        self.event_type = event_type
        self.timeout = timeout
        self.first_id = first_id
        self.ws: Optional[WebSocket] = None
        self._next_id = first_id

    # -- ciclo de vida ---------------------------------------------------
    def open(self) -> "HomeAssistantStream":
        self.ws = WebSocket.connect(derive_ws_url(self.url), timeout=self.timeout)
        self._authenticate()
        self.subscribe()
        return self

    def close(self) -> None:
        if self.ws is not None:
            self.ws.close()
            self.ws = None

    def __enter__(self) -> "HomeAssistantStream":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    # -- protocolo -------------------------------------------------------
    def _next(self) -> dict:
        if self.ws is None:
            raise HaError("conexión no abierta")
        kind, payload = self.ws.recv()
        if kind == "close":
            raise WebSocketError("HA cerró la conexión")
        return json.loads(payload.decode("utf-8"))

    def _send(self, message: Dict) -> int:
        self._next_id += 1
        message = dict(message, id=self._next_id)
        self.ws.send_text(json.dumps(message))
        return self._next_id

    def _authenticate(self) -> dict:
        first = self._next()
        if first.get("type") == "auth_ok":
            return first
        if first.get("type") != "auth_required":
            raise HaError(f"mensaje inesperado de HA: {first.get('type')}")
        self.ws.send_text(json.dumps({"type": "auth", "access_token": self.token}))
        reply = self._next()
        if reply.get("type") == "auth_invalid":
            raise AuthError(reply.get("message") or "token rechazado")
        if reply.get("type") != "auth_ok":
            raise HaError(f"respuesta de autenticación rara: {reply.get('type')}")
        return reply

    def subscribe(self) -> dict:
        message_id = self._send({"type": "subscribe_events", "event_type": self.event_type})
        while True:
            reply = self._next()
            if reply.get("type") == "pong":
                continue
            if reply.get("type") == "result" and reply.get("id") == message_id:
                if not reply.get("success"):
                    error = reply.get("error") or {}
                    raise SubscriptionError(error.get("message") or "suscripción rechazada")
                return reply
            # eventos que lleguen antes del ack: se descartan, no se pierde nada real
            # porque HA no envía eventos hasta confirmar la suscripción.

    def events(self, max_events: Optional[int] = None) -> Iterator[Dict]:
        """Genera los `event` de HA que llegan por la suscripción."""
        served = 0
        while max_events is None or served < max_events:
            message = self._next()
            kind = message.get("type")
            if kind == "pong":
                continue
            if kind == "event":
                served += 1
                yield message.get("event") or {}
                continue
            if kind == "result":
                continue
            raise HaError(f"mensaje no esperado: {kind}")


def _consume(stream, on_entry, stop, max_events: Optional[int]) -> None:
    """Traslada los eventos a entradas y las entrega; sale si piden parar."""
    for event in stream.events(max_events=max_events):
        entry = event_to_entry(event)
        if entry is not None:
            on_entry(entry)
        if stop.is_set():
            return


def _delay(attempt: int, backoff: Sequence[float]) -> float:
    return backoff[min(attempt, len(backoff) - 1)]


def run_stream(
    url: str,
    token: str,
    on_entry: Callable[[SyslogEntry], None],
    event_type: str = DEFAULT_EVENT,
    stop: Optional[threading.Event] = None,
    backoff: Sequence[float] = (1, 2, 5, 10, 30),
    max_events: Optional[int] = None,
    log: Optional[Callable[[str], None]] = None,
    stream_factory=HomeAssistantStream,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Bucle con reconexión. Devuelve cuántas veces se reconectó."""
    stop = stop or threading.Event()
    say = log or (lambda message: None)
    reconnects = 0
    attempt = 0

    while not stop.is_set():
        try:
            with stream_factory(url, token, event_type=event_type) as stream:
                say("conectado a Home Assistant")
                attempt = 0
                _consume(stream, on_entry, stop, max_events)
        except AuthError:
            say("token rechazado: revisa la opción del add-on; no se reintenta")
            raise
        except (HaError, WebSocketError, OSError, json.JSONDecodeError) as error:
            say(f"conexión interrumpida ({error}); reintentando")
        if stop.is_set() or max_events is not None:
            break
        reconnects += 1
        sleep(_delay(attempt, backoff))
        attempt += 1
    return reconnects
