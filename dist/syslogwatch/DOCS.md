# Syslogwatch

Analiza el syslog que **ya recibe Home Assistant** (`syslog_receiver`), detecta
patrones de error, los ordena por importancia y busca referencias externas del
porqué y del cómo se resuelve.

## Qué hace

1. Se suscribe por WebSocket al evento `syslog_receiver_message` de tu HA. No
   toca routers ni ocupa el puerto 514: usa el receptor que ya funciona.
2. Guarda cada mensaje ya normalizado en SQLite (`/data/eventos.db`).
3. Cada `refresh_minutes` genera un informe en el panel lateral (Ingress) con el
   ranking de hallazgos, la causa y el remedio de cada patrón, y enlaces a
   Server Fault y GitHub.
4. `/healthz` expone contadores y el estado de la última generación (lo usa el
   watchdog del add-on).

## Requisitos

- La integración **syslog_receiver** (HACS) instalada y recibiendo mensajes.
- Los emisores deben estar en su `allowed_ips`; si no, sus mensajes se descartan
  antes de llegar al add-on y aquí no hay nada que analizar.

## Opciones

| Opción | Por defecto | Para qué |
| --- | --- | --- |
| `since_hours` | 24 | ventana de análisis |
| `top` | 15 | hallazgos que muestra el informe |
| `min_score` | 40 | nota mínima para consultar buscadores externos |
| `min_severity` | 7 | guarda sólo mensajes con severidad ≤ N (0 emerg … 7 todo) |
| `web` | true | desactívalo para no hacer ninguna petición a Internet |
| `refresh_minutes` | 30 | cada cuánto se regenera el informe |
| `event_type` | syslog_receiver_message | cámbialo si tu integración emite otro evento |
| `ingress_port` | 8099 | puerto interno del panel |

## Instalación local

Copia la carpeta que genera `scripts/build_addon.py` (`dist/syslogwatch/`) en el
directorio `/addons` de tu instalación (Samba, SSH o el editor de ficheros) y
recarga la tienda de add-ons. Aparecerá en la sección de add-ons locales.

## Limitaciones

- Los mensajes que llegan mientras el add-on está parado no se recuperan: el bus
  de eventos de HA no guarda histórico.
- Si HA reinicia, el add-on reconecta solo (espera creciente hasta 30 s) y deja
  constancia en el log.
- Sin clave de API, los buscadores públicos limitan peticiones (GitHub ~10/min);
  cuando se agota, el informe se marca con el aviso de búsqueda degradada.
