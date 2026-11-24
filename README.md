# syslogwatch

Lee el syslog de tu red, detecta patrones de error, los ordena por importancia y
explica **por qué falla cada cosa y cómo se resuelve**, con referencias externas
(Stack Exchange y GitHub) además de un catálogo curado propio.

Sin dependencias: Python ≥ 3.9 con la biblioteca estándar (`socket`, `sqlite3`,
`urllib`, `dataclasses`). Corre en un Mac, en un contenedor o en una Raspberry Pi.

## Cómo funciona

```
routers/APs ──UDP 514──▶ syslogwatch listen ──▶ SQLite (eventos crudos)
                                                    │
                    syslogwatch analyze ◀───────────┘
                            │        clasifica con el catálogo de reglas
                            │        prioriza (gravedad × patrón × frecuencia × equipo)
                            ▼
              informe markdown / HTML / JSON  +  referencias externas
```

1. **Recolecta** (`listen`, `ingest`): normaliza RFC 3164, RFC 5424 y los formatos
   propietarios que se ven en la práctica (Zyxel escribe `user.info zcmdModuleCfg:`,
   los D-Link COVR escriben `kernel:` sin nivel). Se guardan eventos crudos, nunca
   conclusiones: puedes reescribir el catálogo y reclasificar el histórico.
2. **Clasifica** (`rules.py`): 22 patrones con categoría, peso, causa y remedio.
   Lo que no coincide cae en `unclassified` y se busca fuera.
3. **Prioriza** (`rank.py`):

   ```
   score = criticalidad_equipo × (0.50 × peso_regla
                                  + 0.35 × severidad_syslog
                                  + 0.15 × frecuencia)
   ```

   Un `kernel panic` en el router pesa mucho más que un cliente Wi-Fi que se
   desasocia, aunque este último se repita 200 veces. La frecuencia sube la nota
   con `20·log2(1+n)` saturada en 100, así que no puede tapar un fallo crítico.
4. **Busca referencias** (`enrich.py`): primero las curadas de la regla; después
   la API de Stack Exchange (Server Fault, Super User, Stack Overflow) y la de
   GitHub (el mismo mensaje en el firmware o en el driver). Si la consulta larga
   no devuelve nada se reintenta con las palabras clave del mensaje real. Todo se
   cachea en disco 7 días y un fallo de red degrada el informe, nunca lo rompe.

## Instalación

Hay dos formas de usarlo:

| Forma | Cuándo | Qué necesitas |
| --- | --- | --- |
| **Add-on de Home Assistant** (recomendada) | Ya tienes `syslog_receiver` recibiendo logs | Nada: usa el receptor y el bus de eventos de HA |
| CLI / colector propio | Sin HA, o para analizar un log suelto | Que los equipos apunten su syslog a esta máquina |

### Add-on de Home Assistant

```bash
python3 scripts/build_addon.py --zip     # genera dist/syslogwatch/ y el zip
```

Copia `dist/syslogwatch/` en el directorio `/addons` de tu instalación (Samba,
SSH o el editor de ficheros), recarga la tienda de add-ons e instálalo. Aparecerá
un panel **Syslogwatch** en la barra lateral con el informe.

El add-on se suscribe por WebSocket al evento `syslog_receiver_message` con el
token del Supervisor: no abre puertos, no toca los routers y no compite con el
receptor que ya funciona. Si el add-on se para, los mensajes de ese rato no se
recuperan — el bus de HA no guarda histórico.

Opciones, requisitos y límites: [`addon/DOCS.md`](addon/DOCS.md).

### CLI

```bash
cd syslogwatch
python3 -m pip install --user -e .        # deja el comando `syslogwatch` en el PATH
syslogwatch --help
```

O sin instalar: `PYTHONPATH=src python3 -m syslogwatch.cli ...`

## Uso

```bash
# 1. Recoger syslog en vivo (puerto 514 = privilegios; usa 5514 mientras pruebas)
sudo syslogwatch listen --port 514 --bind 0.0.0.0 \
     --allowed 192.168.1.1,192.168.1.153,192.168.1.125 \
     --forward 192.168.1.219:514        # opcional: sigue alimentando HA

# 2. Importar un log ya existente
syslogwatch ingest --file /var/log/syslog --source-ip 192.168.1.1

# 3. Ver qué hay
syslogwatch stats

# 4. Informe (markdown por defecto)
syslogwatch analyze --since 24h --format html -o informe.html
syslogwatch analyze --since 7d --format json --top 5 --no-web

# 5. Probar sin datos reales
syslogwatch demo && syslogwatch analyze --format markdown
```

### Opciones de `analyze`

| Opción | Para qué |
| --- | --- |
| `--since 1h/24h/7d` | ventana de análisis (por defecto: todo) |
| `--top N` | cuántos hallazgos mostrar (0 = todos) |
| `--min-score N` | nota mínima para salir a buscar referencias (por defecto 40) |
| `--no-web` | sólo catálogo, sin red |
| `--format` | `markdown`, `html` (página autónoma) o `json` |
| `-o fichero` | escribe el informe ahí en vez de por stdout |

## Reenviar syslog desde los equipos

`listen` sustituye al receptor de Home Assistant **o** se pone delante y reenvía
con `--forward`. Lo segundo evita romper lo que ya funciona: los equipos apuntan
su syslog a la máquina del colector y éste replica cada línea a HA.

- **Zyxel EX3301-T0 (Digi):** objeto `oid=zlog`; una sola escritura con el array
  completo, `Severity: INFO` para ver errores y avisos. Sólo acepta un servidor.
- **D-Link COVR-1100:** `SetSysLogSettings` con `{"SysLog":"true","IPAddress":"<ip>"}`;
  puerto 514 fijo, sin opción de cambiarlo.

## Automatizarlo

`deploy/` trae lo necesario para dejarlo corriendo en un Mac:

- `com.syslogwatch.listen.plist` — LaunchAgent que arranca el colector al iniciar
  sesión (con `--port 514` necesita ejecutarse como root: instálalo en
  `/Library/LaunchDaemons/`).
- `com.syslogwatch.daily.plist` — genera el informe HTML cada mañana en
  `~/Documents/syslogwatch/`.

```bash
./deploy/install-macos.sh          # copia los plists y los carga
```

## Calidad

```bash
make test        # pytest
make gates       # crapper (CRAP ≤ 10), dryer (duplicación) y mutator
```

Estado medido en el sandbox (Python 3.13, verificado el 24-nov-2026):

| Gate | Resultado |
| --- | --- |
| pytest | 197 tests, cobertura 94 % |
| crapper | peor CRAP 8.1 (umbral 10) |
| dryer | 0 duplicados ≥ 0.82 |
| mutator | 195/207 mutantes muertos (94 %); 100 % en `parse`, `rank` y `rules` |
| protocolo HA | cliente WebSocket propio (RFC 6455) probado contra un servidor que habla el protocolo: handshake, fragmentación, ping/pong, cierre y reconexión |

Los 12 supervivientes están en la capa de E/S: inicializaciones de banderas
(`_running`, `degraded`), contadores que nadie observa, el `start=1` de una tabla
y comparaciones cuyo cambio no altera ninguna salida. Ahí el gate que manda es la
cobertura (≥ 92 % en todos esos módulos) y los tests de comportamiento.

## Añadir patrones

Abre `src/syslogwatch/rules.py` y añade una `Rule` **antes** de `unclassified`
(el orden es la prioridad). Un test honesto primero:

```python
def test_mi_patron_se_reconoce():
    rule = match_rule(_entry("Nov 24 15:20:00 daemon.err dhcpd: no free leases"))
    assert rule.id == "dhcp-pool-exhausted"
```

## Límites conocidos

- El nivel de severidad depende de lo que declare el emisor; los D-Link no lo
  mandan y se asume `notice`.
- El año no viene en el formato RFC 3164: se infiere (si la fecha queda más de un
  día en el futuro, se resta un año).
- Las consultas externas usan las APIs públicas; sin clave hay límite de
  peticiones (GitHub ~10/min). Con `--min-score` alto se hacen menos.
- El catálogo cubre fallos típicos de router/AP Linux (DHCP, Wi-Fi, flash, NTP,
  conntrack). Un mensaje nuevo cae en `unclassified` con enlaces de búsqueda:
  añadir la regla es parte del trabajo.
