"""Catálogo de patrones: qué significa cada fallo y cómo se resuelve.

Cada regla lleva el porqué, el remedio y referencias externas curadas (además
de la consulta que se lanza contra buscadores/foros para ampliar). El orden de
la lista es la prioridad de coincidencia: primero lo que rompe el servicio,
último el ruido conocido.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .parse import SyslogEntry


@dataclass(frozen=True)
class Ref:
    title: str
    url: str


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: str
    category: str
    weight: int
    cause: str
    fix: str
    query: str
    refs: Tuple[Ref, ...] = field(default_factory=tuple)

    def matches(self, entry: SyslogEntry) -> bool:
        haystack = f"{entry.app or ''} {entry.message}"
        return re.search(self.pattern, haystack, re.IGNORECASE) is not None


RULES: Tuple[Rule, ...] = (
    Rule(
        id="kernel-panic",
        title="Kernel panic / bloqueo del sistema",
        pattern=r"kernel panic|Oops:|BUG: (unable to handle|soft lockup)|general protection fault",
        category="hardware",
        weight=100,
        cause=(
            "El kernel ha encontrado un estado imposible y se detiene: casi siempre memoria "
            "defectuosa, un driver inestable o un fallo de alimentación."
        ),
        fix=(
            "Anota la dirección y el módulo del traceback, actualiza el firmware del equipo y, si "
            "se repite en el mismo módulo, descarta ese driver/versión. Si el equipo se reinicia "
            "solo, revisa la fuente de alimentación antes que el software."
        ),
        query="kernel panic general protection fault router firmware",
        refs=(
            Ref("Documentación del kernel: informe de fallos", "https://docs.kernel.org/admin-guide/bug-hunting.html"),
            Ref("Kernel oops y cómo leerlo", "https://en.wikipedia.org/wiki/Linux_kernel_oops"),
        ),
    ),
    Rule(
        id="kernel-out-of-memory",
        title="Sin memoria: el kernel mata procesos",
        pattern=r"out of memory|oom[-_ ]?killer|killed process \d+",
        category="recursos",
        weight=95,
        cause=(
            "La memoria libre se ha agotado y el OOM killer ha sacrificado un proceso. Suele venir "
            "de una tabla de conexiones o de un log que crece sin límite."
        ),
        fix=(
            "Reduce `nf_conntrack_max` si la tabla es la causa, limita el tamaño de los logs y "
            "reinicia el servicio que crece. Si es recurrente con el mismo proceso, actualiza el "
            "firmware: es una fuga conocida del binario."
        ),
        query="out of memory oom-killer router low memory fix",
        refs=(
            Ref("Kernel: gestión de memoria y OOM", "https://docs.kernel.org/admin-guide/mm/concepts.html"),
        ),
    ),
    Rule(
        id="kernel-hardware-error",
        title="Error de hardware corregido o detectado",
        pattern=r"hardware error|machine check|PCIe bus error|severity=corrected|ECC error|MCE",
        category="hardware",
        weight=92,
        cause=(
            "El chipset ha reportado un error de bus o de memoria. `corrected` significa que se ha "
            "recuperado, pero es el aviso previo a un fallo mayor."
        ),
        fix=(
            "Vigila la frecuencia: uno aislado se ignora, varios por hora apuntan a memoria, cable "
            "SATA o alimentación. Revisa la temperatura y la fuente; si el equipo tiene garantía, "
            "abre incidencia con estos logs."
        ),
        query="PCIe bus error severity corrected hardware error fix",
        refs=(
            Ref("Kernel: RAS y errores de máquina", "https://docs.kernel.org/admin-guide/ras.html"),
        ),
    ),
    Rule(
        id="disk-io-error",
        title="Error de escritura/lectura en flash o disco",
        pattern=r"I/O error|EXT4-fs error|read-only file system|libmtd|mtd.*(erase|write).*(fail|error)|jffs2.*error",
        category="hardware",
        weight=88,
        cause=(
            "El almacenamiento persistente falla al escribir: flash NAND desgastada, sector dañado "
            "o un `erase` interrumpido por un corte de luz."
        ),
        fix=(
            "Copia la configuración del equipo ahora. Si el sistema se ha montado en solo lectura, "
            "un reinicio lo recupera temporalmente; si el aviso se repite, la flash está al final de "
            "su vida y toca reemplazar el equipo."
        ),
        query="mtd erase failed jffs2 I/O error router flash",
        refs=(
            Ref("OpenWrt: NAND/flash y errores de escritura", "https://openwrt.org/docs/techref/flash.layout"),
        ),
    ),
    Rule(
        id="watchdog-reboot",
        title="Reinicio por watchdog",
        pattern=r"watchdog|reset reason|unexpected (reboot|reset)|rebooting after",
        category="estabilidad",
        weight=85,
        cause=(
            "El hardware ha reiniciado el equipo porque el software dejó de responder al temporizador "
            "de vigilancia."
        ),
        fix=(
            "Cruza la hora del reinicio con cortes de luz y con los logs previos (OOM, panic). Si no "
            "hay causa visible, actualiza el firmware: es el camino habitual de estos cuelgues."
        ),
        query="router watchdog reset reason unexpected reboot firmware",
        refs=(),
    ),
    Rule(
        id="dhcp-pool-exhausted",
        title="Pool DHCP agotado: clientes sin IP",
        pattern=r"no free leases|no leases left|pool .*exhaust|no more addresses available|address pool is full",
        category="dhcp",
        weight=88,
        cause=(
            "Todas las direcciones del rango están concedidas. Los clientes nuevos se quedan sin "
            "respuesta y acaban en 169.254.x.x (APIPA), sin puerta de enlace ni DNS."
        ),
        fix=(
            "Amplía el rango del pool, acorta el lease time (`LeaseTime`) o borra leases huérfanos. "
            "Antes de ampliar, comprueba que el nuevo rango no pisa direcciones estáticas."
        ),
        query="dhcpd no free leases pool exhausted how to fix",
        refs=(
            Ref("RFC 3927: direcciones link-local (APIPA)", "https://datatracker.ietf.org/doc/html/rfc3927"),
            Ref("ISC dhcpd.conf: rangos y lease time", "https://man7.org/linux/man-pages/man5/dhcpd.conf.5.html"),
        ),
    ),
    Rule(
        id="arp-ip-conflict",
        title="Conflicto de IP / dirección duplicada",
        pattern=r"duplicate address|IP conflict|arp.*(conflict|collision)|DHCP.*conflict|address .*in use.*\(?conflict",
        category="dhcp",
        weight=82,
        cause=(
            "Dos equipos usan la misma IPv4: una reserva que no coincide con la IP fija del cliente, "
            "o un rango DHCP que incluye direcciones estáticas."
        ),
        fix=(
            "Identifica el MAC dueño de la IP y pasa el cliente a DHCP con reserva por MAC, o saca "
            "esa IP del pool. Nunca las dos cosas a la vez con direcciones distintas."
        ),
        query="duplicate address detection IP conflict same subnet fix",
        refs=(
            Ref("RFC 5227: detección de direcciones duplicadas", "https://datatracker.ietf.org/doc/html/rfc5227"),
        ),
    ),
    Rule(
        id="dhcp-offer-failed",
        title="DHCP no consigue asignar dirección",
        pattern=r"no address available|cannot assign|failed to (allocate|assign).*address|dhcp.*(timeout|no response)",
        category="dhcp",
        weight=80,
        cause=(
            "El servidor recibe la petición pero no puede responder con una concesión: pool lleno, "
            "rango mal definido o un cliente pidiendo una IP concreta que no le corresponde."
        ),
        fix=(
            "Revisa inicio/fin del rango y que el servidor esté en el mismo segmento que el cliente. "
            "Fuerza una renovación en el cliente tras corregirlo."
        ),
        query="dhcp server no address available client gets APIPA 169.254",
        refs=(),
    ),
    Rule(
        id="dns-resolver-down",
        title="Resolutor DNS caído o sin respuesta",
        pattern=r"dnsmasq.*(fail|error|exiting|cannot)|cannot resolve|SERVFAIL|dns.*refused|no servers found",
        category="dns",
        weight=80,
        cause=(
            "El resolutor local no arranca o no alcanza a los reenviadores. Todo el que dependa de él "
            "queda sin nombres, aunque la LAN siga funcionando."
        ),
        fix=(
            "Verifica que el puerto 53 está libre y que el fichero de configuración es válido "
            "(`dnsmasq --test`). Si el resolutor vive en un add-on, comprueba que escucha en la "
            "interfaz correcta tras un cambio de red."
        ),
        query="dnsmasq failed to start cannot resolve SERVFAIL fix",
        refs=(
            Ref("dnsmasq: manual completo", "https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html"),
        ),
    ),
    Rule(
        id="wifi-handshake-failed",
        title="Fallo de handshake WPA (clave o firmware)",
        pattern=r"4-?way handshake (failed|timeout)|pre-shared key may be incorrect|WPA.*(failed|mismatch)|invalid (PSK|MIC)",
        category="wifi",
        weight=70,
        cause=(
            "El cliente y el AP no completan el intercambio de claves: contraseña mal escrita, "
            "mezcla WPA2/WPA3 o un cliente antiguo que no soporta el modo del AP."
        ),
        fix=(
            "Baja el AP a WPA2-PSK (AES) si hay clientes antiguos, revisa la clave carácter a "
            "carácter y separa WPA2/WPA3 en SSID distintos mientras convivan dispositivos viejos."
        ),
        query="hostapd 4-way handshake failed pre-shared key may be incorrect WPA2 WPA3",
        refs=(
            Ref("hostapd.conf: opciones de seguridad", "https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf"),
        ),
    ),
    Rule(
        id="wifi-auth-failed",
        title="Fallos de autenticación repetidos",
        pattern=r"(authentication|login) (failed|rejected|failure)|invalid user|too many (auth|failed)|brute ?force",
        category="seguridad",
        weight=78,
        cause=(
            "Alguien (o algo) intenta entrar sin credenciales válidas de forma repetida: un cliente "
            "con clave vieja en bucle, o un escaneo desde Internet."
        ),
        fix=(
            "Si es interno, actualiza la clave en ese cliente. Si viene de la WAN, desactiva la "
            "administración remota y revisa el port forwarding; añade bloqueo por IP tras N fallos."
        ),
        query="router repeated authentication failures brute force login mitigate",
        refs=(),
    ),
    Rule(
        id="conntrack-full",
        title="Tabla de conexiones llena (paquetes descartados)",
        pattern=r"nf_conntrack: table full|conntrack.*full|ip_conntrack",
        category="red",
        weight=72,
        cause=(
            "La tabla de seguimiento de conexiones está al máximo y el router empieza a tirar "
            "paquetes nuevos: navegación lenta y caídas intermitentes."
        ),
        fix=(
            "Sube `net.netfilter.nf_conntrack_max` y baja los timeouts establecidos; si el router no "
            "lo permite, reduce el número de conexiones (P2P, cámaras con reconexión agresiva)."
        ),
        query="nf_conntrack table full dropping packet increase nf_conntrack_max",
        refs=(
            Ref("Kernel: parámetros de nf_conntrack", "https://docs.kernel.org/networking/nf_conntrack-sysctl.html"),
        ),
    ),
    Rule(
        id="wifi-dfs-radar",
        title="Cambio de canal por detección de radar (DFS)",
        pattern=r"radar detected|DFS|channel switch announced|CAC (started|completed)",
        category="wifi",
        weight=60,
        cause=(
            "El AP opera en una banda DFS (5 GHz 52-140) y ha detectado un radar meteorológico o "
            "aéreo: está obligado a abandonar el canal en segundos."
        ),
        fix=(
            "Si las desconexiones coinciden con estos avisos, fija el 5 GHz en canales no DFS "
            "(36-48, 149-165) o desactiva 160 MHz, que casi siempre cae en DFS."
        ),
        query="wifi DFS radar detected channel switch 5GHz disconnects fix",
        refs=(),
    ),
    Rule(
        id="link-flap",
        title="Enlace Ethernet que sube y baja",
        pattern=r"link (is )?(down|up)|carrier (lost|down)|PHY.*down|port \d+ (down|up)|eth\d.*(down|up)",
        category="red",
        weight=65,
        cause="El enlace físico se cae y vuelve: cable dañado, conector suelto o negociación inestable.",
        fix=(
            "Sustituye el cable y prueba otro puerto. Si solo pasa con un equipo, fija la velocidad "
            "y dúplex en ambos extremos para descartar autonegociación defectuosa."
        ),
        query="ethernet link down carrier lost flapping cable duplex mismatch",
        refs=(),
    ),
    Rule(
        id="packet-drop",
        title="Descarte de paquetes por sobrecarga",
        pattern=r"dropping packet|overrun|buffer overflow|queue full|tail drop",
        category="red",
        weight=55,
        cause=(
            "Las colas del interfaz se llenan antes de poder transmitir: un cliente satura el enlace "
            "o el equipo no da abasto."
        ),
        fix=(
            "Mide quién satura (contadores por interfaz) y aplica QoS o límite por cliente; si el "
            "descarte ocurre en reposo, el equipo está por debajo de la carga que se le pide."
        ),
        query="interface dropping packets overrun queue full QoS fix",
        refs=(),
    ),
    Rule(
        id="ntp-desync",
        title="Reloj desincronizado (NTP)",
        pattern=r"ntp.*(no server|unreachable|fail|step|adjust)|time (sync|server).*(fail|error)|stratum",
        category="servicios",
        weight=50,
        cause=(
            "El equipo no alcanza ningún servidor NTP, así que su reloj deriva: los logs pierden "
            "sentido y los certificados pueden fallar."
        ),
        fix=(
            "Apunta el cliente NTP a una IP de la LAN (o al propio router) y comprueba que la regla "
            "de firewall no bloquea UDP 123."
        ),
        query="ntp no server suitable found synchronisation unsynchronised fix",
        refs=(),
    ),
    Rule(
        id="cloud-disconnect",
        title="Agente cloud/MQTT desconectado",
        pattern=r"cloud.*(disconnect|offline|fail|lost|retrying)|mqtt.*(disconnect|fail|refused)|agent.*offline",
        category="servicios",
        weight=45,
        cause=(
            "El equipo ha perdido la conexión con su plataforma: sin salida a Internet, DNS roto o "
            "credenciales caducadas."
        ),
        fix=(
            "Comprueba salida a Internet y DNS del equipo, y vuelve a enlazar la cuenta en su app si "
            "las credenciales han caducado."
        ),
        query="mqtt client disconnects cloud agent offline reconnect fix",
        refs=(),
    ),
    Rule(
        id="wifi-client-roam",
        title="Cliente Wi-Fi asociado/desasociado (roaming normal)",
        pattern=r"deauth|disassociat|STA .* (left|removed|associated)|associated with .*ssid",
        category="wifi",
        weight=35,
        cause=(
            "Un cliente cambia de nodo o se apaga. Es normal de forma aislada; solo importa si se "
            "repite cada minuto con el mismo dispositivo."
        ),
        fix=(
            "Si el mismo MAC entra y sale constantemente, tiene cobertura límite: acerca un nodo o "
            "fija ese cliente a la banda/nodo con mejor señal."
        ),
        query="wifi client constantly deauthenticated roaming sticky client fix",
        refs=(),
    ),
    Rule(
        id="crond-task",
        title="Tarea programada ejecutada por cron",
        pattern=r"crond?\s+(USER|cron)\s+\w+.*\b(cmd|command)\b",
        category="ruido",
        weight=6,
        cause=(
            "El planificador del equipo lanza un script de mantenimiento (rtspStream.sh, "
            "quarterHour.sh…). Es la prueba de que cron funciona."
        ),
        fix=(
            "Nada, salvo que veas scripts que no reconoces: entonces conviene revisar "
            "/etc/crontabs/root del equipo por si el firmware trae algo que no esperabas."
        ),
        query="busybox crond USER root pid cmd scheduled script log",
        refs=(),
    ),
    Rule(
        id="wifi-roaming-trigger",
        title="El AP fuerza el roaming de un cliente (señal)",
        pattern=r"Triggered [0-9A-Fa-f:]{17}.*rssi=(-?\d+).*rssi=(-?\d+)",
        category="wifi",
        weight=30,
        cause=(
            "El punto de acceso decide mover al cliente a otra banda o nodo porque su señal "
            "baja del umbral (last_rssi) y encuentra otra mejor (current_rssi)."
        ),
        fix=(
            "Normal mientras el cliente se mueve. Si pasa cada pocos minutos con un equipo "
            "fijo, está entre dos nodos: fija ese cliente a la banda de 2,4 GHz o acerca un AP."
        ),
        query="wifi AP triggered client rssi roaming steering threshold",
        refs=(),
    ),
    Rule(
        id="config-save-ok",
        title="Guardado de configuración correcto",
        pattern=r"(saving|saved) config|configuration saved|config.*saved ok",
        category="ruido",
        weight=5,
        cause="El equipo ha persistido su configuración sin errores.",
        fix="Nada que hacer: es la señal de que un cambio se aplicó.",
        query="router config saved ok syslog",
        refs=(),
    ),
    Rule(
        id="zcmd-noise",
        title="Ruido interno del router (zcmdModuleCfg / radvd)",
        pattern=r"zcmd[A-Za-z]*|beRaInfo|beIpIfaceStats|radvd.*received RS|mapping parameter",
        category="ruido",
        weight=8,
        cause=(
            "Traza interna del demonio de configuración del router cuando se le consulta. No es un "
            "fallo y no requiere acción."
        ),
        fix=(
            "Si molesta, sube la severidad mínima del receptor de syslog a `warning` o silencia la "
            "categoría en el router."
        ),
        query="zcmdModuleCfg syslog noise disable",
        refs=(),
    ),
    Rule(
        id="bridge-port-state",
        title="Cambio de estado de un puerto del bridge",
        pattern=r"br\d+: port \d+\(.*?\) entered (forwarding|disabled|blocking) state",
        category="ruido",
        weight=8,
        cause=(
            "El bridge de Linux ha cambiado el estado de un puerto al asociarse o irse un cliente "
            "Wi-Fi. Es la traza de un roaming normal."
        ),
        fix=(
            "Nada si es puntual. Si el mismo puerto oscila cada pocos segundos, el cliente tiene "
            "cobertura límite o el nodo está reiniciándose."
        ),
        query="br0 port entered forwarding state wifi",
        refs=(),
    ),
    Rule(
        id="blocklist-expire",
        title="Caducidad de la lista de bloqueo Wi-Fi",
        pattern=r"expireEntryBlockList|BLOCK LIST STA EXPIRES",
        category="ruido",
        weight=6,
        cause="El AP purga entradas de su lista temporal de bloqueo de clientes. Rutina.",
        fix="Nada que hacer; si aparece un MAC de un equipo propio, el AP lo bloqueó por reintentos fallidos.",
        query="wifi block list sta expires dlink meaning",
        refs=(),
    ),
)

UNCLASSIFIED = Rule(
    id="unclassified",
    title="Mensaje sin patrón conocido",
    pattern=r".*",
    category="desconocido",
    weight=50,
    cause="No hay patrón curado para este mensaje: se busca en foros y en el código del firmware.",
    fix=(
        "Usa las referencias externas para localizarlo; si se repite, añade una regla nueva al "
        "catálogo con su causa y su remedio."
    ),
    query="",
)


def match_rule(entry: SyslogEntry) -> Rule:
    """Primera regla del catálogo que coincide, o la de desconocidos."""
    for rule in RULES:
        if rule.matches(entry):
            return rule
    return UNCLASSIFIED


def rule_by_id(rule_id: str) -> Optional[Rule]:
    for rule in RULES:
        if rule.id == rule_id:
            return rule
    return UNCLASSIFIED if rule_id == UNCLASSIFIED.id else None
