#!/usr/bin/env bash
# Instala syslogwatch como servicio en macOS.
#
#   ./deploy/install-macos.sh                 # LaunchAgent, puerto 5514
#   ./deploy/install-macos.sh --as-root       # LaunchDaemon, puerto 514 (sudo)
#   ./deploy/install-macos.sh --forward 192.168.1.219:514
#
# Con --as-root el colector escucha en el 514 que exigen los D-Link COVR y sigue
# reenviando a Home Assistant lo que le indiques con --forward.
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
PORT=5514
FORWARD="127.0.0.1:9"   # destino inerte por defecto: el reenvío se descarta
AS_ROOT=0

while [ $# -gt 0 ]; do
    case "$1" in
        --as-root) AS_ROOT=1; PORT=514; shift ;;
        --forward) FORWARD="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        *) echo "opción desconocida: $1" >&2; exit 2 ;;
    esac
done

if ! /usr/bin/env python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "Hace falta Python 3.9 o superior" >&2
    exit 1
fi

mkdir -p "$HOME/.syslogwatch"
sed -e "s|__PROJECT__|$PROJECT|g" \
    -e "s|__HOME__|$HOME|g" \
    -e "s|__PORT__|$PORT|g" \
    -e "s|__FORWARD__|$FORWARD|g" \
    "$PROJECT/deploy/com.syslogwatch.listen.plist" > "/tmp/com.syslogwatch.listen.plist"
sed -e "s|__PROJECT__|$PROJECT|g" -e "s|__HOME__|$HOME|g" \
    "$PROJECT/deploy/com.syslogwatch.daily.plist" > "/tmp/com.syslogwatch.daily.plist"

if [ "$AS_ROOT" -eq 1 ]; then
    sudo cp "/tmp/com.syslogwatch.listen.plist" /Library/LaunchDaemons/
    sudo chown root:wheel /Library/LaunchDaemons/com.syslogwatch.listen.plist
    sudo launchctl bootout system/com.syslogwatch.listen 2>/dev/null || true
    sudo launchctl bootstrap system /Library/LaunchDaemons/com.syslogwatch.listen.plist
    echo "Colector instalado como LaunchDaemon en el puerto $PORT (reenvía a $FORWARD)"
else
    mkdir -p "$HOME/Library/LaunchAgents"
    cp "/tmp/com.syslogwatch.listen.plist" "$HOME/Library/LaunchAgents/"
    launchctl bootout "gui/$UID/com.syslogwatch.listen" 2>/dev/null || true
    launchctl bootstrap "gui/$UID" "$HOME/Library/LaunchAgents/com.syslogwatch.listen.plist"
    echo "Colector instalado como LaunchAgent en el puerto $PORT (reenvía a $FORWARD)"
fi

cp "/tmp/com.syslogwatch.daily.plist" "$HOME/Library/LaunchAgents/"
launchctl bootout "gui/$UID/com.syslogwatch.daily" 2>/dev/null || true
launchctl bootstrap "gui/$UID" "$HOME/Library/LaunchAgents/com.syslogwatch.daily.plist"

cat <<EOF

Listo. Comprobaciones:
  launchctl list | grep syslogwatch
  tail -f "$HOME/.syslogwatch/listen.err.log"
  PYTHONPATH="$PROJECT/src" python3 -m syslogwatch.cli stats

Informe diario a las 07:30 en $HOME/Documents/syslogwatch/informe.html
Para quitar el agente: launchctl bootout gui/$UID/com.syslogwatch.listen
Y si lo pusiste como daemon: sudo launchctl bootout system/com.syslogwatch.listen
EOF
