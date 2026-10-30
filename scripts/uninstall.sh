#!/usr/bin/env bash
# Caddy Sentinel entfernen (systemd-Installation)
#
#   sudo caddy-sentinel-uninstall           # Programme entfernen, Daten behalten
#   sudo caddy-sentinel-uninstall --purge   # auch Datenbank und Sicherungen löschen
#
# Caddyfile und Zertifikate bleiben immer erhalten. War vorher ein
# Distributions-Caddy installiert, läuft danach wieder dieser.
set -euo pipefail
PURGE=0
YES=0
for a in "$@"; do
	case "$a" in
	--purge) PURGE=1 ;;
	-y | --yes) YES=1 ;;
	-h | --help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "Unbekannte Option: $a" >&2; exit 2 ;;
	esac
done
[ "$(id -u)" = 0 ] || { echo "Bitte mit sudo ausführen" >&2; exit 1; }
if [ "$YES" = 0 ] && [ -t 0 ]; then
	read -r -p "Caddy Sentinel entfernen$([ "$PURGE" = 1 ] && echo ' inklusive aller Daten')? [j/N] " a
	case "$a" in [jJyY]*) ;; *) exit 1 ;; esac
fi

systemctl disable --now caddy-sentinel.service 2>/dev/null || true
rm -f /etc/systemd/system/caddy-sentinel.service /etc/systemd/system/caddy.service.d/sentinel.conf
rmdir /etc/systemd/system/caddy.service.d 2>/dev/null || true
rm -f /usr/local/bin/caddy-sentinel /usr/local/sbin/caddy-sentinel-update /usr/local/sbin/caddy-sentinel-uninstall
if [ -f /usr/local/bin/caddy.orig ]; then
	mv -f /usr/local/bin/caddy.orig /usr/local/bin/caddy
	echo "Ursprüngliches /usr/local/bin/caddy wiederhergestellt."
elif [ -x /usr/bin/caddy ]; then
	rm -f /usr/local/bin/caddy
	echo "Caddy aus dem Distributionspaket (/usr/bin/caddy) ist wieder aktiv."
else
	echo "Hinweis: /usr/local/bin/caddy (Sentinel-Build) bleibt installiert, damit deine Sites weiterlaufen."
	echo "         Entferne die Direktive \"sentinel\" aus der Caddyfile, bevor du einen Standard-Caddy einsetzt."
fi
systemctl daemon-reload
if systemctl list-unit-files caddy.service >/dev/null 2>&1; then
	systemctl restart caddy.service 2>/dev/null || echo "Caddy startet nicht – vermutlich steht noch \"sentinel\" in der Caddyfile."
fi
rm -rf /usr/local/share/caddy-sentinel /usr/local/share/doc/caddy-sentinel
if [ "$PURGE" = 1 ]; then
	rm -rf /var/lib/caddy-sentinel /var/backups/caddy-sentinel /etc/default/caddy-sentinel
	echo "Daten gelöscht."
else
	echo "Daten behalten: /var/lib/caddy-sentinel, /etc/default/caddy-sentinel, /var/backups/caddy-sentinel"
fi
echo "Caddy Sentinel wurde entfernt."
