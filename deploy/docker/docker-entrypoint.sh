#!/bin/sh
# Legt beim ersten Start eine Standard-Caddyfile an, damit Caddy und Panel
# mit leeren Volumes starten können.
set -e
CF=${SENTINEL_CADDYFILE:-/etc/caddy/Caddyfile}
if [ ! -f "$CF" ] && [ -w "$(dirname "$CF")" ]; then
	cp /usr/share/caddy-sentinel/Caddyfile.default "$CF"
	mkdir -p "$(dirname "$CF")/sites"
	echo "caddy-sentinel: Standard-Caddyfile nach $CF geschrieben"
fi
exec "$@"
