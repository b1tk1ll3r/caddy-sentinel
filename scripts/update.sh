#!/usr/bin/env bash
# Caddy Sentinel – Update (systemd-Installation)
#
#   sudo caddy-sentinel-update              # auf die neueste Version
#   sudo caddy-sentinel-update --check      # nur prüfen (Exit 10 = Update verfügbar)
#   sudo caddy-sentinel-update --version v1.4.0
#   sudo caddy-sentinel-update --rollback   # letzte Sicherung zurückspielen
#
# Ablauf: Download + Prüfsumme → Caddyfile mit dem neuen Caddy prüfen →
# Sicherung (Binaries, Datenbank, Units) → Panel tauschen und prüfen →
# Caddy tauschen und prüfen → bei Fehlern automatisch zurück.
#
# Optionen:
#   --dir PFAD        Binaries aus einem Verzeichnis statt Download
#   --force           auch bei gleicher Version neu installieren
#   --skip-validate   Caddyfile nicht vorab prüfen
#   --with-db         beim Rollback auch die Datenbank zurückspielen
#   -y, --yes         keine Rückfragen
set -euo pipefail

SHARE_DIR=/usr/local/share/caddy-sentinel
REPO=${SENTINEL_REPO:-$(cat "$SHARE_DIR/REPO" 2>/dev/null || echo b1tk1ll3r/caddy-sentinel)}
DL=${SENTINEL_DOWNLOAD:-$(cat "$SHARE_DIR/DOWNLOAD" 2>/dev/null || echo "https://github.com/$REPO/releases")}
BIN_DIR=/usr/local/bin
DATA_DIR=${SENTINEL_DATA:-/var/lib/caddy-sentinel}
BACKUP_ROOT=/var/backups/caddy-sentinel
CADDYFILE=/etc/caddy/Caddyfile
KEEP_BACKUPS=5

MODE=update
VERSION=""
SRC=""
FORCE=0
VALIDATE=1
WITH_DB=0
YES=0
while [ $# -gt 0 ]; do
	case "$1" in
	--check) MODE=check ;;
	--rollback) MODE=rollback ;;
	--version) VERSION=$2; shift ;;
	--dir) SRC=$2; shift ;;
	--force) FORCE=1 ;;
	--skip-validate) VALIDATE=0 ;;
	--with-db) WITH_DB=1 ;;
	-y | --yes) YES=1 ;;
	-h | --help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "Unbekannte Option: $1" >&2; exit 2 ;;
	esac
	shift
done

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }
confirm() {
	[ "$YES" = 1 ] && return 0
	[ -t 0 ] || return 0
	read -r -p "$1 [J/n] " a
	case "$a" in [nN]*) return 1 ;; *) return 0 ;; esac
}

# Agent-Server (install.sh --agent): nur Caddy mit Sentinel-Modul, kein Panel
AGENT=0
[ "$(cat "$SHARE_DIR/MODE" 2>/dev/null)" = agent ] && AGENT=1
if [ "$AGENT" = 1 ]; then
	[ -x "$BIN_DIR/caddy" ] || die "Kein Caddy in $BIN_DIR gefunden."
	CURRENT=$(cat "$SHARE_DIR/VERSION" 2>/dev/null || echo unbekannt)
else
	[ -x "$BIN_DIR/caddy-sentinel" ] || die "Keine Installation in $BIN_DIR gefunden (erst install.sh ausführen)."
	CURRENT=$("$BIN_DIR/caddy-sentinel" -version 2>/dev/null | awk '{print $NF}')
fi
HAS_CADDY=0
if [ -x "$BIN_DIR/caddy" ] && "$BIN_DIR/caddy" list-modules 2>/dev/null | grep -q '^http.handlers.sentinel$'; then HAS_CADDY=1; fi

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv7l | armv7*) ARCH=armv7 ;;
*) die "Architektur $(uname -m) wird nicht unterstützt." ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() {
	local auth=()
	[ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
	if command -v curl >/dev/null; then curl -fsSL --retry 3 "${auth[@]}" -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}
# Neueste Version: VERSION-Datei des letzten Releases (kein API-Limit),
# notfalls über die GitHub-API
latest_version() {
	if fetch "$DL/latest/download/VERSION" "$TMP/VERSION" 2>/dev/null; then
		tr -d '[:space:]' <"$TMP/VERSION"
		return 0
	fi
	fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json" || return 1
	sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n1
}

panel_url() {
	local l
	l=$(sed -n 's/^SENTINEL_LISTEN=//p' /etc/default/caddy-sentinel 2>/dev/null | tail -n1)
	l=${l:-127.0.0.1:7600}
	echo "http://${l/0.0.0.0/127.0.0.1}"
}
http_ok() { curl -fsS -o /dev/null --max-time 3 "$1" 2>/dev/null || wget -q -O /dev/null -T 3 "$1" 2>/dev/null; }

wait_panel() {
	local url
	url="$(panel_url)/api/auth/state"
	for _ in $(seq 1 60); do
		if systemctl is-active --quiet caddy-sentinel && http_ok "$url"; then return 0; fi
		sleep 0.5
	done
	return 1
}
wait_caddy() {
	for _ in $(seq 1 30); do
		if systemctl is-active --quiet caddy; then
			sleep 2 # kurz laufen lassen – stirbt Caddy beim Laden der Konfiguration?
			systemctl is-active --quiet caddy && return 0
		fi
		sleep 0.5
	done
	return 1
}

# ------------------------------------------------------------ Sicherung
backup() {
	local dir
	dir="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)-$CURRENT"
	install -d -m 0700 "$dir"
	cp -a "$BIN_DIR/caddy-sentinel" "$dir/"
	[ "$HAS_CADDY" = 1 ] && cp -a "$BIN_DIR/caddy" "$dir/"
	cp -a /etc/systemd/system/caddy-sentinel.service "$dir/" 2>/dev/null || true
	cp -a /etc/systemd/system/caddy.service.d/sentinel.conf "$dir/caddy-override.conf" 2>/dev/null || true
	cp -a /etc/default/caddy-sentinel "$dir/caddy-sentinel.env" 2>/dev/null || true
	cp -a "$CADDYFILE" "$dir/Caddyfile" 2>/dev/null || true
	# Datenbank konsistent sichern: Panel ist zu diesem Zeitpunkt gestoppt
	for f in "$DATA_DIR"/sentinel.db "$DATA_DIR"/sentinel.db-wal "$DATA_DIR"/sentinel.db-shm; do
		[ -f "$f" ] && cp -a "$f" "$dir/"
	done
	echo "$CURRENT" >"$dir/VERSION"
	# alte Sicherungen aufräumen
	find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | head -n -"$KEEP_BACKUPS" | xargs -r rm -rf
	echo "$dir"
}

restore() { # dir with_db
	local dir=$1
	say "Stelle Sicherung $(basename "$dir") wieder her"
	systemctl stop caddy-sentinel || true
	install -m 0755 "$dir/caddy-sentinel" "$BIN_DIR/caddy-sentinel"
	if [ -f "$dir/caddy" ]; then
		install -m 0755 "$dir/caddy" "$BIN_DIR/caddy"
		command -v setcap >/dev/null && setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	fi
	[ -f "$dir/caddy-sentinel.service" ] && install -m 0644 "$dir/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service
	[ -f "$dir/caddy-override.conf" ] && install -m 0644 "$dir/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf
	if [ "$2" = 1 ] && [ -f "$dir/sentinel.db" ]; then
		rm -f "$DATA_DIR"/sentinel.db-wal "$DATA_DIR"/sentinel.db-shm
		for f in "$dir"/sentinel.db*; do install -o caddy -g caddy -m 0640 "$f" "$DATA_DIR/"; done
	fi
	cat "$dir/VERSION" >"$SHARE_DIR/VERSION" 2>/dev/null || true
	systemctl daemon-reload
	systemctl start caddy-sentinel
	wait_panel || warn "Panel antwortet nach dem Zurückspielen nicht – journalctl -u caddy-sentinel"
	if [ -f "$dir/caddy" ]; then systemctl restart caddy || warn "Caddy startet nicht – journalctl -u caddy"; fi
}

[ "$(id -u)" = 0 ] || [ "$MODE" = check ] || die "Bitte als root bzw. mit sudo ausführen."

if [ "$MODE" = rollback ] && [ "$AGENT" = 1 ]; then
	last=$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n1)
	[ -n "$last" ] && [ -f "$last/caddy" ] || die "Keine Sicherung in $BACKUP_ROOT gefunden."
	confirm "Caddy aus $(basename "$last") zurückspielen?" || exit 1
	install -m 0755 "$last/caddy" "$BIN_DIR/caddy"
	command -v setcap >/dev/null && setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	systemctl restart caddy || die "Caddy startet nicht – journalctl -u caddy"
	cp "$last/VERSION" "$SHARE_DIR/VERSION" 2>/dev/null || true
	say "Caddy zurückgesetzt."
	exit 0
fi
if [ "$MODE" = rollback ]; then
	# neueste Sicherung einer anderen als der laufenden Version
	last=""
	while read -r d; do
		if [ "$(cat "$d/VERSION" 2>/dev/null)" != "$CURRENT" ]; then last=$d; break; fi
	done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
	[ -n "$last" ] || die "Keine Sicherung einer anderen Version in $BACKUP_ROOT gefunden."
	confirm "Auf $(cat "$last/VERSION") zurückgehen (Sicherung $(basename "$last"))?" || exit 1
	restore "$last" "$WITH_DB"
	say "Zurückgesetzt auf $(cat "$last/VERSION")."
	exit 0
fi

# ------------------------------------------------------------ Zielversion
if [ -z "$SRC" ]; then
	if [ -z "$VERSION" ]; then
		VERSION=$(latest_version) || die "Konnte die neueste Version nicht ermitteln (Internet?)."
	fi
	[ -n "$VERSION" ] || die "Keine Version gefunden."
fi

if [ "$MODE" = check ]; then
	echo "Installiert: $CURRENT"
	echo "Verfügbar:   $VERSION"
	if [ "$CURRENT" = "$VERSION" ]; then echo "Caddy Sentinel ist aktuell."; exit 0; fi
	echo "Update verfügbar: https://github.com/$REPO/releases/tag/$VERSION"
	exit 10
fi

if [ -z "$SRC" ]; then
	if [ "$CURRENT" = "$VERSION" ] && [ "$FORCE" = 0 ]; then
		say "Bereits auf $CURRENT – nichts zu tun (--force installiert neu)."
		exit 0
	fi
	name="caddy-sentinel_${VERSION}_linux_${ARCH}.tar.gz"
	base="$DL/download/$VERSION"
	say "Lade $name"
	fetch "$base/$name" "$TMP/$name" || die "Download fehlgeschlagen: $base/$name"
	fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" || die "Prüfsummen fehlen."
	(cd "$TMP" && grep " $name\$" SHA256SUMS | sha256sum -c --quiet -) || die "Prüfsumme stimmt nicht – Abbruch."
	install -d "$TMP/pkg"
	tar -C "$TMP/pkg" --strip-components=1 -xzf "$TMP/$name"
	SRC="$TMP/pkg"
fi
[ -x "$SRC/caddy-sentinel" ] || die "$SRC/caddy-sentinel fehlt."
NEW=$("$SRC/caddy-sentinel" -version | awk '{print $NF}')
[ "$AGENT" = 1 ] && HAS_CADDY=1
say "Update $CURRENT → $NEW"
confirm "Jetzt aktualisieren? Caddy wird dabei kurz neu gestartet." || exit 1

# ------------------------------------------------------------ Vorabprüfung
if [ "$HAS_CADDY" = 1 ] && [ -x "$SRC/caddy" ] && [ "$VALIDATE" = 1 ] && [ -f "$CADDYFILE" ]; then
	say "Prüfe $CADDYFILE mit dem neuen Caddy"
	# der Benutzer caddy muss das neue Binary ausführen können
	chmod 0755 "$TMP"
	install -d -m 0755 "$TMP/validate"
	install -m 0755 "$SRC/caddy" "$TMP/validate/caddy"
	if ! (cd /etc/caddy && runuser -u caddy -- env HOME=/var/lib/caddy SENTINEL_PANEL="$(panel_url)" "$TMP/validate/caddy" validate --config "$CADDYFILE" --adapter caddyfile >"$TMP/validate.log" 2>&1); then
		cat "$TMP/validate.log" >&2
		die "Die Konfiguration ist mit der neuen Caddy-Version ungültig – nichts geändert. (--skip-validate überspringt die Prüfung)"
	fi
fi

# ------------------------------------------------------------ Agent-Server: nur Caddy
if [ "$AGENT" = 1 ]; then
	[ -x "$SRC/caddy" ] || die "$SRC/caddy fehlt."
	BACKUP="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
	install -d -m 0700 "$BACKUP"
	cp -a "$BIN_DIR/caddy" "$BACKUP/caddy"
	echo "$CURRENT" >"$BACKUP/VERSION"
	say "Installiere Caddy $("$SRC/caddy" version | awk '{print $1}')"
	install -m 0755 "$SRC/caddy" "$BIN_DIR/caddy"
	command -v setcap >/dev/null && setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	if ! systemctl restart caddy || ! wait_caddy; then
		warn "Caddy startet nicht – setze zurück."
		install -m 0755 "$BACKUP/caddy" "$BIN_DIR/caddy"
		systemctl restart caddy || true
		die "Update fehlgeschlagen, alte Version ist wieder aktiv."
	fi
	for s in update uninstall; do
		[ -f "$SRC/$s.sh" ] && install -m 0755 "$SRC/$s.sh" "/usr/local/sbin/caddy-sentinel-$s"
	done
	echo "$NEW" >"$SHARE_DIR/VERSION"
	say "Caddy mit Sentinel-Agent ist jetzt auf $NEW (Sicherung: $BACKUP)."
	exit 0
fi

# ------------------------------------------------------------ Panel
say "Sichere aktuelle Installation"
systemctl stop caddy-sentinel
BACKUP=$(backup)
echo "    $BACKUP"

rollback() {
	warn "$1 – setze auf $CURRENT zurück."
	restore "$BACKUP" 0
	die "Update fehlgeschlagen, alte Version ist wieder aktiv."
}

say "Installiere Panel $NEW"
install -m 0755 "$SRC/caddy-sentinel" "$BIN_DIR/caddy-sentinel"
if [ -f "$SRC/deploy/caddy-sentinel.service" ] && ! cmp -s "$SRC/deploy/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service; then
	install -m 0644 "$SRC/deploy/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service
	say "Unit caddy-sentinel.service aktualisiert"
fi
if [ "$HAS_CADDY" = 1 ] && [ -f "$SRC/deploy/caddy-override.conf" ] && ! cmp -s "$SRC/deploy/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf; then
	install -m 0644 "$SRC/deploy/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf
	say "Caddy-Override aktualisiert"
fi
for s in update uninstall; do
	[ -f "$SRC/$s.sh" ] && install -m 0755 "$SRC/$s.sh" "/usr/local/sbin/caddy-sentinel-$s"
done
systemctl daemon-reload
systemctl start caddy-sentinel || rollback "Panel startet nicht"
wait_panel || rollback "Panel antwortet nicht"

# ------------------------------------------------------------ Caddy
if [ "$HAS_CADDY" = 1 ] && [ -x "$SRC/caddy" ]; then
	say "Installiere Caddy $("$SRC/caddy" version | awk '{print $1}')"
	install -m 0755 "$SRC/caddy" "$BIN_DIR/caddy"
	command -v setcap >/dev/null && setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	systemctl restart caddy || rollback "Caddy startet nicht"
	wait_caddy || rollback "Caddy läuft nicht stabil"
fi

echo "$NEW" >"$SHARE_DIR/VERSION"
cat <<EOF

Caddy Sentinel ist jetzt auf $NEW.
  Änderungen:  https://github.com/$REPO/releases/tag/$NEW
  Sicherung:   $BACKUP
  Zurück:      sudo caddy-sentinel-update --rollback

EOF
