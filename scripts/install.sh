#!/usr/bin/env bash
# Caddy Sentinel – Installation als systemd-Dienste (Debian/Ubuntu/RHEL u. a.)
#
# Direkt aus dem neuesten GitHub-Release:
#   curl -fsSL https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh | sudo bash
#
# Aus einem entpackten Release-Archiv:
#   sudo ./install.sh
#
# Optionen:
#   --version vX.Y.Z   bestimmte Version statt der neuesten
#   --dir PFAD         Binaries aus diesem Verzeichnis (caddy, caddy-sentinel)
#   --listen ADDR      Adresse des Panels (Standard: 127.0.0.1:7600)
#   --panel-only       nur das Panel installieren, Caddy nicht anfassen
#   --agent            nur Caddy mit Sentinel-Agent installieren – für einen
#                      weiteren Server, der sich mit einem bestehenden Panel
#                      verbindet (Instanz im Panel unter „Caddy-Instanzen“ anlegen)
#     --panel URL      Adresse des Panels, z. B. https://sentinel.example.com
#     --token TOKEN    Token der Instanz
#     --remote MODUS   full (Caddyfile im Panel bearbeitbar, Standard) | read | off
#   --no-start         Dienste nicht starten
#   -y, --yes          keine Rückfragen
#
# Umgebung: SENTINEL_REPO (Standard b1tk1ll3r/caddy-sentinel), GITHUB_TOKEN (optional, gegen API-Limits)
set -euo pipefail

REPO=${SENTINEL_REPO:-b1tk1ll3r/caddy-sentinel}
VERSION=""
SRC=""
LISTEN=""
PANEL_ONLY=0
AGENT=0
PANEL_URL=""
AGENT_TOKEN=""
REMOTE=full
START=1
YES=0
BIN_DIR=/usr/local/bin
DATA_DIR=/var/lib/caddy-sentinel
SHARE_DIR=/usr/local/share/caddy-sentinel

while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION=$2; shift ;;
	--dir) SRC=$2; shift ;;
	--listen) LISTEN=$2; shift ;;
	--panel-only) PANEL_ONLY=1 ;;
	--agent) AGENT=1 ;;
	--panel) PANEL_URL=$2; shift ;;
	--token) AGENT_TOKEN=$2; shift ;;
	--remote) REMOTE=$2; shift ;;
	--no-start) START=0 ;;
	-y | --yes) YES=1 ;;
	-h | --help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

[ "$(id -u)" = 0 ] || die "Bitte als root bzw. mit sudo ausführen."
if [ "$AGENT" = 1 ]; then
	[ -n "$PANEL_URL" ] && [ -n "$AGENT_TOKEN" ] || die "--agent braucht --panel URL und --token TOKEN (im Panel unter „Caddy-Instanzen“)."
	case "$REMOTE" in full | read | off) ;; *) die "--remote muss full, read oder off sein." ;; esac
	[ "$PANEL_ONLY" = 0 ] || die "--agent und --panel-only schließen sich aus."
fi
command -v systemctl >/dev/null || die "systemd wird benötigt (für Docker siehe docs/INSTALL.md)."

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv7l | armv7*) ARCH=armv7 ;;
*) die "Architektur $(uname -m) wird nicht unterstützt." ;;
esac

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo .)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() { # url dest
	local auth=()
	[ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
	if command -v curl >/dev/null; then
		curl -fsSL --retry 3 "${auth[@]}" -o "$2" "$1"
	elif command -v wget >/dev/null; then
		wget -q -O "$2" "$1"
	else
		die "curl oder wget wird benötigt."
	fi
}

latest_version() {
	fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json" || die "Konnte die neueste Version nicht ermitteln (GitHub-API)."
	sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n1
}

download_release() { # version -> sets SRC
	local v=$1 name="caddy-sentinel_${1}_linux_${ARCH}"
	local base="https://github.com/$REPO/releases/download/$v"
	say "Lade $name.tar.gz"
	fetch "$base/$name.tar.gz" "$TMP/$name.tar.gz" || die "Download fehlgeschlagen: $base/$name.tar.gz"
	fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" || die "Prüfsummen fehlen im Release."
	(cd "$TMP" && grep " $name.tar.gz\$" SHA256SUMS | sha256sum -c --quiet -) || die "Prüfsumme stimmt nicht – Abbruch."
	tar -C "$TMP" -xzf "$TMP/$name.tar.gz"
	SRC="$TMP/$name"
}

# ------------------------------------------------------------ Quelle bestimmen
if [ -z "$SRC" ]; then
	if [ -x "$SCRIPT_DIR/caddy-sentinel" ] && [ -z "$VERSION" ]; then
		SRC=$SCRIPT_DIR # entpacktes Release-Archiv
	else
		[ -n "$VERSION" ] || VERSION=$(latest_version)
		[ -n "$VERSION" ] || die "Keine Version gefunden."
		download_release "$VERSION"
	fi
fi
[ "$AGENT" = 1 ] || [ -x "$SRC/caddy-sentinel" ] || die "$SRC/caddy-sentinel fehlt."
[ "$PANEL_ONLY" = 1 ] || [ -x "$SRC/caddy" ] || die "$SRC/caddy fehlt."
DEPLOY=""
for d in "$SRC/deploy" "$SCRIPT_DIR/deploy" "$SCRIPT_DIR/../deploy"; do
	[ -f "$d/caddy-sentinel.service" ] && { DEPLOY=$(cd "$d" && pwd); break; }
done
if [ -z "$DEPLOY" ]; then
	# z. B. bei "curl | bash" mit --dir: Unit-Dateien aus dem Release holen
	[ -n "$VERSION" ] || VERSION=$(latest_version)
	download_release "$VERSION"
	DEPLOY="$SRC/deploy"
fi
if [ -x "$SRC/caddy-sentinel" ]; then
	NEW_VERSION=$("$SRC/caddy-sentinel" -version | awk '{print $NF}')
else
	NEW_VERSION=${VERSION:-unbekannt}
fi

say "Installiere Caddy Sentinel $NEW_VERSION (linux/$ARCH)"
if [ "$AGENT" = 0 ] && [ -x "$BIN_DIR/caddy-sentinel" ]; then
	warn "Caddy Sentinel ist bereits installiert ($("$BIN_DIR/caddy-sentinel" -version | awk '{print $NF}')). Für Updates besser caddy-sentinel-update verwenden."
	confirm "Trotzdem fortfahren?" || exit 1
fi

# ------------------------------------------------------------ Benutzer & Verzeichnisse
say "Benutzer und Verzeichnisse"
if ! getent group caddy >/dev/null; then groupadd --system caddy; fi
if ! id caddy >/dev/null 2>&1; then
	useradd --system --gid caddy --create-home --home-dir /var/lib/caddy --shell /usr/sbin/nologin --comment "Caddy web server" caddy
fi
[ "$AGENT" = 1 ] || install -d -o caddy -g caddy -m 0750 "$DATA_DIR"
install -d -m 0755 /etc/caddy "$SHARE_DIR"
if [ ! -f /etc/caddy/Caddyfile ]; then
	cat >/etc/caddy/Caddyfile <<'CF'
# Caddyfile – wird im Sentinel-Panel bearbeitet
{
	# email admin@example.com
}

:80 {
	sentinel
	respond "Caddy Sentinel läuft"
}

import sites/*.caddy
CF
fi
install -d -o root -g caddy -m 0775 /etc/caddy/sites
# Das Panel schreibt Caddyfile und importierte Dateien als Benutzer caddy
chgrp -R caddy /etc/caddy
chmod g+rwX /etc/caddy
find /etc/caddy -maxdepth 3 -type f \( -name 'Caddyfile*' -o -name '*.caddy' -o -name '*.caddyfile' -o -name '*.conf' \) -exec chmod g+rw {} +

# ------------------------------------------------------------ Binaries
say "Binaries nach $BIN_DIR"
[ "$AGENT" = 1 ] || install -m 0755 "$SRC/caddy-sentinel" "$BIN_DIR/caddy-sentinel"
if [ "$PANEL_ONLY" = 0 ]; then
	if [ -x "$BIN_DIR/caddy" ] && ! "$BIN_DIR/caddy" list-modules 2>/dev/null | grep -q '^http.handlers.sentinel$'; then
		cp -a "$BIN_DIR/caddy" "$BIN_DIR/caddy.orig"
		warn "Vorhandenes $BIN_DIR/caddy als caddy.orig gesichert."
	fi
	install -m 0755 "$SRC/caddy" "$BIN_DIR/caddy"
	if command -v setcap >/dev/null; then
		setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	fi
fi
for s in update uninstall; do
	for f in "$SRC/$s.sh" "$SCRIPT_DIR/$s.sh"; do
		if [ -f "$f" ]; then install -m 0755 "$f" "/usr/local/sbin/caddy-sentinel-$s"; break; fi
	done
done
echo "$NEW_VERSION" >"$SHARE_DIR/VERSION"
echo "$REPO" >"$SHARE_DIR/REPO"

# ------------------------------------------------------------ Agent-Modus
if [ "$AGENT" = 1 ]; then
	say "Agent-Verbindung zu $PANEL_URL"
	echo agent >"$SHARE_DIR/MODE"
	umask 027
	printf '%s\n' "$AGENT_TOKEN" >/etc/caddy/sentinel-agent.token
	chown root:caddy /etc/caddy/sentinel-agent.token
	chmod 0640 /etc/caddy/sentinel-agent.token
	install -d /etc/systemd/system/caddy.service.d
	{
		echo "# Caddy Sentinel – Agent für das Panel $PANEL_URL"
		echo "[Service]"
		echo "ExecStart="
		echo "ExecStart=$BIN_DIR/caddy run --environ --config /etc/caddy/Caddyfile"
		echo "ExecReload="
		echo "ExecReload=$BIN_DIR/caddy reload --config /etc/caddy/Caddyfile --force"
		echo "Environment=SENTINEL_PANEL=$PANEL_URL"
		echo "Environment=SENTINEL_TOKEN_FILE=/etc/caddy/sentinel-agent.token"
		echo "Environment=SENTINEL_REMOTE=$REMOTE"
		echo "Environment=SENTINEL_CADDYFILE=/etc/caddy/Caddyfile"
		# remote full: Caddy (Benutzer caddy) schreibt die Caddyfile
		if [ "$REMOTE" = full ]; then echo "ReadWritePaths=/etc/caddy"; fi
	} >/etc/systemd/system/caddy.service.d/sentinel.conf
	if [ ! -f /lib/systemd/system/caddy.service ] && [ ! -f /usr/lib/systemd/system/caddy.service ] && [ ! -f /etc/systemd/system/caddy.service ]; then
		install -m 0644 "$DEPLOY/caddy.service" /etc/systemd/system/caddy.service
		sed -i 's/ caddy-sentinel.service//' /etc/systemd/system/caddy.service
	fi
	systemctl daemon-reload
	if [ "$START" = 1 ]; then
		systemctl enable caddy.service >/dev/null 2>&1 || true
		systemctl restart caddy.service || { journalctl -u caddy -n 30 --no-pager || true; die "Caddy startet nicht."; }
	fi
	cat <<AGENTEOF

Caddy mit Sentinel-Agent ist installiert und verbindet sich mit $PANEL_URL.
Im Panel unter „Caddy-Instanzen“ erscheint der Server als verbunden.

  Zugriff des Panels: $REMOTE
  Token:              /etc/caddy/sentinel-agent.token
  Logs:               journalctl -u caddy -f

AGENTEOF
	exit 0
fi

# ------------------------------------------------------------ systemd
say "systemd-Units"
install -m 0644 "$DEPLOY/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service
if [ ! -f /etc/default/caddy-sentinel ]; then
	install -m 0644 "$DEPLOY/caddy-sentinel.env" /etc/default/caddy-sentinel
	[ "$PANEL_ONLY" = 1 ] && sed -i 's|^SENTINEL_CADDY_BIN=.*|SENTINEL_CADDY_BIN=|' /etc/default/caddy-sentinel
fi
if [ -n "$LISTEN" ]; then
	sed -i "s|^SENTINEL_LISTEN=.*|SENTINEL_LISTEN=$LISTEN|" /etc/default/caddy-sentinel
fi
if [ "$PANEL_ONLY" = 0 ]; then
	install -d /etc/systemd/system/caddy.service.d
	install -m 0644 "$DEPLOY/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf
	if [ ! -f /lib/systemd/system/caddy.service ] && [ ! -f /usr/lib/systemd/system/caddy.service ] && [ ! -f /etc/systemd/system/caddy.service ]; then
		install -m 0644 "$DEPLOY/caddy.service" /etc/systemd/system/caddy.service
	fi
fi
systemctl daemon-reload

if [ "$START" = 0 ]; then
	say "Installiert. Starten mit: systemctl enable --now caddy-sentinel caddy"
	exit 0
fi

# ------------------------------------------------------------ Start
say "Starte Panel"
systemctl enable --now caddy-sentinel.service
listen=$(sed -n 's/^SENTINEL_LISTEN=//p' /etc/default/caddy-sentinel | tail -n1)
listen=${listen:-127.0.0.1:7600}
probe=${listen/0.0.0.0/127.0.0.1}
ok=0
for _ in $(seq 1 40); do
	if [ -f "$DATA_DIR/agent.token" ] && (curl -fsS -o /dev/null "http://$probe/api/auth/state" 2>/dev/null || wget -q -O /dev/null "http://$probe/api/auth/state" 2>/dev/null); then ok=1; break; fi
	sleep 0.5
done
[ "$ok" = 1 ] || { journalctl -u caddy-sentinel -n 30 --no-pager || true; die "Panel startet nicht (siehe Log oben)."; }

if [ "$PANEL_ONLY" = 0 ]; then
	say "Starte Caddy"
	systemctl enable caddy.service >/dev/null 2>&1 || true
	if ! systemctl restart caddy.service; then
		journalctl -u caddy -n 30 --no-pager || true
		die "Caddy startet nicht – Caddyfile prüfen: $BIN_DIR/caddy validate --config /etc/caddy/Caddyfile"
	fi
fi

cat <<EOF

Caddy Sentinel $NEW_VERSION ist installiert.

  Panel:      http://$listen
              von einem anderen Rechner: ssh -L 7600:$probe server
              beim ersten Aufruf legst du das Administratorkonto an
  Logs:       journalctl -u caddy-sentinel -u caddy -f
  Update:     sudo caddy-sentinel-update            (prüfen: --check)
  Entfernen:  sudo caddy-sentinel-uninstall

EOF
