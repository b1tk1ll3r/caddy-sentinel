#!/usr/bin/env bash
# Caddy Sentinel – Installation und Update als systemd-Dienste
# (Debian, Ubuntu, RHEL, Raspberry Pi OS …)
#
# Ein Befehl – installiert beim ersten Mal und aktualisiert danach:
#   bash <(wget -qO- https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh)
# Ohne root startet sich das Skript selbst mit sudo neu.
#
# Aus einem entpackten Release-Archiv:
#   sudo ./install.sh
#
# Optionen (ohne Optionen fragt das Skript nach, was installiert werden soll):
#   --version vX.Y.Z   bestimmte Version statt der neuesten
#   --dir PFAD         Binaries aus diesem Verzeichnis (caddy, caddy-sentinel)
#   --listen ADDR      Adresse des Panels (Standard: 127.0.0.1:7600)
#   --panel-only       nur das Panel installieren, Caddy nicht anfassen
#   --agent            nur Caddy mit Sentinel-Agent – für einen weiteren Server,
#                      der sich mit einem bestehenden Panel verbindet
#     --panel URL      Adresse des Panels, z. B. https://sentinel.example.com
#     --token TOKEN    Token der Instanz (Panel › Caddy-Instanzen)
#     --remote MODUS   full (Caddyfile im Panel bearbeitbar, Standard) | read | off
#   --reinstall        auch bei vorhandener Installation neu installieren
#   --force            auch dieselbe Version erneut einspielen
#   --no-start         Dienste nicht starten
#   -y, --yes          keine Rückfragen
#
# Umgebung: SENTINEL_REPO (Standard b1tk1ll3r/caddy-sentinel),
#           SENTINEL_DOWNLOAD (Spiegel statt https://github.com/<repo>/releases)
set -euo pipefail

main() {

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
REINSTALL=0
FORCE=0
MODE_GIVEN=0
BIN_DIR=/usr/local/bin
DATA_DIR=/var/lib/caddy-sentinel
SHARE_DIR=/usr/local/share/caddy-sentinel
# Spiegel möglich, z. B. SENTINEL_DOWNLOAD=https://mirror.example.com/caddy-sentinel
DL=${SENTINEL_DOWNLOAD:-$(cat "$SHARE_DIR/DOWNLOAD" 2>/dev/null || echo "https://github.com/$REPO/releases")}

while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION=$2; shift ;;
	--dir) SRC=$2; shift ;;
	--listen) LISTEN=$2; shift ;;
	--panel-only) PANEL_ONLY=1; MODE_GIVEN=1 ;;
	--agent) AGENT=1; MODE_GIVEN=1 ;;
	--panel) PANEL_URL=$2; shift ;;
	--token) AGENT_TOKEN=$2; shift ;;
	--remote) REMOTE=$2; shift ;;
	--reinstall) REINSTALL=1 ;;
	--force) FORCE=1 ;;
	--no-start) START=0 ;;
	-y | --yes) YES=1 ;;
	-h | --help) usage; exit 0 ;;
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
ask() { # frage default -> REPLY
	local a
	read -r -p "$1 " a </dev/tty || a=""
	REPLY=${a:-$2}
}
interactive() { [ "$YES" = 0 ] && [ -r /dev/tty ] && [ -t 1 ]; }
[ "$AGENT" = 0 ] || [ "$PANEL_ONLY" = 0 ] || die "--agent und --panel-only schließen sich aus."
command -v systemctl >/dev/null || die "systemd wird benötigt (für Docker siehe docs/INSTALL.md)."

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
armv7l | armv7*) ARCH=armv7 ;;
*) die "Architektur $(uname -m) wird nicht unterstützt." ;;
esac

# Verzeichnis des Skripts – nur wenn es als echte Datei aufgerufen wurde
# (bei "bash <(wget …)" oder "curl | bash" gibt es keins)
SCRIPT_DIR=${SENTINEL_SCRIPT_DIR:-}
if [ -z "$SCRIPT_DIR" ] && [ -f "${BASH_SOURCE[0]:-}" ]; then
	SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi
SCRIPT_DIR=${SCRIPT_DIR:-/nonexistent}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() { # url dest
	if command -v curl >/dev/null; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null; then
		wget -q -O "$2" "$1"
	else
		die "curl oder wget wird benötigt."
	fi
}

# Download ohne GitHub-API (kein Abfragelimit): das neueste Release hat
# Archive mit festem Namen unter releases/latest/download/.
download_release() { # [version] -> sets SRC
	local v=${1:-} name base
	if [ -n "$v" ]; then
		name="caddy-sentinel_${v}_linux_${ARCH}.tar.gz"
		base="$DL/download/$v"
	else
		name="caddy-sentinel_linux_${ARCH}.tar.gz"
		base="$DL/latest/download"
	fi
	say "Lade ${v:-neueste Version} (linux/$ARCH)"
	fetch "$base/$name" "$TMP/$name" || die "Download fehlgeschlagen: $base/$name"
	fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" || die "Prüfsummen fehlen im Release."
	(cd "$TMP" && grep " $name\$" SHA256SUMS | sha256sum -c --quiet -) || die "Prüfsumme stimmt nicht – Abbruch."
	install -d "$TMP/pkg"
	tar -C "$TMP/pkg" --strip-components=1 -xzf "$TMP/$name"
	SRC="$TMP/pkg"
}

# ------------------------------------------------------------ Quelle bestimmen
if [ -z "$SRC" ]; then
	if [ -x "$SCRIPT_DIR/caddy-sentinel" ] && [ -z "$VERSION" ]; then
		SRC=$SCRIPT_DIR # entpacktes Release-Archiv
	else
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
	download_release "$VERSION"
	DEPLOY="$SRC/deploy"
fi
if [ -x "$SRC/caddy-sentinel" ]; then
	NEW_VERSION=$("$SRC/caddy-sentinel" -version | awk '{print $NF}')
else
	NEW_VERSION=${VERSION:-unbekannt}
fi

# ------------------------------------------------------------ vorhandene Installation → Update
INSTALLED=""
if [ "$(cat "$SHARE_DIR/MODE" 2>/dev/null)" = agent ] && [ -x "$BIN_DIR/caddy" ]; then
	INSTALLED=$(cat "$SHARE_DIR/VERSION" 2>/dev/null || echo unbekannt)
elif [ -x "$BIN_DIR/caddy-sentinel" ]; then
	INSTALLED=$("$BIN_DIR/caddy-sentinel" -version 2>/dev/null | awk '{print $NF}')
fi
if [ -n "$INSTALLED" ] && [ "$REINSTALL" = 0 ]; then
	[ "$MODE_GIVEN" = 0 ] || warn "Bereits installiert – --agent/--panel-only werden ignoriert (neu einrichten: --reinstall)."
	if [ "$INSTALLED" = "$NEW_VERSION" ] && [ "$FORCE" = 0 ]; then
		say "Caddy Sentinel $INSTALLED ist installiert und aktuell."
		exit 0
	fi
	say "Caddy Sentinel $INSTALLED ist installiert – Update auf $NEW_VERSION"
	[ -f "$SRC/update.sh" ] || die "update.sh fehlt im Archiv."
	args=(--dir "$SRC")
	[ "$YES" = 1 ] && args+=(--yes)
	[ "$FORCE" = 1 ] && args+=(--force)
	bash "$SRC/update.sh" "${args[@]}"
	exit $?
fi

# ------------------------------------------------------------ was installieren?
if [ "$MODE_GIVEN" = 0 ] && interactive; then
	echo
	echo "Was soll auf diesem Server installiert werden?"
	echo "  1) Panel und Caddy mit Sentinel   (Standard, alles auf einem Server)"
	echo "  2) Nur das Panel                  (Caddy läuft woanders oder kommt später)"
	echo "  3) Nur Caddy mit Sentinel-Agent   (weiterer Server für ein bestehendes Panel)"
	ask "Auswahl [1]:" 1
	case "$REPLY" in
	2) PANEL_ONLY=1 ;;
	3) AGENT=1 ;;
	esac
	if [ "$AGENT" = 1 ]; then
		[ -n "$PANEL_URL" ] || { ask "Adresse des Panels (z. B. https://sentinel.example.com):" ""; PANEL_URL=$REPLY; }
		[ -n "$AGENT_TOKEN" ] || { ask "Token der Instanz (Panel › Caddy-Instanzen › Instanz hinzufügen):" ""; AGENT_TOKEN=$REPLY; }
		ask "Darf das Panel die Caddyfile bearbeiten? [J/n]:" j
		case "$REPLY" in [nN]*) REMOTE=read ;; *) REMOTE=full ;; esac
		[ -n "$PANEL_URL" ] && [ -n "$AGENT_TOKEN" ] || die "Panel-Adresse und Token werden benötigt."
	elif [ -z "$LISTEN" ]; then
		ask "Adresse des Panels [127.0.0.1:7600] (0.0.0.0:7600 = aus dem Netz erreichbar):" 127.0.0.1:7600
		LISTEN=$REPLY
	fi
	[ "$PANEL_ONLY" = 1 ] || [ -x "$SRC/caddy" ] || die "$SRC/caddy fehlt."
fi
if [ "$AGENT" = 1 ]; then
	[ -n "$PANEL_URL" ] && [ -n "$AGENT_TOKEN" ] || die "--agent braucht --panel URL und --token TOKEN (im Panel unter „Caddy-Instanzen“)."
	case "$REMOTE" in full | read | off) ;; *) die "--remote muss full, read oder off sein." ;; esac
fi

say "Installiere Caddy Sentinel $NEW_VERSION (linux/$ARCH)"

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
if [ "$DL" != "https://github.com/$REPO/releases" ]; then echo "$DL" >"$SHARE_DIR/DOWNLOAD"; else rm -f "$SHARE_DIR/DOWNLOAD"; fi

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
}

usage() {
	cat <<'USAGE'
Caddy Sentinel – Installation und Update

  bash <(wget -qO- https://raw.githubusercontent.com/b1tk1ll3r/caddy-sentinel/main/scripts/install.sh) [Optionen]

  --version vX.Y.Z   bestimmte Version statt der neuesten
  --dir PFAD         Binaries aus diesem Verzeichnis
  --listen ADDR      Adresse des Panels (Standard: 127.0.0.1:7600)
  --panel-only       nur das Panel
  --agent            nur Caddy mit Sentinel-Agent (mit --panel URL --token TOKEN [--remote full|read|off])
  --reinstall        auch bei vorhandener Installation neu installieren
  --force            auch dieselbe Version erneut einspielen
  --no-start         Dienste nicht starten
  -y, --yes          keine Rückfragen

Ohne Optionen fragt das Skript nach. Ist Caddy Sentinel schon installiert,
aktualisiert derselbe Befehl auf die neueste Version.
USAGE
}

# Ohne root: mit sudo neu starten. Das Skript kann aus einer Pipe oder
# "<(…)" kommen, die sudo nicht lesen kann – deshalb wird der Quelltext der
# Funktionen übergeben statt einer Datei.
if [ "$(id -u)" -ne 0 ]; then
	case " $* " in *" -h "* | *" --help "*) usage; exit 0 ;; esac
	command -v sudo >/dev/null || { echo "Bitte als root ausführen (sudo ist nicht installiert)." >&2; exit 1; }
	echo "==> Für die Installation werden root-Rechte benötigt – starte mit sudo neu"
	dir=""
	if [ -f "${BASH_SOURCE[0]:-}" ]; then dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); fi
	exec sudo env SENTINEL_SCRIPT_DIR="$dir" SENTINEL_REPO="${SENTINEL_REPO:-}" SENTINEL_DOWNLOAD="${SENTINEL_DOWNLOAD:-}" bash -c "set -euo pipefail; $(declare -f main usage); main \"\$@\"" caddy-sentinel-install "$@"
fi
main "$@"
