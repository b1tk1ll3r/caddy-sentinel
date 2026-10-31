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
# Ältere Installationen, in denen Panel und Caddy beide als Benutzer caddy
# laufen, stellt das Update auf einen eigenen Panel-Benutzer caddy-sentinel
# um (Datenbank nach /var/lib/caddy-sentinel/data, 0700) – auch wenn die
# Version schon aktuell ist. Ein Rollback stellt den alten Zustand wieder her.
#
# Optionen:
#   --dir PFAD        Binaries aus einem Verzeichnis statt Download
#   --force           auch bei gleicher Version neu installieren
#   --skip-validate   Caddyfile nicht vorab prüfen
#   --with-db         beim Rollback auch die Datenbank zurückspielen
#   --keep-config     beim Rollback Caddyfile und /etc/default/caddy-sentinel nicht zurücksetzen
#   --skip-signature  Signatur der Prüfsummen nicht prüfen (nur in Notfällen)
#   --verify-attestation  Herkunftsnachweis des Archivs mit gh prüfen
#                     (auch SENTINEL_VERIFY_ATTESTATION=1; gh braucht GH_TOKEN)
#   -y, --yes         keine Rückfragen
set -euo pipefail

SHARE_DIR=/usr/local/share/caddy-sentinel
REPO=${SENTINEL_REPO:-$(cat "$SHARE_DIR/REPO" 2>/dev/null || echo b1tk1ll3r/caddy-sentinel)}
DL=${SENTINEL_DOWNLOAD:-$(cat "$SHARE_DIR/DOWNLOAD" 2>/dev/null || echo "https://github.com/$REPO/releases")}
BIN_DIR=/usr/local/bin
BACKUP_ROOT=/var/backups/caddy-sentinel
CADDYFILE=/etc/caddy/Caddyfile
KEEP_BACKUPS=5
KEEP_DB_BACKUPS=2
KEEP_CONFIG=0

MODE=update
VERSION=""
SRC=""
FORCE=0
VALIDATE=1
WITH_DB=0
YES=0
VERIFY_ATT=${SENTINEL_VERIFY_ATTESTATION:-0}
SKIP_SIG=${SENTINEL_SKIP_SIGNATURE:-0}
while [ $# -gt 0 ]; do
	case "$1" in
	--check) MODE=check ;;
	--rollback) MODE=rollback ;;
	--version) VERSION=$2; shift ;;
	--dir) SRC=$2; shift ;;
	--force) FORCE=1 ;;
	--skip-validate) VALIDATE=0 ;;
	--with-db) WITH_DB=1 ;;
	--keep-config) KEEP_CONFIG=1 ;;
	--verify-attestation) VERIFY_ATT=1 ;;
	--skip-signature) SKIP_SIG=1 ;;
	-y | --yes) YES=1 ;;
	-h | --help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "Unbekannte Option: $1" >&2; exit 2 ;;
	esac
	shift
done

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }
ensure_log_dir() { # siehe install.sh
	local d=/var/log/caddy
	if [ ! -d "$d" ]; then
		install -d -o caddy -g caddy -m 0755 "$d"
	elif ! runuser -u caddy -- test -w "$d" 2>/dev/null; then
		chown caddy:caddy "$d"
		chmod u+rwx "$d"
		warn "$d gehört jetzt dem Benutzer caddy (vorher nicht beschreibbar)."
	fi
}
confirm() {
	[ "$YES" = 1 ] && return 0
	[ -t 0 ] || return 0
	read -r -p "$1 [J/n] " a
	case "$a" in [nN]*) return 1 ;; *) return 0 ;; esac
}

# ------------------------------------------------------------ sichere Dateioperationen
# /etc/caddy ist für die Gruppe caddy beschreibbar (Panel, im Agent-Modus
# auch Caddy), das Verzeichnis des Panels gehört caddy-sentinel. root darf
# dort nicht über Pfade lesen, schreiben oder Rechte ändern, die einer
# dieser Benutzer zwischen Prüfung und Zugriff umbiegen kann (Symlink,
# Hardlink, Austausch – eine Prüfung vorab hilft wegen TOCTOU allein nicht).
# Dieser Block ist in install.sh, update.sh und uninstall.sh gleich.

# root_only DIR: gehört root, niemand sonst darf darin schreiben
root_only() {
	local s
	s=$(stat -Lc '%u %a' -- "$1" 2>/dev/null) || return 1
	[ "${s%% *}" = 0 ] && [ $((8#${s##* } & 8#022)) = 0 ]
}

# safe_copy SRC DST: nur eine echte Datei lesen. cp -P öffnet die Quelle mit
# O_NOFOLLOW und bricht ab, wenn sie zwischen Prüfung und Öffnen ersetzt
# wurde; mehrfach verlinkte Dateien (Hardlink auf eine fremde Datei) werden
# nicht gelesen. DST muss in einem nur für root zugänglichen Verzeichnis liegen.
safe_copy() {
	rm -f -- "$2"
	[ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %h -- "$1" 2>/dev/null)" = 1 ] || return 1
	if ! cp -P --preserve=mode,timestamps -- "$1" "$2" 2>/dev/null || [ -L "$2" ] || [ ! -f "$2" ]; then
		rm -f -- "$2"
		return 1
	fi
}

# put_file SRC DST MODE OWNER:GROUP: DST in einem fremd beschreibbaren
# Verzeichnis (z. B. /etc/caddy) ersetzen. Die Datei entsteht samt Besitzer
# und Rechten in einem Verzeichnis, das nur root beschreiben kann und auf
# demselben Dateisystem liegt (dem übergeordneten Verzeichnis, z. B. /etc),
# und wird dann mit rename(2) eingesetzt: rename folgt keinem Symlink am
# Ziel, und dazwischen gibt es keinen Pfadzugriff im fremden Verzeichnis.
put_file() {
	local src=$1 dst=$2 mode=$3 own=$4 dir parent st rc=0
	dir=$(realpath -e -- "$(dirname -- "$dst")") || return 1
	parent=$(dirname -- "$dir")
	if ! root_only "$parent" || [ "$(stat -c %d -- "$parent")" != "$(stat -c %d -- "$dir")" ]; then
		warn "$dst nicht geschrieben: $parent ist nicht nur für root beschreibbar oder liegt auf einem anderen Dateisystem als $dir."
		return 1
	fi
	st=$(mktemp -d -- "$parent/.caddy-sentinel.XXXXXX") || return 1
	install -o "${own%%:*}" -g "${own##*:}" -m "$mode" -- "$src" "$st/f" && mv -fT -- "$st/f" "$dir/$(basename -- "$dst")" || rc=1
	rm -rf -- "$st"
	return $rc
}

# lock_tree DIR: DIR mit allem darin root übergeben und Schreibrechte für
# Gruppe und andere entziehen. Danach kann kein anderer Benutzer darin
# Einträge anlegen, umbenennen oder durch Symlinks ersetzen – auch nicht
# über schon geöffnete Verzeichnisse. DIR selbst muss in einem nur für root
# beschreibbaren Verzeichnis liegen. chown -hR folgt keinem Symlink; find
# arbeitet von oben nach unten, jedes Verzeichnis liegt also schon in einem
# gesperrten.
lock_tree() {
	[ -d "$1" ] && [ ! -L "$1" ] || return 1
	chown root:root -- "$1" && chmod 0700 -- "$1" || return 1
	chown -hR root:root -- "$1" || return 1
	find -P "$1" -mindepth 1 -type d -exec chmod go-w -- {} \;
}

# give DIR OWNER:GROUP [EXCLUDE]: Besitz im gesperrten Baum übertragen –
# DIR selbst zuletzt, EXCLUDE (ein Unterverzeichnis) nicht, mehrfach
# verlinkte Dateien nicht (ein Hardlink auf eine Systemdatei bekäme sonst
# einen neuen Besitzer). Rechte vorher setzen: danach kann der neue
# Besitzer die Einträge verändern.
give() {
	find -P "$1" -mindepth 1 \( -path "${3:-/nonexistent}" -o -type f -links +1 \) -prune -o -exec chown -h -- "$2" {} +
	chown -h -- "$2" "$1"
	if [ -n "$(find -P "$1" -type f -links +1 -print -quit)" ]; then
		warn "Mehrfach verlinkte Dateien (Hardlinks) in $1 wurden nicht übertragen – bitte prüfen: find $1 -type f -links +1"
	fi
}

# ------------------------------------------------------------ Benutzer und Verzeichnisse
# Panel und Caddy laufen unter getrennten Benutzern:
#   caddy           Caddy; liest vom Panel nur das Agent-Token und die Prüf-Kopien
#   caddy-sentinel  Panel (ohne Login), Zusatzgruppe caddy für /etc/caddy
#
#   <BASE>          = /var/lib/caddy-sentinel   caddy-sentinel:caddy 2750
#     agent.token                                caddy-sentinel:caddy 0640
#     staging/                                   caddy-sentinel:caddy 2750
#     geo/ …        (GeoIP, von Caddy gelesen)   caddy-sentinel:caddy g+r
#     data/         = SENTINEL_DATA              caddy-sentinel:caddy-sentinel 0700
#                     sentinel.db*, mirror/, validate-data/
#
# Frühere Installationen (Layout "legacy"): Panel als Benutzer caddy,
# SENTINEL_DATA=<BASE> mit Datenbank direkt in <BASE> (caddy:caddy 0750).
PANEL_USER=caddy-sentinel
ENV_FILE=/etc/default/caddy-sentinel
DB_FILES="sentinel.db sentinel.db-wal sentinel.db-shm mirror validate-data"

env_get() { # KEY [Datei]
	[ -f "${2:-$ENV_FILE}" ] || return 0
	sed -n "s/^$1=//p" "${2:-$ENV_FILE}" | tail -n1 | tr -d "\"'"
}
env_set() { # KEY VALUE (Datei liegt in /etc/default, nur root schreibt dort)
	if grep -q "^$1=" "$ENV_FILE" 2>/dev/null; then
		sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
	else
		printf '%s=%s\n' "$1" "$2" >>"$ENV_FILE"
	fi
}

# layout_of [Datei]: setzt LAYOUT (user|legacy) und BASE aus einer
# /etc/default/caddy-sentinel. Mit eigenem Benutzer liegt das Agent-Token
# außerhalb des Datenverzeichnisses (SENTINEL_TOKEN_FILE=<BASE>/agent.token,
# SENTINEL_DATA=<BASE>/data); früher lag es darin.
layout_of() {
	local f=${1:-$ENV_FILE} data tok
	data=$(env_get SENTINEL_DATA "$f")
	data=${data:-/var/lib/caddy-sentinel}
	tok=$(env_get SENTINEL_TOKEN_FILE "$f")
	if [ -n "$tok" ] && [ "$(dirname -- "$tok")" != "$data" ]; then
		LAYOUT=user BASE=$(dirname -- "$tok")
	else
		LAYOUT=legacy BASE=$data
	fi
}

ensure_panel_user() {
	getent group caddy >/dev/null || groupadd --system caddy
	getent group "$PANEL_USER" >/dev/null || groupadd --system "$PANEL_USER"
	if ! id "$PANEL_USER" >/dev/null 2>&1; then
		useradd --system --gid "$PANEL_USER" --groups caddy --no-create-home --home-dir "${BASE:-/var/lib/caddy-sentinel}" \
			--shell /usr/sbin/nologin --comment "Caddy Sentinel panel" "$PANEL_USER"
	elif ! id -nG "$PANEL_USER" | tr ' ' '\n' | grep -qx caddy; then
		usermod -a -G caddy "$PANEL_USER"
	fi
}

remove_panel_user() {
	id "$PANEL_USER" >/dev/null 2>&1 && userdel "$PANEL_USER" 2>/dev/null
	getent group "$PANEL_USER" >/dev/null && groupdel "$PANEL_USER" 2>/dev/null
	return 0
}

# move_db FROM TO STALE: Datenbank und Arbeitsverzeichnisse des Panels von
# FROM nach TO verschieben; schon in TO vorhandene (veraltete) Einträge
# kommen nach STALE. Nur im gesperrten Baum aufrufen.
move_db() {
	local f
	for f in $DB_FILES; do
		[ -e "$1/$f" ] || [ -L "$1/$f" ] || continue
		if [ -e "$2/$f" ] || [ -L "$2/$f" ]; then
			install -d -m 0700 -- "$3"
			mv -f -- "$2/$f" "$3/"
		fi
		[ -d "$2" ] || install -d -m 0700 -- "$2"
		mv -f -- "$1/$f" "$2/$f"
	done
}

# restore_db FROM DIR OWNER:GROUP MODE: Datenbank aus einer Sicherung (nur
# root zugänglich) in DIR des gesperrten Baums einspielen
restore_db() {
	local f
	rm -rf -- "$2"/sentinel.db "$2"/sentinel.db-wal "$2"/sentinel.db-shm
	for f in "$1"/sentinel.db*; do
		[ -f "$f" ] && install -o "${3%%:*}" -g "${3##*:}" -m "$4" -- "$f" "$2/"
	done
}

# layout_user BASE ACTIVE_IN_BASE [DB_BACKUP]: Verzeichnisse für den eigenen
# Panel-Benutzer herstellen (idempotent). ACTIVE_IN_BASE=1: die aktive
# Datenbank liegt noch direkt in BASE (Umstellung einer älteren Installation).
layout_user() {
	local base=$1 legacy=$2 dbsrc=${3:-} data=$1/data ts
	ts=$(date +%Y%m%d-%H%M%S)
	if [ -L "$base" ] || { [ -e "$base" ] && [ ! -d "$base" ]; }; then
		warn "$base ist kein Verzeichnis (symbolischer Link?) – bitte selbst durch ein Verzeichnis ersetzen."
		return 1
	fi
	root_only "$(dirname -- "$base")" || { warn "$(dirname -- "$base") ist nicht nur für root beschreibbar."; return 1; }
	[ -d "$base" ] || install -d -m 0700 -- "$base"
	lock_tree "$base" || return 1
	if [ -L "$data" ] || { [ -e "$data" ] && [ ! -d "$data" ]; }; then
		mv -f -- "$data" "$base/data.ungueltig-$ts"
	fi
	[ -d "$data" ] || install -d -m 0700 -- "$data"
	if [ "$legacy" = 1 ]; then
		move_db "$base" "$data" "$data/alt-$ts"
	else
		# eine Datenbank direkt in BASE wäre für Caddy lesbar – beiseite legen
		move_db "$base" "$data/alt-$ts" "$data/alt-$ts/alt"
	fi
	[ -z "$dbsrc" ] || restore_db "$dbsrc" "$data" "$PANEL_USER:$PANEL_USER" 0600
	# Rechte (noch gehört alles root): gemeinsamer Teil für Caddy (Gruppe)
	# lesbar, neue Einträge erben die Gruppe; data nur für das Panel
	find -P "$base" -mindepth 1 -path "$data" -prune -o -type d -exec chmod g+rx,g+s,g-w,o-rwx -- {} +
	find -P "$base" -mindepth 1 -path "$data" -prune -o -type f -links 1 -exec chmod g+r,g-w,o-rwx -- {} +
	chmod 0700 -- "$data"
	# Besitz: erst data, dann der Rest, BASE selbst zuletzt
	give "$data" "$PANEL_USER:$PANEL_USER"
	give "$base" "$PANEL_USER:caddy" "$data"
	chmod 2750 -- "$base"
}

# layout_legacy BASE [DB_BACKUP]: früheren Zustand herstellen (Rollback auf
# eine Version ohne eigenen Panel-Benutzer)
layout_legacy() {
	local base=$1 dbsrc=${2:-} data=$1/data ts
	ts=$(date +%Y%m%d-%H%M%S)
	[ -d "$base" ] && [ ! -L "$base" ] || return 0
	root_only "$(dirname -- "$base")" || { warn "$(dirname -- "$base") ist nicht nur für root beschreibbar."; return 1; }
	lock_tree "$base" || return 1
	if [ -d "$data" ] && [ ! -L "$data" ]; then
		move_db "$data" "$base" "$base/alt-$ts"
		rmdir -- "$data" 2>/dev/null || true
	fi
	[ -z "$dbsrc" ] || restore_db "$dbsrc" "$base" caddy:caddy 0640
	find -P "$base" -type d -exec chmod g-s -- {} +
	chmod 0750 -- "$base"
	give "$base" caddy:caddy
}

# etc_caddy_fix [OWNER]: /etc/caddy für die Gruppe caddy beschreibbar machen
# (setgid: neue Dateien gehören zur Gruppe caddy, Caddy kann sie lesen).
# OWNER gesetzt: Dateien des Panel-Benutzers gehen an OWNER (Rollback,
# Deinstallation). Erst sperren (Verzeichnisse root, ohne Gruppen-
# Schreibrecht, von oben nach unten), dann ändern, dann von unten nach oben
# wieder freigeben – so zeigt kein bearbeiteter Pfad auf etwas anderes.
etc_caddy_fix() {
	local d=/etc/caddy owner=${1:-} setgid=g+s
	[ -n "$owner" ] && setgid=g-s
	if [ -L "$d" ] || [ ! -d "$d" ]; then
		[ -e "$d" ] && warn "$d ist ein symbolischer Link – Rechte bitte selbst setzen (Gruppe caddy, schreibbar, setgid)."
		return 0
	fi
	# Verzeichnisse von caddy bzw. caddy-sentinel gehen an root (deren
	# Besitzer könnte die Sperre sonst selbst aufheben)
	local who=() u
	for u in caddy "$PANEL_USER"; do
		id "$u" >/dev/null 2>&1 && who+=(-user "$u" -o)
	done
	who+=(-false)
	find -P "$d" -type d \( \( "${who[@]}" \) -exec chown -h root -- {} \; -o -true \) -exec chmod g-w,o-w -- {} \;
	[ -e "$d/sites" ] || [ -L "$d/sites" ] || install -d -m 0775 -- "$d/sites"
	if [ -n "$owner" ] && id "$PANEL_USER" >/dev/null 2>&1; then
		find -P "$d" -user "$PANEL_USER" \( -type f -links +1 \) -prune -o -user "$PANEL_USER" -exec chown -h -- "$owner" {} +
	fi
	find -P "$d" \( -type f -links +1 \) -prune -o -exec chgrp -h caddy -- {} +
	find -P "$d" -maxdepth 3 -type f -links 1 \( -name 'Caddyfile*' -o -name '*.caddy' -o -name '*.caddyfile' -o -name '*.conf' -o -name '*.snippet' \) -exec chmod g+rw -- {} +
	find -P "$d" -depth -type d -perm -g=x -exec chmod "g+rwx,$setgid" -- {} \;
}

# ------------------------------------------------------------ Admin-API als Unix-Socket
# Caddy lauscht mit der Ergänzung der Caddy-Unit (CADDY_ADMIN, RuntimeDirectory)
# nicht mehr auf localhost:2019, sondern auf /run/caddy/admin.sock (0660,
# Gruppe caddy). Eine globale Option "admin" in der Caddyfile hat Vorrang.
ADMIN_URL=unix//run/caddy/admin.sock

# caddyfile_admin DATEI: Wert der globalen Option "admin" (leer = keine)
caddyfile_admin() {
	awk '
		st == 0 && /^[[:space:]]*($|#)/ { next }
		st == 0 { if ($0 ~ /^[[:space:]]*\{[[:space:]]*(#.*)?$/) { st = 1; d = 1; next } exit }
		{
			l = $0; sub(/(^|[[:space:]])#.*$/, "", l)
			if (d == 1 && l ~ /^[[:space:]]*admin([[:space:]]|$)/) {
				n = split(l, a, /[[:space:]]+/); v = ""
				for (i = 1; i < n; i++) if (a[i] == "admin") { v = a[i + 1]; break }
				if (v == "" || v == "{") v = "localhost:2019"
				print v; exit
			}
			d += gsub(/\{/, "{", l) - gsub(/\}/, "}", l)
			if (d <= 0) exit
		}' "$1"
}

# sync_admin_env OVERRIDE: SENTINEL_CADDY_ADMIN an die tatsächliche
# Admin-Adresse anpassen – Socket, wenn die Caddy-Ergänzung CADDY_ADMIN setzt
# und die Caddyfile keine eigene "admin"-Option hat; zurück auf localhost,
# wenn die Ergänzung keinen Socket (mehr) setzt.
sync_admin_env() {
	local cur="" sock=0
	[ -f "$ENV_FILE" ] || return 0
	grep -q "^Environment=CADDY_ADMIN=$ADMIN_URL" "$1" 2>/dev/null && sock=1
	if safe_copy /etc/caddy/Caddyfile "$TMP/Caddyfile.admin"; then
		cur=$(caddyfile_admin "$TMP/Caddyfile.admin")
	fi
	case "$cur" in
	"") ;;
	"$ADMIN_URL" | "$ADMIN_URL|"*)
		env_set SENTINEL_CADDY_ADMIN "$ADMIN_URL"
		return 0
		;;
	*)
		warn "Die Caddyfile setzt die Admin-API selbst (admin $cur) – das hat Vorrang vor dem Unix-Socket $ADMIN_URL. SENTINEL_CADDY_ADMIN in $ENV_FILE muss dazu passen (jetzt: $(env_get SENTINEL_CADDY_ADMIN)); sicherer: die Zeile entfernen."
		return 0
		;;
	esac
	if [ "$sock" = 1 ]; then
		env_set SENTINEL_CADDY_ADMIN "$ADMIN_URL"
	elif [ "$(env_get SENTINEL_CADDY_ADMIN)" = "$ADMIN_URL" ]; then
		env_set SENTINEL_CADDY_ADMIN http://127.0.0.1:2019
	fi
}

# agent_admin_lines: Zeilen für die Caddy-Ergänzung im Agent-Modus
agent_admin_lines() {
	echo "# Admin-API nur als Unix-Socket (statt localhost:2019 für alle lokalen Prozesse)"
	echo "Environment=CADDY_ADMIN=$ADMIN_URL|0660"
	echo "RuntimeDirectory=caddy"
	echo "RuntimeDirectoryMode=0750"
}

# agent_admin_http: steht im sentinel-Block eine feste HTTP-Admin-Adresse
# ("admin http://…")? Dann bleibt Caddys Admin-API auf TCP – der Agent
# erreichte sie über den Socket sonst nicht.
agent_admin_http() {
	grep -rqsE '^[[:space:]]*admin[[:space:]]+https?://' /etc/caddy --include='Caddyfile*' --include='*.caddy' --include='*.caddyfile' --include='*.conf'
}

# warn_explicit_admin: eine globale Option "admin" übersteuert den Socket
warn_explicit_admin() {
	local cur=""
	if safe_copy /etc/caddy/Caddyfile "$TMP/Caddyfile.admin"; then cur=$(caddyfile_admin "$TMP/Caddyfile.admin"); fi
	if [ -n "$cur" ]; then
		warn "Die Caddyfile setzt die Admin-API selbst (admin $cur) – sie bleibt dort statt auf $ADMIN_URL."
	fi
	if agent_admin_http; then
		warn "Im sentinel-Block steht „admin http://…“ – die Admin-API bleibt deshalb auf TCP (localhost:2019, für alle lokalen Prozesse erreichbar). Für den Unix-Socket die Zeile entfernen (der Agent übernimmt Caddys Admin-Adresse dann selbst) und erneut aktualisieren."
	fi
}

# Layout der laufenden Installation; SENTINEL_DATA aus der Umgebung hat Vorrang
LAYOUT=legacy BASE=/var/lib/caddy-sentinel
[ -r "$ENV_FILE" ] && layout_of
DATA_DIR=${SENTINEL_DATA:-$(env_get SENTINEL_DATA)}
DATA_DIR=${DATA_DIR:-$BASE}

# Umstellung auf den eigenen Panel-Benutzer nötig?
# (eigener Benutzer; bei lokalem Caddy auch die Admin-API als Unix-Socket)
needs_migration() {
	if [ -f /etc/systemd/system/caddy.service.d/sentinel.conf ] &&
		! grep -q '^Environment=CADDY_ADMIN=' /etc/systemd/system/caddy.service.d/sentinel.conf; then
		return 0
	fi
	[ "$LAYOUT" = user ] && id "$PANEL_USER" >/dev/null 2>&1 &&
		grep -qx "User=$PANEL_USER" /etc/systemd/system/caddy-sentinel.service 2>/dev/null && return 1
	return 0
}

# Agent-Server (install.sh --agent): nur Caddy mit Sentinel-Modul, kein Panel
AGENT_DROPIN=/etc/systemd/system/caddy.service.d/sentinel.conf
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
	# the token only goes to GitHub itself, never to a mirror (SENTINEL_DOWNLOAD)
	case "$1" in
	https://github.com/* | https://api.github.com/*) [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN") ;;
	esac
	if command -v curl >/dev/null; then curl -fsSL --retry 3 "${auth[@]}" -o "$2" "$1"; else wget -q -O "$2" "$1"; fi
}
# ------------------------------------------------------------ Signatur der Prüfsummen
# SHA256SUMS liegt neben den Archiven und schützt allein nur vor
# Übertragungsfehlern. Die Release-Action signiert SHA256SUMS mit einem
# SSH-Schlüssel (SHA256SUMS.sig, ssh-keygen -Y sign); geprüft wird mit
# ssh-keygen -Y verify – OpenSSH ist auf praktisch jedem Server vorhanden.
# Öffentlicher Schlüssel (eine Zeile je Schlüssel, beim Wechsel alter und
# neuer): leer = keine Pflicht. Muss scripts/release-signing.pub
# entsprechen (die CI prüft das). Ist ein Schlüssel bekannt, ist eine
# gültige Signatur Pflicht; abschalten nur mit --skip-signature.
RELEASE_SIGNING_PUBKEY=''
SIG_NAMESPACE=caddy-sentinel-release

# signing_keys: eingebauter Schlüssel, sonst der bei einer früheren
# Installation gemerkte (so fällt die Pflicht nicht weg, wenn ein Skript
# ohne Schlüssel auftaucht)
signing_keys() {
	if [ -n "$RELEASE_SIGNING_PUBKEY" ]; then
		printf '%s\n' "$RELEASE_SIGNING_PUBKEY"
	elif [ -s "$SHARE_DIR/release-signing.pub" ]; then
		cat "$SHARE_DIR/release-signing.pub"
	fi
}

# verify_signature BASIS-URL: $TMP/SHA256SUMS gegen BASIS-URL/SHA256SUMS.sig
verify_signature() {
	local keys
	keys=$(signing_keys)
	[ -n "$keys" ] || return 0
	if [ "$SKIP_SIG" = 1 ]; then
		warn "Signaturprüfung ausdrücklich abgeschaltet (--skip-signature) – die Herkunft der Prüfsummen ist NICHT geprüft."
		return 0
	fi
	command -v ssh-keygen >/dev/null || die "ssh-keygen (OpenSSH) fehlt – nötig für die Signatur der Release-Prüfsummen (Paket openssh-client bzw. openssh)."
	fetch "$1/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" 2>/dev/null ||
		die "Das Release hat keine Signatur (SHA256SUMS.sig), es ist aber ein Signaturschlüssel hinterlegt – Abbruch. (Nur wenn du der Quelle sicher vertraust: --skip-signature)"
	printf '%s\n' "$keys" | awk -v ns="$SIG_NAMESPACE" 'NF && $1 !~ /^#/ { print ns " namespaces=\"" ns "\" " $0 }' >"$TMP/allowed_signers"
	if ! ssh-keygen -Y verify -f "$TMP/allowed_signers" -I "$SIG_NAMESPACE" -n "$SIG_NAMESPACE" -s "$TMP/SHA256SUMS.sig" <"$TMP/SHA256SUMS" >"$TMP/signature.log" 2>&1; then
		cat "$TMP/signature.log" >&2
		die "Die Signatur der Prüfsummen ist ungültig – Abbruch. Archiv oder Prüfsummen wurden verändert oder nicht mit dem hinterlegten Schlüssel signiert."
	fi
	say "Signatur der Prüfsummen gültig"
}

# pubkey_of SKRIPT: RELEASE_SIGNING_PUBKEY eines anderen Skripts (ohne es auszuführen)
pubkey_of() {
	awk -v q="'" '
		index($0, "RELEASE_SIGNING_PUBKEY=" q) == 1 { f = 1; $0 = substr($0, 25) }
		f { i = index($0, q); if (i) { printf "%s", substr($0, 1, i - 1); exit } print }
	' "$1" 2>/dev/null
}

# remember_signing_key [SKRIPT]: Schlüssel für spätere Updates merken – aus
# dem neu installierten Skript (Schlüsselwechsel), sonst dem eigenen
remember_signing_key() {
	local keys=""
	[ -n "${1:-}" ] && keys=$(pubkey_of "$1")
	[ -n "$keys" ] || keys=$(signing_keys)
	[ -n "$keys" ] || return 0
	printf '%s\n' "$keys" >"$TMP/release-signing.pub"
	install -m 0644 "$TMP/release-signing.pub" "$SHARE_DIR/release-signing.pub"
}

# Herkunftsnachweis (optional, --verify-attestation): SHA256SUMS liegt neben
# dem Archiv und schützt nur vor Übertragungsfehlern; die Release-Action
# signiert die Archive (Sigstore). gh prüft, dass das Archiv in diesem
# Repository gebaut wurde – auch beim Download über einen Spiegel.
verify_attestation() { # datei
	[ "$VERIFY_ATT" = 1 ] || return 0
	command -v gh >/dev/null || die "--verify-attestation braucht die GitHub-CLI (gh) – installieren oder den Schalter weglassen."
	say "Prüfe Herkunftsnachweis (gh attestation verify)"
	gh attestation verify "$1" --repo "$REPO" >"$TMP/attestation.log" 2>&1 || {
		cat "$TMP/attestation.log" >&2
		die "Herkunftsnachweis für $(basename "$1") fehlt oder ist ungültig – Abbruch. (gh braucht eine Anmeldung: gh auth login oder GH_TOKEN)"
	}
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
	l=$(env_get SENTINEL_LISTEN)
	l=${l:-127.0.0.1:7600}
	case "$l" in
	0.0.0.0:*) l=127.0.0.1:${l#0.0.0.0:} ;;
	"[::]:"*) l="[::1]:${l#\[::\]:}" ;;
	:*) l=127.0.0.1$l ;;
	esac
	echo "http://$l"
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
# Platz für die Sicherung prüfen, bevor etwas gestoppt wird
check_backup_space() {
	local need avail
	install -d -m 0700 "$BACKUP_ROOT"
	need=$(du -sk "$BIN_DIR/caddy-sentinel" "$BIN_DIR/caddy" "$DATA_DIR"/sentinel.db* 2>/dev/null | awk '{s+=$1} END {print int(s*1.1)+51200}')
	avail=$(df -Pk "$BACKUP_ROOT" | awk 'NR==2 {print $4}')
	[ -n "$avail" ] && [ "$avail" -lt "$need" ] && die "Zu wenig Platz in $BACKUP_ROOT für die Sicherung ($((need / 1024)) MB nötig, $((avail / 1024)) MB frei). Alte Sicherungen löschen oder Platz schaffen."
	return 0
}

# save_regular src dst: nur echte Dateien sichern. /etc/caddy und das
# Verzeichnis des Panels sind für andere Benutzer beschreibbar – ein dort
# untergeschobener Symlink oder Hardlink (z. B. auf /etc/shadow) darf weder
# gesichert noch beim Rollback mit lesbaren Rechten zurückgeschrieben werden.
save_regular() {
	safe_copy "$1" "$2" || true
}

# setzt BACKUP; bricht bei jedem Fehler ab (kein "$(…)": dort gilt set -e nicht)
backup() {
	local dir f
	dir="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)-$CURRENT"
	install -d -m 0700 "$dir" || return 1
	cp -a "$BIN_DIR/caddy-sentinel" "$dir/" || return 1
	if [ "$HAS_CADDY" = 1 ]; then cp -a "$BIN_DIR/caddy" "$dir/" || return 1; fi
	save_regular /etc/systemd/system/caddy-sentinel.service "$dir/caddy-sentinel.service"
	save_regular /etc/systemd/system/caddy.service.d/sentinel.conf "$dir/caddy-override.conf"
	save_regular "$ENV_FILE" "$dir/caddy-sentinel.env"
	save_regular "$CADDYFILE" "$dir/Caddyfile"
	# Datenbank konsistent sichern: Panel ist zu diesem Zeitpunkt gestoppt.
	# safe_copy öffnet ohne Symlinks zu folgen (das Verzeichnis gehört dem
	# Panel-Benutzer bzw. früher caddy).
	for f in sentinel.db sentinel.db-wal sentinel.db-shm; do
		if [ -e "$DATA_DIR/$f" ] || [ -L "$DATA_DIR/$f" ]; then
			safe_copy "$DATA_DIR/$f" "$dir/$f" || { warn "$DATA_DIR/$f ist keine reguläre Datei – nicht gesichert."; return 1; }
		fi
	done
	echo "$CURRENT" >"$dir/VERSION" || return 1
	sync
	# alte Sicherungen aufräumen: Programme der letzten $KEEP_BACKUPS Versionen,
	# die (große) Datenbank nur in den letzten $KEEP_DB_BACKUPS
	find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -name 'vor-*' | sort | head -n -"$KEEP_BACKUPS" | xargs -r rm -rf
	find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -name 'vor-*' | sort | head -n -"$KEEP_DB_BACKUPS" | while read -r d; do rm -f "$d"/sentinel.db*; done
	BACKUP=$dir
}

# restore_file backup target mode owner: target auf den Stand der Sicherung.
# Eine abweichende aktuelle Fassung kommt nach $BACKUP_ROOT/vor-rollback-<Zeit>
# (nur root) – nicht neben das Ziel, wo ein Symlink sie umleiten könnte.
restore_file() {
	local src=$1 dst=$2 owner=$4 keep
	[ -f "$src" ] && [ ! -L "$src" ] || return 0
	if [ -L "$dst" ]; then
		warn "$dst ist ein symbolischer Link – nicht zurückgesetzt."
		return 0
	fi
	if [ -e "$dst" ]; then
		safe_copy "$dst" "$TMP/aktuell" || { warn "$dst ist keine reguläre Datei – nicht zurückgesetzt."; return 0; }
		cmp -s "$src" "$TMP/aktuell" && return 0
		keep="$BACKUP_ROOT/vor-rollback-$(date +%Y%m%d-%H%M%S)"
		install -d -m 0700 "$keep"
		install -m 0600 "$TMP/aktuell" "$keep/$(basename "$dst")"
		warn "$dst hatte sich seit der Sicherung geändert – aktuelle Fassung aufbewahrt in $keep/"
	fi
	if root_only "$(dirname "$dst")"; then
		# Besitzer und Rechte in einem Schritt (kein Zeitfenster mit falschen Rechten)
		install -o "${owner%%:*}" -g "${owner##*:}" -m "$3" "$src" "$dst"
	else
		put_file "$src" "$dst" "$3" "$owner" || warn "$dst nicht zurückgesetzt."
	fi
}

# apply_layout user|legacy BASE [DB_BACKUP]: Benutzer, Verzeichnisse und
# /etc/caddy für das Layout herstellen (idempotent). user: eigener Benutzer
# caddy-sentinel (die aktive Datenbank liegt noch in BASE, wenn die Umgebung
# das alte Layout zeigt). legacy: Panel wieder als caddy, Benutzer entfernen.
apply_layout() {
	local want=$1 base=$2 db=${3:-} from_legacy=0
	if [ "$want" = user ]; then
		[ "$LAYOUT" = legacy ] && from_legacy=1
		ensure_panel_user || return 1
		layout_user "$base" "$from_legacy" "$db" || return 1
		etc_caddy_fix
	else
		layout_legacy "$base" "$db" || return 1
		etc_caddy_fix caddy
		remove_panel_user
	fi
}

# set_env_layout user|legacy BASE: Pfade in /etc/default/caddy-sentinel
set_env_layout() {
	[ -f "$ENV_FILE" ] || return 0
	if [ "$1" = user ]; then
		env_set SENTINEL_DATA "$2/data"
		env_set SENTINEL_TOKEN_FILE "$2/agent.token"
		env_set SENTINEL_STAGING "$2/staging"
	else
		env_set SENTINEL_DATA "$2"
		sed -i '/^SENTINEL_TOKEN_FILE=/d; /^SENTINEL_STAGING=/d' "$ENV_FILE"
	fi
}

restore() { # dir with_db
	local dir=$1 want base db=""
	say "Stelle Sicherung $(basename "$dir") wieder her"
	systemctl stop caddy-sentinel || true
	install -m 0755 "$dir/caddy-sentinel" "$BIN_DIR/caddy-sentinel"
	if [ -f "$dir/caddy" ]; then
		install -m 0755 "$dir/caddy" "$BIN_DIR/caddy"
		command -v setcap >/dev/null && setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	fi
	[ -f "$dir/caddy-sentinel.service" ] && install -m 0644 "$dir/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service
	# --keep-config: Ergänzung der Caddy-Unit bleibt, damit sie zur behaltenen
	# Einstellung SENTINEL_CADDY_ADMIN (Unix-Socket) passt
	if [ -f "$dir/caddy-override.conf" ] && [ "$KEEP_CONFIG" != 1 ]; then
		install -m 0644 "$dir/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf
	fi
	# Layout der Sicherung: Sicherungen älterer Versionen haben das alte
	# Layout (Panel als caddy) – dann Datenbank zurückverschieben, Rechte
	# zurücksetzen und den Benutzer caddy-sentinel entfernen
	if [ -f "$dir/caddy-sentinel.env" ]; then
		layout_of "$dir/caddy-sentinel.env"
		want=$LAYOUT base=$BASE
		layout_of
	else
		want=$LAYOUT base=$BASE
	fi
	# Einstellungen des Panels und Caddyfile auf den Stand der Sicherung;
	# abweichende aktuelle Fassungen kommen nach $BACKUP_ROOT/vor-rollback-<Zeit>
	if [ "$KEEP_CONFIG" != 1 ]; then
		restore_file "$dir/caddy-sentinel.env" "$ENV_FILE" 0644 root:root
		restore_file "$dir/Caddyfile" "$CADDYFILE" 0664 root:caddy
	fi
	# --keep-config: Einstellungen bleiben, nur die Pfade folgen dem Layout
	[ "$KEEP_CONFIG" = 1 ] && set_env_layout "$want" "$base"
	if [ "$2" = 1 ] && [ -f "$dir/sentinel.db" ]; then db=$dir; fi
	apply_layout "$want" "$base" "$db" || warn "Verzeichnisse/Benutzer für das Layout \"$want\" nicht vollständig hergestellt – bitte prüfen."
	LAYOUT=$want BASE=$base
	cat "$dir/VERSION" >"$SHARE_DIR/VERSION" 2>/dev/null || true
	systemctl daemon-reload
	systemctl start caddy-sentinel
	wait_panel || warn "Panel antwortet nach dem Zurückspielen nicht – journalctl -u caddy-sentinel"
	if [ -f "$dir/caddy" ] || [ -f "$dir/caddy-override.conf" ]; then
		systemctl restart caddy || warn "Caddy startet nicht – journalctl -u caddy"
	elif [ "$KEEP_CONFIG" != 1 ] && [ -f "$dir/Caddyfile" ]; then
		systemctl reload caddy 2>/dev/null || true
	fi
}

[ "$(id -u)" = 0 ] || [ "$MODE" = check ] || die "Bitte als root bzw. mit sudo ausführen."

if [ "$MODE" = rollback ] && [ "$AGENT" = 1 ]; then
	last=$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -name 'vor-*' 2>/dev/null | sort -r | head -n1)
	[ -n "$last" ] && [ -f "$last/caddy" ] || die "Keine Sicherung in $BACKUP_ROOT gefunden."
	confirm "Caddy aus $(basename "$last") zurückspielen?" || exit 1
	install -m 0755 "$last/caddy" "$BIN_DIR/caddy"
	command -v setcap >/dev/null && setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	# Ergänzung der Caddy-Unit (Admin-Socket) auf den Stand der Sicherung
	if [ -f "$last/caddy-override.conf" ] && [ "$KEEP_CONFIG" != 1 ]; then
		install -m 0644 "$last/caddy-override.conf" "$AGENT_DROPIN"
		systemctl daemon-reload
	fi
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
	done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -name 'vor-*' 2>/dev/null | sort -r)
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
		# die VERSION-Datei ist nicht signiert: ein manipulierter Spiegel
		# könnte so ein älteres (gültig signiertes, aber verwundbares) Release
		# unterschieben – zurück nur mit ausdrücklichem --version
		case "$CURRENT$VERSION" in
		v[0-9]*v[0-9]*)
			# ohne Vorabkennung (-rc.1) vergleichen: v1.3.0 ist nicht älter als v1.3.0-rc.1
			if [ "${VERSION%%-*}" != "${CURRENT%%-*}" ] && [ "$(printf '%s\n' "${VERSION%%-*}" "${CURRENT%%-*}" | sort -V | tail -n1)" = "${CURRENT%%-*}" ]; then
				die "Als neueste Version wird $VERSION gemeldet, installiert ist aber schon $CURRENT – Abbruch. (Ein älteres Release nur mit --version $VERSION einspielen.)"
			fi
			;;
		esac
	fi
	[ -n "$VERSION" ] || die "Keine Version gefunden."
fi

MIGRATE=0
[ "$AGENT" = 0 ] && needs_migration && MIGRATE=1
if [ "$MODE" = check ]; then
	echo "Installiert: $CURRENT"
	echo "Verfügbar:   $VERSION"
	[ "$MIGRATE" = 1 ] && echo "Eigener Panel-Benutzer ($PANEL_USER) bzw. Admin-Socket: noch nicht eingerichtet – das nächste Update stellt um."
	if [ "$CURRENT" = "$VERSION" ] && [ "$MIGRATE" = 0 ]; then echo "Caddy Sentinel ist aktuell."; exit 0; fi
	[ "$CURRENT" = "$VERSION" ] || echo "Update verfügbar: https://github.com/$REPO/releases/tag/$VERSION"
	exit 10
fi

if [ -z "$SRC" ]; then
	if [ "$CURRENT" = "$VERSION" ] && [ "$FORCE" = 0 ]; then
		if [ "$MIGRATE" = 0 ]; then
			say "Bereits auf $CURRENT – nichts zu tun (--force installiert neu)."
			exit 0
		fi
		say "Bereits auf $CURRENT – richte den eigenen Panel-Benutzer $PANEL_USER bzw. den Admin-Socket ein (Version wird neu eingespielt)."
	fi
	name="caddy-sentinel_${VERSION}_linux_${ARCH}.tar.gz"
	base="$DL/download/$VERSION"
	say "Lade $name"
	fetch "$base/$name" "$TMP/$name" || die "Download fehlgeschlagen: $base/$name"
	fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" || die "Prüfsummen fehlen."
	verify_signature "$base"
	(cd "$TMP" && grep " $name\$" SHA256SUMS | sha256sum -c --quiet -) || die "Prüfsumme stimmt nicht – Abbruch."
	verify_attestation "$TMP/$name"
	install -d "$TMP/pkg"
	tar -C "$TMP/pkg" --strip-components=1 -xzf "$TMP/$name"
	SRC="$TMP/pkg"
fi
[ -x "$SRC/caddy-sentinel" ] || die "$SRC/caddy-sentinel fehlt."
NEW=$("$SRC/caddy-sentinel" -version | awk '{print $NF}')
[ "$AGENT" = 1 ] && HAS_CADDY=1
# Unit-Dateien: ab der Version mit eigenem Panel-Benutzer in deploy/systemd/.
# (Ältere update.sh kennen nur deploy/caddy-sentinel.service: aktualisieren
# sie auf diese Version, lassen sie die Units unverändert, das Panel läuft
# weiter als caddy, und das nächste Update mit diesem Skript stellt um.)
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /nonexistent)
DEPLOY="" WANT=$LAYOUT
for d in "$SRC/deploy" "$SCRIPT_DIR/../deploy"; do
	if [ -f "$d/systemd/caddy-sentinel.service" ]; then DEPLOY="$d/systemd" WANT=user; break; fi
	if [ -f "$d/caddy-sentinel.service" ]; then DEPLOY=$d WANT=legacy; break; fi
done
if [ "$AGENT" = 0 ] && [ -z "$DEPLOY" ] && [ "$MIGRATE" = 1 ]; then
	warn "Keine Unit-Dateien gefunden ($SRC/deploy/systemd) – der eigene Panel-Benutzer wird erst mit einem Release-Archiv eingerichtet."
fi
say "Update $CURRENT → $NEW"
[ "$AGENT" = 0 ] && [ "$WANT" = user ] && [ "$LAYOUT" = legacy ] &&
	say "Dabei: Panel läuft künftig als eigener Benutzer $PANEL_USER, Datenbank nach $BASE/data (für Caddy nicht lesbar)."
[ "$AGENT" = 0 ] && [ "$WANT" = legacy ] && [ "$LAYOUT" = user ] &&
	warn "Die Zielversion kennt den eigenen Panel-Benutzer nicht – das Panel läuft danach wieder als caddy."
confirm "Jetzt aktualisieren? Caddy wird dabei kurz neu gestartet." || exit 1
[ "$HAS_CADDY" = 1 ] && ensure_log_dir

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
	save_regular "$AGENT_DROPIN" "$BACKUP/caddy-override.conf"
	echo "$CURRENT" >"$BACKUP/VERSION"
	find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -name 'vor-*' | sort | head -n -"$KEEP_BACKUPS" | xargs -r rm -rf
	say "Installiere Caddy $("$SRC/caddy" version | awk '{print $1}')"
	install -m 0755 "$SRC/caddy" "$BIN_DIR/caddy"
	command -v setcap >/dev/null && setcap cap_net_bind_service=+ep "$BIN_DIR/caddy" || true
	# Admin-API als Unix-Socket: die Agent-Ergänzung bekommt CADDY_ADMIN und
	# RuntimeDirectory (Agenten dieser Version sprechen Unix-Sockets und
	# übernehmen Caddys Admin-Adresse); auf ältere Versionen wieder ohne
	if [ -f "$BACKUP/caddy-override.conf" ]; then
		if [ "$WANT" = user ]; then
			if agent_admin_http; then
				warn_explicit_admin
			elif ! grep -q '^Environment=CADDY_ADMIN=' "$AGENT_DROPIN"; then
				{ cat "$BACKUP/caddy-override.conf"; agent_admin_lines; } >"$TMP/agent-dropin.conf"
				install -m 0644 "$TMP/agent-dropin.conf" "$AGENT_DROPIN"
				say "Admin-API von Caddy jetzt als Unix-Socket /run/caddy/admin.sock"
			fi
		else
			grep -vE '^(Environment=CADDY_ADMIN=|RuntimeDirectory|# Admin-API nur als Unix-Socket)' "$BACKUP/caddy-override.conf" >"$TMP/agent-dropin.conf" || true
			install -m 0644 "$TMP/agent-dropin.conf" "$AGENT_DROPIN"
		fi
		systemctl daemon-reload
	fi
	if ! systemctl restart caddy || ! wait_caddy; then
		warn "Caddy startet nicht – setze zurück."
		install -m 0755 "$BACKUP/caddy" "$BIN_DIR/caddy"
		if [ -f "$BACKUP/caddy-override.conf" ]; then
			install -m 0644 "$BACKUP/caddy-override.conf" "$AGENT_DROPIN"
			systemctl daemon-reload
		fi
		systemctl restart caddy || true
		die "Update fehlgeschlagen, alte Version ist wieder aktiv."
	fi
	install -d -m 0755 /usr/local/share/doc/caddy-sentinel
	for f in LICENSE NOTICE AUTHORS THIRD_PARTY_LICENSES.txt; do
		[ -f "$SRC/$f" ] && install -m 0644 "$SRC/$f" /usr/local/share/doc/caddy-sentinel/
	done
	for s in update uninstall; do
		[ -f "$SRC/$s.sh" ] && install -m 0755 "$SRC/$s.sh" "/usr/local/sbin/caddy-sentinel-$s"
	done
	echo "$NEW" >"$SHARE_DIR/VERSION"
	remember_signing_key "$SRC/update.sh"
	say "Caddy mit Sentinel-Agent ist jetzt auf $NEW (Sicherung: $BACKUP)."
	exit 0
fi

# ------------------------------------------------------------ Panel
CADDY_RESTART=0
say "Sichere aktuelle Installation"
check_backup_space
systemctl stop caddy-sentinel
if ! backup; then
	systemctl start caddy-sentinel || true
	die "Sicherung nach $BACKUP_ROOT fehlgeschlagen – Update abgebrochen, die bisherige Version läuft weiter."
fi
echo "    $BACKUP"

rollback() {
	warn "$1 – setze auf $CURRENT zurück."
	restore "$BACKUP" 0
	die "Update fehlgeschlagen, alte Version ist wieder aktiv."
}

# Benutzer, Verzeichnisse und Rechte (bei jedem Update, idempotent): eigener
# Panel-Benutzer, Datenbank in BASE/data (0700), Token und Prüf-Kopien für
# Caddy lesbar, /etc/caddy für die Gruppe caddy beschreibbar (setgid)
if [ -n "$DEPLOY" ]; then
	[ "$WANT" != "$LAYOUT" ] && say "Stelle Benutzer und Verzeichnisse um ($LAYOUT → $WANT)"
	set_env_layout "$WANT" "$BASE"
	apply_layout "$WANT" "$BASE" || rollback "Benutzer/Verzeichnisse konnten nicht eingerichtet werden"
	LAYOUT=$WANT
	DATA_DIR=$(env_get SENTINEL_DATA)
	DATA_DIR=${DATA_DIR:-$BASE}
fi

say "Installiere Panel $NEW"
install -m 0755 "$SRC/caddy-sentinel" "$BIN_DIR/caddy-sentinel"
if [ -n "$DEPLOY" ] && ! cmp -s "$DEPLOY/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service; then
	install -m 0644 "$DEPLOY/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service
	say "Unit caddy-sentinel.service aktualisiert"
fi
if [ "$HAS_CADDY" = 1 ] && [ -n "$DEPLOY" ] && [ -f "$DEPLOY/caddy-override.conf" ]; then
	# Vorlage mit der eingestellten Panel-Adresse und dem Token-Pfad
	# vergleichen, nicht mit dem Standard
	tok=$(env_get SENTINEL_TOKEN_FILE)
	sed -e "s|^Environment=SENTINEL_PANEL=.*|Environment=SENTINEL_PANEL=$(panel_url)|" \
		-e "s|^Environment=SENTINEL_TOKEN_FILE=.*|Environment=SENTINEL_TOKEN_FILE=${tok:-$BASE/agent.token}|" \
		"$DEPLOY/caddy-override.conf" >"$TMP/caddy-override.conf"
	if ! cmp -s "$TMP/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf; then
		install -d /etc/systemd/system/caddy.service.d
		install -m 0644 "$TMP/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf
		say "Caddy-Override aktualisiert"
		CADDY_RESTART=1
	fi
	# Admin-API: Socket aus CADDY_ADMIN (bzw. wieder TCP bei älteren Versionen)
	sync_admin_env /etc/systemd/system/caddy.service.d/sentinel.conf
fi
install -d -m 0755 /usr/local/share/doc/caddy-sentinel
for f in LICENSE NOTICE AUTHORS THIRD_PARTY_LICENSES.txt; do
	[ -f "$SRC/$f" ] && install -m 0644 "$SRC/$f" /usr/local/share/doc/caddy-sentinel/
done
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
	CADDY_RESTART=1
fi
if [ "$HAS_CADDY" = 1 ] && [ "$CADDY_RESTART" = 1 ]; then
	systemctl restart caddy || rollback "Caddy startet nicht"
	wait_caddy || rollback "Caddy läuft nicht stabil"
fi

echo "$NEW" >"$SHARE_DIR/VERSION"
remember_signing_key "$SRC/update.sh"
cat <<EOF

Caddy Sentinel ist jetzt auf $NEW.
  Benutzer:    Panel $(sed -n 's/^User=//p' /etc/systemd/system/caddy-sentinel.service | tail -n1), Caddy caddy – Datenbank in $DATA_DIR
  Änderungen:  https://github.com/$REPO/releases/tag/$NEW
  Sicherung:   $BACKUP
  Zurück:      sudo caddy-sentinel-update --rollback

EOF
