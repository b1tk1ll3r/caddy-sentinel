#!/usr/bin/env bash
# Caddy Sentinel – Installation und Update als systemd-Dienste
# (Debian, Ubuntu, RHEL, Raspberry Pi OS …)
#
# Ein Befehl – installiert beim ersten Mal und aktualisiert danach:
#   bash <(wget -qO- https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh)
#   bash <(curl -fsSL https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh)
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
#     --token TOKEN    Token der Instanz (Panel › Caddy-Instanzen); besser: SENTINEL_AGENT_TOKEN=TOKEN
#     --remote MODUS   full (Caddyfile im Panel bearbeitbar, Standard) | read | off
#   --reinstall        auch bei vorhandener Installation neu installieren
#   --force            auch dieselbe Version erneut einspielen
#   --no-start         Dienste nicht starten
#   --skip-signature   Signatur der Prüfsummen nicht prüfen (nur in Notfällen;
#                      Standard: Pflicht, sobald ein Signaturschlüssel hinterlegt ist)
#   --verify-attestation  Herkunftsnachweis des Archivs mit der GitHub-CLI
#                      prüfen (gh attestation verify; braucht gh und GH_TOKEN)
#   -y, --yes          keine Rückfragen
#
# Umgebung: SENTINEL_REPO (Standard b1tk1ll3r/caddy-sentinel),
#           SENTINEL_DOWNLOAD (Spiegel statt https://github.com/<repo>/releases),
#           SENTINEL_VERIFY_ATTESTATION=1 (wie --verify-attestation),
#           SENTINEL_SKIP_SIGNATURE=1 (wie --skip-signature)
#
# Benutzer: Caddy läuft als caddy, das Panel als eigener Systembenutzer
# caddy-sentinel (ohne Login, Zusatzgruppe caddy). Die Datenbank des
# Panels (/var/lib/caddy-sentinel/data, 0700) kann Caddy nicht lesen; Caddy
# liest nur das Agent-Token und die Prüf-Kopien (Gruppe caddy). Das Panel
# kann Caddys private Schlüssel nicht lesen.
set -euo pipefail

main() {

REPO=${SENTINEL_REPO:-b1tk1ll3r/caddy-sentinel}
VERSION=""
SRC=""
LISTEN=""
PANEL_ONLY=0
AGENT=0
PANEL_URL=""
# Token besser per Umgebung übergeben (SENTINEL_AGENT_TOKEN=… bash install.sh …):
# ein Argument steht für alle Benutzer sichtbar in der Prozessliste
AGENT_TOKEN="${SENTINEL_AGENT_TOKEN:-}"
if [ -z "$AGENT_TOKEN" ] && [ -n "${SENTINEL_AGENT_TOKEN_FILE:-}" ] && [ -f "$SENTINEL_AGENT_TOKEN_FILE" ]; then
	AGENT_TOKEN=$(tr -d '[:space:]' <"$SENTINEL_AGENT_TOKEN_FILE")
	rm -f "$SENTINEL_AGENT_TOKEN_FILE"
fi
REMOTE=full
START=1
YES=0
REINSTALL=0
FORCE=0
MODE_GIVEN=0
VERIFY_ATT=${SENTINEL_VERIFY_ATTESTATION:-0}
SKIP_SIG=${SENTINEL_SKIP_SIGNATURE:-0}
BIN_DIR=/usr/local/bin
SHARE_DIR=/usr/local/share/caddy-sentinel
BACKUP_ROOT=/var/backups/caddy-sentinel
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
	--verify-attestation) VERIFY_ATT=1 ;;
	--skip-signature) SKIP_SIG=1 ;;
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

# Caddy lädt den Sentinel-Agent nur, wenn die Caddyfile "sentinel" enthält
# (Direktive in einem Site-Block oder globale Option). Eine vorhandene
# Caddyfile – z. B. aus dem Distributionspaket – hat das nicht.
# /etc/caddy ist für die Gruppe caddy beschreibbar: gelesen wird eine
# geprüfte Kopie, geschrieben nur mit put_file, die Sicherung liegt in
# $BACKUP_ROOT (nur root).
ensure_sentinel_caddyfile() {
	local cf=/etc/caddy/Caddyfile bk owner mode
	[ -f "$cf" ] || return 0
	if grep -rqsE '^[[:space:]]*sentinel([[:space:]]|\{|$)' /etc/caddy --include='Caddyfile*' --include='*.caddy' --include='*.caddyfile' --include='*.conf'; then
		return 0
	fi
	warn "$cf enthält keine Direktive \"sentinel\" – ohne sie verbindet sich Caddy nicht mit dem Panel."
	confirm "Sentinel als globale Option in $cf eintragen?" || { warn "Nicht eingetragen – bitte \"sentinel\" selbst ergänzen (siehe docs/INSTALL.md)."; return 0; }
	safe_copy "$cf" "$TMP/Caddyfile.alt" || { warn "$cf ist keine reguläre Datei – bitte \"sentinel\" selbst ergänzen."; return 0; }
	install -d -m 0700 "$BACKUP_ROOT"
	bk="$BACKUP_ROOT/Caddyfile.vor-sentinel-$(date +%Y%m%d-%H%M%S)"
	install -m 0600 "$TMP/Caddyfile.alt" "$bk"
	# neue Fassung: root:caddy 0664 wie eine von install.sh angelegte Caddyfile
	owner=root:caddy mode=0664
	awk '
		!done && /^[[:space:]]*($|#)/ { buf = buf $0 "\n"; next }
		!done && /^[[:space:]]*\{[[:space:]]*$/ { printf "%s%s\n\tsentinel\n", buf, $0; done = 1; next }
		!done { printf "{\n\tsentinel\n}\n\n%s%s\n", buf, $0; done = 1; next }
		{ print }
		END { if (!done) printf "{\n\tsentinel\n}\n%s", buf }
	' "$TMP/Caddyfile.alt" >"$TMP/Caddyfile.neu"
	put_file "$TMP/Caddyfile.neu" "$cf" "$mode" "$owner" || { warn "Nicht eingetragen – bitte \"sentinel\" selbst ergänzen."; return 0; }
	if "$BIN_DIR/caddy" adapt --config "$cf" >/dev/null 2>&1; then
		say "Globale Option \"sentinel\" eingetragen (Sicherung: $bk)."
		say "Schutz pro Site: in jedem Site-Block, der geschützt werden soll, \"sentinel\" ergänzen."
	else
		put_file "$TMP/Caddyfile.alt" "$cf" "$mode" "$owner" || true
		warn "Eintragen fehlgeschlagen (Caddyfile ließ sich danach nicht lesen) – unverändert gelassen. Bitte \"sentinel\" selbst ergänzen."
	fi
}

# Log-Verzeichnis für "log { output file /var/log/caddy/… }": Caddy läuft als
# Benutzer caddy und legt die Dateien selbst an (wie im offiziellen Paket).
ensure_log_dir() {
	local d=/var/log/caddy
	if [ ! -d "$d" ]; then
		install -d -o caddy -g caddy -m 0755 "$d"
	elif ! runuser -u caddy -- test -w "$d" 2>/dev/null; then
		chown caddy:caddy "$d"
		chmod u+rwx "$d"
		warn "$d gehört jetzt dem Benutzer caddy (vorher nicht beschreibbar)."
	fi
}

# Adresse, unter der Caddy das Panel lokal erreicht (aus SENTINEL_LISTEN)
panel_probe() { # listen
	local l=${1:-127.0.0.1:7600}
	case "$l" in
	0.0.0.0:*) l=127.0.0.1:${l#0.0.0.0:} ;;
	"[::]:"*) l="[::1]:${l#\[::\]:}" ;;
	:*) l=127.0.0.1$l ;;
	esac
	echo "$l"
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

# Herkunftsnachweis (optional, --verify-attestation): die Prüfsummen liegen
# neben dem Archiv und schützen nur vor Übertragungsfehlern. Die Release-
# Action signiert die Archive zusätzlich (Sigstore, actions/attest-build-
# provenance); gh prüft, dass das Archiv in diesem Repository gebaut wurde –
# auch beim Download über einen Spiegel (SENTINEL_DOWNLOAD).
verify_attestation() { # datei
	[ "$VERIFY_ATT" = 1 ] || return 0
	command -v gh >/dev/null || die "--verify-attestation braucht die GitHub-CLI (gh) – installieren oder den Schalter weglassen."
	say "Prüfe Herkunftsnachweis (gh attestation verify)"
	gh attestation verify "$1" --repo "$REPO" >"$TMP/attestation.log" 2>&1 || {
		cat "$TMP/attestation.log" >&2
		die "Herkunftsnachweis für $(basename "$1") fehlt oder ist ungültig – Abbruch. (gh braucht eine Anmeldung: gh auth login oder GH_TOKEN)"
	}
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
	verify_signature "$base"
	(cd "$TMP" && grep " $name\$" SHA256SUMS | sha256sum -c --quiet -) || die "Prüfsumme stimmt nicht – Abbruch."
	verify_attestation "$TMP/$name"
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
# Unit-Dateien liegen in deploy/systemd/ (ältere Releases: deploy/)
DEPLOY=""
for d in "$SRC/deploy/systemd" "$SCRIPT_DIR/deploy/systemd" "$SCRIPT_DIR/../deploy/systemd"; do
	[ -f "$d/caddy-sentinel.service" ] && { DEPLOY=$(cd "$d" && pwd); break; }
done
if [ -z "$DEPLOY" ]; then
	# z. B. bei "curl | bash" mit --dir: Unit-Dateien aus dem Release holen
	download_release "$VERSION"
	DEPLOY="$SRC/deploy/systemd"
	[ -f "$DEPLOY/caddy-sentinel.service" ] || die "Unit-Dateien (deploy/systemd) fehlen im Release."
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
	[ "$VERIFY_ATT" = 1 ] && args+=(--verify-attestation)
	[ "$SKIP_SIG" = 1 ] && args+=(--skip-signature)
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
	[ -n "$PANEL_URL" ] && [ -n "$AGENT_TOKEN" ] || die "--agent braucht --panel URL und das Token (SENTINEL_AGENT_TOKEN=… oder --token, im Panel unter „Caddy-Instanzen“)."
	case "$REMOTE" in full | read | off) ;; *) die "--remote muss full, read oder off sein." ;; esac
fi

say "Installiere Caddy Sentinel $NEW_VERSION (linux/$ARCH)"

# ------------------------------------------------------------ Benutzer & Verzeichnisse
say "Benutzer und Verzeichnisse"
if ! getent group caddy >/dev/null; then groupadd --system caddy; fi
if ! id caddy >/dev/null 2>&1; then
	useradd --system --gid caddy --create-home --home-dir /var/lib/caddy --shell /usr/sbin/nologin --comment "Caddy web server" caddy
fi
install -d -m 0755 "$SHARE_DIR"
[ -d /etc/caddy ] || install -d -m 0755 /etc/caddy
if [ "$AGENT" = 0 ]; then
	# eigener Benutzer für das Panel; eine vorhandene Installation (auch eine
	# ältere, in der das Panel als caddy lief) wird umgestellt
	systemctl stop caddy-sentinel.service 2>/dev/null || true
	if [ -f "$ENV_FILE" ]; then
		layout_of
	else
		LAYOUT=new BASE=/var/lib/caddy-sentinel
		install -m 0644 "$DEPLOY/caddy-sentinel.env" "$ENV_FILE"
		[ "$PANEL_ONLY" = 1 ] && sed -i 's|^SENTINEL_CADDY_BIN=.*|SENTINEL_CADDY_BIN=|' "$ENV_FILE"
	fi
	ensure_panel_user
	layout_user "$BASE" "$([ "$LAYOUT" = legacy ] && echo 1)" || die "Verzeichnisse des Panels unter $BASE konnten nicht eingerichtet werden."
	env_set SENTINEL_DATA "$BASE/data"
	env_set SENTINEL_TOKEN_FILE "$BASE/agent.token"
	env_set SENTINEL_STAGING "$BASE/staging"
	[ "$LAYOUT" = legacy ] && say "Panel läuft künftig als Benutzer $PANEL_USER, Datenbank jetzt in $BASE/data"
	TOKEN_FILE="$BASE/agent.token"
fi
ensure_log_dir
if [ ! -f /etc/caddy/Caddyfile ] && [ ! -L /etc/caddy/Caddyfile ]; then
	cat >"$TMP/Caddyfile" <<'CF'
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
	put_file "$TMP/Caddyfile" /etc/caddy/Caddyfile 0664 root:caddy || die "Konnte /etc/caddy/Caddyfile nicht anlegen."
fi
# Das Panel (Gruppe caddy) schreibt Caddyfile und importierte Dateien;
# setgid: neue Dateien gehören zur Gruppe caddy, Caddy kann sie lesen
etc_caddy_fix

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
# Lizenzhinweise (Apache-2.0 und enthaltene Komponenten Dritter)
install -d -m 0755 /usr/local/share/doc/caddy-sentinel
for f in LICENSE NOTICE AUTHORS THIRD_PARTY_LICENSES.txt; do
	[ -f "$SRC/$f" ] && install -m 0644 "$SRC/$f" /usr/local/share/doc/caddy-sentinel/
done
echo "$NEW_VERSION" >"$SHARE_DIR/VERSION"
echo "$REPO" >"$SHARE_DIR/REPO"
remember_signing_key
if [ "$DL" != "https://github.com/$REPO/releases" ]; then echo "$DL" >"$SHARE_DIR/DOWNLOAD"; else rm -f "$SHARE_DIR/DOWNLOAD"; fi

# ------------------------------------------------------------ Agent-Modus
if [ "$AGENT" = 1 ]; then
	say "Agent-Verbindung zu $PANEL_URL"
	echo agent >"$SHARE_DIR/MODE"
	# /etc/caddy ist für caddy beschreibbar (remote full): Token nicht über
	# den Pfad schreiben, sondern fertig einsetzen (put_file)
	(umask 077 && printf '%s\n' "$AGENT_TOKEN" >"$TMP/agent.token")
	put_file "$TMP/agent.token" /etc/caddy/sentinel-agent.token 0640 root:caddy || die "Konnte das Token nicht nach /etc/caddy/sentinel-agent.token schreiben."
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
		agent_admin_http || agent_admin_lines
	} >/etc/systemd/system/caddy.service.d/sentinel.conf
	warn_explicit_admin
	if [ ! -f /lib/systemd/system/caddy.service ] && [ ! -f /usr/lib/systemd/system/caddy.service ] && [ ! -f /etc/systemd/system/caddy.service ]; then
		install -m 0644 "$DEPLOY/caddy.service" /etc/systemd/system/caddy.service
		sed -i 's/ caddy-sentinel.service//' /etc/systemd/system/caddy.service
	fi
	systemctl daemon-reload
	ensure_sentinel_caddyfile
	if [ "$START" = 1 ]; then
		systemctl enable caddy.service >/dev/null 2>&1 || true
		systemctl restart caddy.service || { journalctl -u caddy -n 30 --no-pager || true; die "Caddy startet nicht."; }
	fi
	cat <<AGENTEOF

Caddy mit Sentinel-Agent ist installiert und verbindet sich mit $PANEL_URL.
Im Panel unter „Caddy-Instanzen“ erscheint der Server als verbunden.

  Zugriff des Panels: $REMOTE
  Token:              /etc/caddy/sentinel-agent.token
  Admin-API:          /run/caddy/admin.sock (nur Benutzer/Gruppe caddy)
  Logs:               journalctl -u caddy -f

AGENTEOF
	exit 0
fi

# ------------------------------------------------------------ systemd
say "systemd-Units"
install -m 0644 "$DEPLOY/caddy-sentinel.service" /etc/systemd/system/caddy-sentinel.service
if [ -n "$LISTEN" ]; then
	sed -i "s|^SENTINEL_LISTEN=.*|SENTINEL_LISTEN=$LISTEN|" "$ENV_FILE"
fi
if [ "$PANEL_ONLY" = 0 ]; then
	install -d /etc/systemd/system/caddy.service.d
	# Caddy muss das Panel unter der tatsächlich eingestellten Adresse
	# erreichen und das Token am eingestellten Ort finden
	plisten=$(env_get SENTINEL_LISTEN)
	sed -e "s|^Environment=SENTINEL_PANEL=.*|Environment=SENTINEL_PANEL=http://$(panel_probe "$plisten")|" \
		-e "s|^Environment=SENTINEL_TOKEN_FILE=.*|Environment=SENTINEL_TOKEN_FILE=$TOKEN_FILE|" \
		"$DEPLOY/caddy-override.conf" >"$TMP/caddy-override.conf"
	install -m 0644 "$TMP/caddy-override.conf" /etc/systemd/system/caddy.service.d/sentinel.conf
	ensure_sentinel_caddyfile
	# Admin-API als Unix-Socket (CADDY_ADMIN in der Ergänzung): das Panel
	# spricht Caddy dann über /run/caddy/admin.sock an
	sync_admin_env "$TMP/caddy-override.conf"
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
listen=$(env_get SENTINEL_LISTEN)
listen=${listen:-127.0.0.1:7600}
probe=$(panel_probe "$listen")
ok=0
for _ in $(seq 1 40); do
	if [ -f "$TOKEN_FILE" ] && (curl -fsS -o /dev/null "http://$probe/api/auth/state" 2>/dev/null || wget -q -O /dev/null "http://$probe/api/auth/state" 2>/dev/null); then ok=1; break; fi
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
  Benutzer:   Panel caddy-sentinel, Caddy caddy (Datenbank: $BASE/data, nur für das Panel)
  Admin-API:  $(env_get SENTINEL_CADDY_ADMIN)
  Logs:       journalctl -u caddy-sentinel -u caddy -f
  Update:     sudo caddy-sentinel-update            (prüfen: --check)
  Entfernen:  sudo caddy-sentinel-uninstall

EOF
}

usage() {
	cat <<'USAGE'
Caddy Sentinel – Installation und Update

  bash <(wget -qO- https://github.com/b1tk1ll3r/caddy-sentinel/releases/latest/download/install.sh) [Optionen]

  --version vX.Y.Z   bestimmte Version statt der neuesten
  --dir PFAD         Binaries aus diesem Verzeichnis
  --listen ADDR      Adresse des Panels (Standard: 127.0.0.1:7600)
  --panel-only       nur das Panel
  --agent            nur Caddy mit Sentinel-Agent (mit --panel URL --token TOKEN [--remote full|read|off])
  --reinstall        auch bei vorhandener Installation neu installieren
  --force            auch dieselbe Version erneut einspielen
  --no-start         Dienste nicht starten
  --verify-attestation  Herkunftsnachweis des Archivs mit gh prüfen (GH_TOKEN nötig)
  --skip-signature   Signatur der Prüfsummen nicht prüfen (nur in Notfällen)
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
	# das Token nicht als Argument an sudo (Prozessliste), sondern als Datei
	tokfile=""
	if [ -n "${SENTINEL_AGENT_TOKEN:-}" ]; then
		tokfile=$(umask 077 && mktemp)
		printf '%s' "$SENTINEL_AGENT_TOKEN" >"$tokfile"
	fi
	exec sudo env SENTINEL_SCRIPT_DIR="$dir" SENTINEL_REPO="${SENTINEL_REPO:-}" SENTINEL_DOWNLOAD="${SENTINEL_DOWNLOAD:-}" SENTINEL_AGENT_TOKEN_FILE="$tokfile" SENTINEL_VERIFY_ATTESTATION="${SENTINEL_VERIFY_ATTESTATION:-0}" SENTINEL_SKIP_SIGNATURE="${SENTINEL_SKIP_SIGNATURE:-0}" bash -c "set -euo pipefail; $(declare -f main usage); main \"\$@\"" caddy-sentinel-install "$@"
fi
main "$@"
