#!/usr/bin/env bash
# Caddy Sentinel entfernen (systemd-Installation)
#
#   sudo caddy-sentinel-uninstall           # Programme entfernen, Daten behalten
#   sudo caddy-sentinel-uninstall --purge   # auch Datenbank und Sicherungen löschen
#
# Caddyfile und Zertifikate bleiben immer erhalten. War vorher ein
# Distributions-Caddy installiert, läuft danach wieder dieser.
# Der Systembenutzer des Panels (caddy-sentinel) wird entfernt; behaltene
# Daten gehören danach root (nur root lesbar), damit ein später angelegter
# Benutzer mit derselben Nummer sie nicht lesen kann.
set -euo pipefail
PURGE=0
YES=0
for a in "$@"; do
	case "$a" in
	--purge) PURGE=1 ;;
	-y | --yes) YES=1 ;;
	-h | --help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "Unbekannte Option: $a" >&2; exit 2 ;;
	esac
done
[ "$(id -u)" = 0 ] || { echo "Bitte mit sudo ausführen" >&2; exit 1; }
warn() { printf '!! %s\n' "$*" >&2; }

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
LAYOUT=legacy BASE=/var/lib/caddy-sentinel
[ -r "$ENV_FILE" ] && layout_of
if [ "$PURGE" = 1 ]; then
	# rm -rf folgt keinen Symlinks
	rm -rf -- "$BASE" /var/backups/caddy-sentinel "$ENV_FILE"
	[ "$BASE" = /var/lib/caddy-sentinel ] || rm -rf /var/lib/caddy-sentinel
	echo "Daten gelöscht."
else
	if [ -d "$BASE" ] && [ ! -L "$BASE" ] && id "$PANEL_USER" >/dev/null 2>&1 && root_only "$(dirname -- "$BASE")"; then
		lock_tree "$BASE" || true
	fi
	echo "Daten behalten (nur für root lesbar): $BASE, $ENV_FILE, /var/backups/caddy-sentinel"
fi
if id "$PANEL_USER" >/dev/null 2>&1; then
	# Dateien des Panels in /etc/caddy gehen an root, dann den Benutzer entfernen
	etc_caddy_fix root
	remove_panel_user
	echo "Benutzer $PANEL_USER entfernt."
fi
echo "Caddy Sentinel wurde entfernt."
