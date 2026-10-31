#!/usr/bin/env bash
# Baut statische Release-Binaries (Caddy mit Sentinel-Modul + Panel) und ein
# Release-Archiv. Wird von der GitHub-Action benutzt, funktioniert aber auch lokal.
#
#   ./scripts/build-release.sh                      # aktuelle Architektur
#   ARCH=arm64 CC=aarch64-linux-gnu-gcc ./scripts/build-release.sh
#   ARCH=armv7 CC=arm-linux-gnueabihf-gcc ./scripts/build-release.sh
#   VERSION=v1.2.0 CADDY_VERSION=latest ./scripts/build-release.sh
#
# Variablen:
#   VERSION        Versionsstring (Standard: git describe)
#   ARCH           amd64 | arm64 | armv7 (Standard: Architektur von Go)
#   CC             C-Compiler für das Panel (SQLite braucht CGO); beim
#                  Cross-Build der passende Cross-Compiler
#   CADDY_VERSION  leer = Version aus go.mod, sonst z. B. "latest" oder "v2.11.0"
#   UPGRADE_WAF=1  Coraza und OWASP CRS auf die neueste Version heben
#                  (beides gilt für sentinel, caddy und panel gleichermaßen)
#   SKIP_TESTS=1   Tests überspringen
#   RESOLVE_ONLY=1 nur Versionen auflösen und testen, nichts bauen
#   OUT            Ausgabeverzeichnis (Standard: ./dist)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
ARCH=${ARCH:-$(go env GOARCH)}
OUT=${OUT:-$ROOT/dist}
MOD=github.com/b1tk1ll3r/caddy-sentinel

case "$ARCH" in
  amd64) GOARCH=amd64; GOARM= ;;
  arm64) GOARCH=arm64; GOARM= ;;
  armv7) GOARCH=arm; GOARM=7 ;;
  *) echo "Nicht unterstützte Architektur: $ARCH" >&2; exit 1 ;;
esac
export GOOS=linux GOARCH GOARM

NAME="caddy-sentinel_${VERSION}_linux_${ARCH}"
STAGE="$OUT/$NAME"
BIN="$OUT/linux_${ARCH}"
rm -rf "$STAGE" "$BIN"
mkdir -p "$STAGE" "$BIN"

echo "==> Version $VERSION, linux/$ARCH ($(go version))"

# Netzwerkschritte (Module laden, Prüfsummen von sum.golang.org) bei
# vorübergehenden Fehlern wiederholen – z. B. "stream error … INTERNAL_ERROR".
retry() {
  local n=1 max=4
  until "$@"; do
    [ $n -ge $max ] && { echo "Fehlgeschlagen nach $max Versuchen: $*" >&2; return 1; }
    echo "Versuch $n fehlgeschlagen – neuer Versuch in $((n * 15)) s: $*" >&2
    sleep $((n * 15)); n=$((n + 1))
  done
}
host_go() { GOOS= GOARCH= GOARM= go "$@"; }

if [ -n "${CADDY_VERSION:-}" ] || [ "${UPGRADE_WAF:-0}" = 1 ]; then
  pkgs=()
  [ -n "${CADDY_VERSION:-}" ] && pkgs+=("github.com/caddyserver/caddy/v2@${CADDY_VERSION}")
  [ "${UPGRADE_WAF:-0}" = 1 ] && pkgs+=(github.com/corazawaf/coraza/v3@latest github.com/corazawaf/coraza-coreruleset/v4@latest)
  # auch das Panel: es bindet Caddy (Caddyfile-Adapter) und Coraza selbst
  # ein und soll exakt dieselben Versionen enthalten wie der Caddy-Build
  for d in sentinel caddy panel; do (cd "$d" && retry host_go get "${pkgs[@]}" && retry host_go mod tidy); done
  # "latest" einmal aufgelöst: alle Module auf dieselbe konkrete Version
  # festlegen (sonst könnte ein zwischendurch erschienenes Release in nur
  # einem Modul landen)
  pinned=()
  for m in github.com/caddyserver/caddy/v2 github.com/corazawaf/coraza/v3 github.com/corazawaf/coraza-coreruleset/v4; do
    v=$(cd caddy && host_go list -m -f '{{.Version}}' "$m" 2>/dev/null) || continue
    [ -n "$v" ] && pinned+=("$m@$v")
  done
  for d in sentinel panel; do (cd "$d" && retry host_go get "${pinned[@]}" && retry host_go mod tidy); done
  echo "==> Versionen: ${pinned[*]}"
fi

# frisch geklont ohne go.sum: Abhängigkeiten auflösen
for d in sentinel caddy panel; do
  [ -f "$d/go.sum" ] || (cd "$d" && retry host_go mod tidy)
done
# alle Module vorab laden (mit Wiederholung), damit Tests und Builds offline laufen
for d in sentinel caddy panel; do (cd "$d" && retry host_go mod download); done

if [ "${SKIP_TESTS:-0}" != 1 ] && [ "$GOARCH" = "$(GOOS= GOARCH= go env GOARCH)" ]; then
  echo "==> Tests (mit den aufgelösten Versionen)"
  (cd sentinel && GOOS= GOARCH= GOARM= go vet ./... && GOOS= GOARCH= GOARM= go test ./...)
  (cd panel && GOOS= GOARCH= GOARM= CGO_ENABLED=1 go vet ./... && GOOS= GOARCH= GOARM= CGO_ENABLED=1 go test ./...)
fi

# RESOLVE_ONLY=1: nur Versionen auflösen und testen (CI-Job "resolve"); die
# go.mod/go.sum-Dateien geben dann allen Architekturen dieselben Versionen vor
if [ "${RESOLVE_ONLY:-0}" = 1 ]; then
  echo "==> Aufgelöste Versionen"
  (cd caddy && host_go list -m github.com/caddyserver/caddy/v2 github.com/corazawaf/coraza/v3 github.com/corazawaf/coraza-coreruleset/v4)
  exit 0
fi

# Coraza-Operator @inspectFile (startet externe Programme) nicht mitbauen
WAF_TAGS="coraza.disabled_operators.inspectFile"

echo "==> Lizenzen der enthaltenen Module"
# Erst jetzt steht fest, welche Versionen gebaut werden (CADDY_VERSION,
# UPGRADE_WAF). Die Liste wird ins Panel eingebettet und liegt dem Archiv bei.
(cd tools/licenses && GOOS= GOARCH= GOARM= CGO_ENABLED=0 go build -o "$OUT/.licenses" .)
LEGAL="$ROOT/panel/internal/legal/data/THIRD_PARTY_LICENSES.txt"
CGO_ENABLED=1 "$OUT/.licenses" -o "$LEGAL" "$ROOT/caddy" "$ROOT/panel:sqlite_omit_load_extension,osusergo,netgo"
cp "$LEGAL" "$BIN/THIRD_PARTY_LICENSES.txt"
cp NOTICE "$ROOT/panel/internal/legal/data/NOTICE" # im Panel angezeigt
rm -f "$OUT/.licenses"

echo "==> Caddy"
(cd caddy && CGO_ENABLED=0 go build -trimpath -tags "$WAF_TAGS" \
  -ldflags "-s -w -X ${MOD}/sentinel.Version=${VERSION}" -o "$BIN/caddy" .)

echo "==> Panel (statisch, SQLite)"
(cd panel && CGO_ENABLED=1 go build -trimpath \
  -tags "sqlite_omit_load_extension osusergo netgo $WAF_TAGS" \
  -ldflags "-s -w -X ${MOD}/panel/internal/core.Version=${VERSION} -linkmode external -extldflags '-static'" \
  -o "$BIN/caddy-sentinel" .)

if [ "$GOARCH" = "$(GOOS= GOARCH= go env GOARCH)" ]; then
  "$BIN/caddy" version
  "$BIN/caddy" list-modules | grep -q '^http.handlers.sentinel$' || { echo "Sentinel-Modul fehlt im Caddy-Build" >&2; exit 1; }
  "$BIN/caddy-sentinel" -version
fi

echo "==> Archiv"
cp "$BIN/caddy" "$BIN/caddy-sentinel" "$STAGE/"
cp -r deploy "$STAGE/deploy"
rm -rf "$STAGE/deploy/docker" "$STAGE/deploy/install.sh"
cp scripts/install.sh scripts/update.sh scripts/uninstall.sh "$STAGE/"
chmod 0755 "$STAGE/install.sh" "$STAGE/update.sh" "$STAGE/uninstall.sh"
cp README.md LICENSE NOTICE AUTHORS "$BIN/THIRD_PARTY_LICENSES.txt" "$STAGE/"
cp -r docs "$STAGE/docs"
echo "$VERSION" > "$STAGE/VERSION"
tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -rf "$STAGE"
(cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "Fertig: $OUT/$NAME.tar.gz"
