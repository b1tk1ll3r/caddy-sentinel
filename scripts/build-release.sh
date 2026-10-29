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
#   SKIP_TESTS=1   Tests überspringen
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

if [ -n "${CADDY_VERSION:-}" ] || [ "${UPGRADE_WAF:-0}" = 1 ]; then
  pkgs=()
  [ -n "${CADDY_VERSION:-}" ] && pkgs+=("github.com/caddyserver/caddy/v2@${CADDY_VERSION}")
  [ "${UPGRADE_WAF:-0}" = 1 ] && pkgs+=(github.com/corazawaf/coraza/v3@latest github.com/corazawaf/coraza-coreruleset/v4@latest)
  for d in sentinel caddy; do (cd "$d" && GOOS= GOARCH= GOARM= go get "${pkgs[@]}" && GOOS= GOARCH= GOARM= go mod tidy); done
  (cd panel && GOOS= GOARCH= GOARM= go mod tidy)
fi

# frisch geklont ohne go.sum: Abhängigkeiten auflösen
for d in sentinel caddy panel; do
  [ -f "$d/go.sum" ] || (cd "$d" && GOOS= GOARCH= GOARM= go mod tidy)
done

if [ "${SKIP_TESTS:-0}" != 1 ] && [ "$GOARCH" = "$(GOOS= GOARCH= go env GOARCH)" ]; then
  echo "==> Tests"
  (cd sentinel && GOOS= GOARCH= GOARM= go test ./...)
  (cd panel && GOOS= GOARCH= GOARM= go vet ./...)
fi

echo "==> Caddy"
(cd caddy && CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X ${MOD}/sentinel.Version=${VERSION}" -o "$BIN/caddy" .)

echo "==> Panel (statisch, SQLite)"
(cd panel && CGO_ENABLED=1 go build -trimpath \
  -tags 'sqlite_omit_load_extension osusergo netgo' \
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
cp README.md "$STAGE/"
cp -r docs "$STAGE/docs"
echo "$VERSION" > "$STAGE/VERSION"
tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -rf "$STAGE"
(cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "Fertig: $OUT/$NAME.tar.gz"
