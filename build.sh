#!/usr/bin/env bash
# Baut Caddy (mit Sentinel-Modul) und das Sentinel-Panel nach ./dist
#
#   ./build.sh                 # neueste Caddy- und Coraza-Version
#   CADDY_VERSION=v2.10.2 ./build.sh
#   PINNED=1 ./build.sh        # exakt die in go.mod hinterlegten Versionen
#   GOARCH=arm64 ./build.sh    # z. B. für einen Raspberry Pi (Panel braucht CGO → nativ bauen empfohlen)
set -euo pipefail
cd "$(dirname "$0")"
ROOT=$PWD
OUT=${OUT:-$ROOT/dist}
CADDY_VERSION=${CADDY_VERSION:-latest}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
MOD=github.com/b1tk1ll3r/caddy-sentinel
mkdir -p "$OUT"

command -v go >/dev/null || { echo "Go fehlt (mindestens die Version, die die gewählte Caddy-Version verlangt – aktuell Go 1.26)"; exit 1; }
echo "==> Go: $(go version)"

upgrade() {
  if [ "${PINNED:-0}" = "1" ]; then return; fi
  go get "github.com/caddyserver/caddy/v2@${CADDY_VERSION}" \
         github.com/corazawaf/coraza/v3@latest \
         github.com/corazawaf/coraza-coreruleset/v4@latest
}

echo "==> Caddy mit Sentinel-Modul (Caddy ${CADDY_VERSION})"
(
  cd "$ROOT/sentinel"
  upgrade
  go mod tidy
  go test ./...
)
(
  cd "$ROOT/caddy"
  upgrade
  go mod tidy
  CGO_ENABLED=0 go build -trimpath -tags coraza.disabled_operators.inspectFile -ldflags "-s -w -X ${MOD}/sentinel.Version=${VERSION}" -o "$OUT/caddy" .
)
"$OUT/caddy" version
"$OUT/caddy" list-modules | grep -q '^http.handlers.sentinel$' && echo "    Sentinel-Modul enthalten"

echo "==> Sentinel-Panel"
(
  cd "$ROOT/panel"
  if [ "${PINNED:-0}" != "1" ]; then
    go get github.com/corazawaf/coraza/v3@latest github.com/corazawaf/coraza-coreruleset/v4@latest
  fi
  go mod tidy
  CGO_ENABLED=1 go build -trimpath -tags coraza.disabled_operators.inspectFile -ldflags "-s -w -X ${MOD}/panel/internal/core.Version=${VERSION}" -o "$OUT/caddy-sentinel" .
)
"$OUT/caddy-sentinel" -version

echo
echo "Fertig: $OUT/caddy und $OUT/caddy-sentinel"
echo "Installation: sudo ./deploy/install.sh   (Release-Archive: ./scripts/build-release.sh, siehe docs/INSTALL.md)"
