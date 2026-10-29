#!/usr/bin/env bash
# Installation aus einem lokalen Build (./build.sh legt die Binaries in ./dist ab).
# Für Releases: scripts/install.sh bzw. docs/INSTALL.md
set -euo pipefail
cd "$(dirname "$0")/.."
DIST=${DIST:-./dist}
exec bash ./scripts/install.sh --dir "$DIST" "$@"
