#!/usr/bin/env bash
# Baut panel/web/static/vendor/codemirror.js aus den CodeMirror-6-Quellen
# (GitHub) mit esbuild. Kein npm nötig – nur git und Go.
#
#   ./scripts/build-codemirror.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# repo  version(tag)
REPOS="
codemirror/state 6.6.0
codemirror/view 6.41.0
codemirror/commands 6.10.3
codemirror/language 6.12.3
codemirror/search 6.6.0
codemirror/autocomplete 6.20.1
codemirror/lint 6.9.5
lezer-parser/common 1.5.2
lezer-parser/highlight 1.2.3
lezer-parser/lr 1.4.8
marijnh/style-mod 4.1.3
marijnh/w3c-keyname 2.2.8
marijnh/crelt 1.0.6
marijnh/find-cluster-break 1.0.2
"
echo "$REPOS" | while read -r repo ver; do
  [ -n "$repo" ] || continue
  name=$(basename "$repo")
  git clone -q --depth 1 --branch "$ver" "https://github.com/$repo" "$name" 2>/dev/null \
    || git clone -q --depth 1 "https://github.com/$repo" "$name"
done

cat > entry.ts <<'TS'
export * from "@codemirror/state";
export * from "@codemirror/view";
export * from "@codemirror/commands";
export * from "@codemirror/language";
export * from "@codemirror/search";
export * from "@codemirror/autocomplete";
export * from "@codemirror/lint";
export { tags } from "@lezer/highlight";
TS

go run github.com/evanw/esbuild/cmd/esbuild@v0.25.10 entry.ts --bundle --format=esm --minify --target=es2020 --legal-comments=none \
  --banner:js="/*! CodeMirror 6 (@codemirror/*, @lezer/*, style-mod, w3c-keyname, crelt, find-cluster-break) | (c) Marijn Haverbeke and others | MIT License | vendor/LICENSE-codemirror.txt */" \
  --alias:@codemirror/state=./state/src/index.ts --alias:@codemirror/view=./view/src/index.ts \
  --alias:@codemirror/commands=./commands/src/commands.ts --alias:@codemirror/language=./language/src/index.ts \
  --alias:@codemirror/search=./search/src/search.ts --alias:@codemirror/autocomplete=./autocomplete/src/index.ts \
  --alias:@codemirror/lint=./lint/src/lint.ts --alias:@lezer/common=./common/src/index.ts \
  --alias:@lezer/highlight=./highlight/src/highlight.ts --alias:@lezer/lr=./lr/src/index.ts \
  --alias:style-mod=./style-mod/src/style-mod.js --alias:w3c-keyname=./w3c-keyname/index.js \
  --alias:crelt=./crelt/index.js --alias:@marijn/find-cluster-break=./find-cluster-break/src/index.js \
  --outfile="$ROOT/panel/web/static/vendor/codemirror.js"
echo "Fertig: panel/web/static/vendor/codemirror.js"
