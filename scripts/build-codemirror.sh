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

# repo  version(tag)  commit
# Der Commit hält die Quelle fest: ein nachträglich umgehängter Tag fällt auf
# (Abbruch), statt unbemerkt anderen Code ins Bundle zu bringen. Neue Version:
#   git ls-remote https://github.com/<repo> 'refs/tags/<tag>^{}'
# (bei leichtgewichtigen Tags ohne ^{}) und Tag und Commit hier eintragen.
REPOS="
codemirror/state 6.6.0 821d9b772a1d2d9c989b6ae472513380bf10136b
codemirror/view 6.41.0 a0a5ed946cfdfde61dcf33b131d551136378ccf9
codemirror/commands 6.10.3 6f83cb93abc81cb13993ce4805aafce45bfe2853
codemirror/language 6.12.3 f5af31eed71fa22e8c110d74e61098c0fb1c1acb
codemirror/search 6.6.0 502b2e43fecbb4b49f631e1ba5dce05d1ad493ae
codemirror/autocomplete 6.20.1 7cbf7fd3b8126fd2b8f3d29a0cb150ac31506fd1
codemirror/lint 6.9.5 296d74376596acd4c7aa4cd1cf00e877cdd2ff52
lezer-parser/common 1.5.2 de5f96276a2954c249de1475e8b03f79c20d9ce4
lezer-parser/highlight 1.2.3 37e3eef517edd8e8dc8790419d04b61a7ac28420
lezer-parser/lr 1.4.8 f81d6a25c3482aa7fc12434e9adea9d75c56ad08
marijnh/style-mod 4.1.3 f8a0376473b604184916ef2ae4f28edfaf653849
marijnh/w3c-keyname 2.2.8 5ea93b04bb62230c7de4165e3a9b5c840f05cd44
marijnh/crelt 1.0.6 25eabb104d50e160cd4e4acd9eed2eacb32b332b
marijnh/find-cluster-break 1.0.2 b0b1f10aa0c131cf53f2dc347a09544b4ae87324
"
echo "$REPOS" | while read -r repo ver commit; do
  [ -n "$repo" ] || continue
  name=$(basename "$repo")
  # exactly the pinned version – never silently fall back to HEAD
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$ver" "https://github.com/$repo" "$name" \
    || { echo "Fehler: $repo $ver nicht abrufbar" >&2; exit 1; }
  got=$(git -C "$name" rev-parse HEAD)
  if [ "$got" != "$commit" ]; then
    echo "Fehler: $repo $ver zeigt auf $got statt $commit – Tag umgehängt? Abbruch." >&2
    exit 1
  fi
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
