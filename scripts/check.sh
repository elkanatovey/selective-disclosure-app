#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

PYTHON=${PYTHON:-python3}
PYTHON_SOURCES=(sd_cwt webapp tests scripts/scitt_flow.py)
JAVASCRIPT_SOURCES=(webapp/static/*.js scripts/scitt_flow.mjs tests/js/*.mjs)
JSON_SOURCES=(biome.json webapp/static/*.json tests/fixtures/*.json)
SHELL_SOURCES=(scripts/*.sh)
[[ ! -d .devcontainer ]] || SHELL_SOURCES+=(.devcontainer/*.sh)
[[ ! -d docker ]] || SHELL_SOURCES+=(docker/*.sh)

command -v shellcheck >/dev/null || {
  echo "shellcheck is required" >&2
  exit 1
}
command -v node >/dev/null || {
  echo "node is required" >&2
  exit 1
}
if command -v biome >/dev/null; then
  BIOME=(biome)
elif [[ -x "$ROOT/.tools/bin/biome" ]]; then
  BIOME=("$ROOT/.tools/bin/biome")
else
  echo "biome is required; run scripts/install-biome.sh" >&2
  exit 1
fi
if command -v ruff >/dev/null; then
  RUFF=(ruff)
elif "$PYTHON" -c "import ruff" >/dev/null 2>&1; then
  RUFF=("$PYTHON" -m ruff)
else
  echo "ruff is required" >&2
  exit 1
fi

"${RUFF[@]}" check "${PYTHON_SOURCES[@]}"
"${RUFF[@]}" format --check "${PYTHON_SOURCES[@]}"
"${BIOME[@]}" lint "${JAVASCRIPT_SOURCES[@]}"
"${BIOME[@]}" format "${JAVASCRIPT_SOURCES[@]}" webapp/static/*.css "${JSON_SOURCES[@]}"
"$PYTHON" -m pytest -q
node --test tests/js/*.mjs

for source in "${JAVASCRIPT_SOURCES[@]}"; do
  node --check "$source"
done

for source in "${SHELL_SOURCES[@]}"; do
  bash -n "$source"
done
shellcheck "${SHELL_SOURCES[@]}"
