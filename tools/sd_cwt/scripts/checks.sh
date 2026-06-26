#!/usr/bin/env bash
# Run the sd_cwt format / type / test checks (mirrors the CI jobs).
# Pass -f to auto-fix formatting and import order.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! python -c "import sd_cwt" >/dev/null 2>&1; then
  echo "sd_cwt is not installed in this environment. Set it up with:" >&2
  echo "  python3 -m venv .venv && . .venv/bin/activate && pip install -e .[lint]" >&2
  exit 1
fi

FIX=0
[ "${1:-}" = "-f" ] && FIX=1

if [ "$FIX" -ne 0 ]; then
  black src tests
  isort src tests
else
  black --check src tests
  isort --check src tests
fi
mypy src/sd_cwt
pytest -q
