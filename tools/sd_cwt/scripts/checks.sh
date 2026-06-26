#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run the sd_cwt format / type / notice / test checks (mirrors the CI jobs).
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
  black src tests scripts
  isort src tests scripts
else
  black --check src tests scripts
  isort --check src tests scripts
fi
python scripts/notice_check.py
mypy src/sd_cwt
pytest -q
