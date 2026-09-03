#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VENV=${VENV:-$ROOT/.venv}

python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --disable-pip-version-check -e "${ROOT}[test]"

printf '\nDevelopment environment ready. Run checks with:\n\n'
printf '    PYTHON=%q scripts/check.sh\n' "$VENV/bin/python"
printf '\nStart the mock demo with:\n\n'
printf '    DEMO_VENV=%q scripts/run-mock-demo.sh\n' "$VENV"
