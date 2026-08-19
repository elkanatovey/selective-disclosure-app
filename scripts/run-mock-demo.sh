#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=${MOCK_DEMO_WORK:-/tmp/selective-disclosure-mock}
VENV=${DEMO_VENV:-$ROOT/.venv}
PYTHON=$VENV/bin/python
RESEARCHER_PID=
MSRC_PID=
VERIFIER_PID=
SCITT_PID=

cleanup(){
  [[ -z "$RESEARCHER_PID" ]] || kill -- "-$RESEARCHER_PID" 2>/dev/null || true
  [[ -z "$MSRC_PID" ]] || kill -- "-$MSRC_PID" 2>/dev/null || true
  [[ -z "$VERIFIER_PID" ]] || kill -- "-$VERIFIER_PID" 2>/dev/null || true
  [[ -z "$SCITT_PID" ]] || kill -- "-$SCITT_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -x "$PYTHON" ]]; then
  printf 'Create the demo environment first: python3 -m venv .venv && .venv/bin/python -m pip install -e .\n' >&2
  exit 1
fi
mkdir -p "$WORK"

SCITT_URL=http://127.0.0.1:8000 RESEARCHER_ORIGIN=http://127.0.0.1:8090 \
  setsid "$PYTHON" -m uvicorn webapp.msrc:app --app-dir "$ROOT" --host 0.0.0.0 --port 8091 >"$WORK/msrc.log" 2>&1 &
MSRC_PID=$!
MSRC_URL=http://127.0.0.1:8091 \
  setsid "$PYTHON" -m uvicorn webapp.mock_scitt:app --app-dir "$ROOT" --host 127.0.0.1 --port 8000 >"$WORK/scitt.log" 2>&1 &
SCITT_PID=$!
MSRC_URL=http://127.0.0.1:8091 SCITT_URL=http://127.0.0.1:8000 \
  setsid "$PYTHON" -m uvicorn webapp.researcher:app --app-dir "$ROOT" --host 0.0.0.0 --port 8090 >"$WORK/researcher.log" 2>&1 &
RESEARCHER_PID=$!
MSRC_URL=http://127.0.0.1:8091 SCITT_URL=http://127.0.0.1:8000 \
  setsid "$PYTHON" -m uvicorn webapp.verifier:app --app-dir "$ROOT" --host 0.0.0.0 --port 8092 >"$WORK/verifier.log" 2>&1 &
VERIFIER_PID=$!

"$PYTHON" - <<'PY'
import time
import requests

services = {
    "researcher": "http://127.0.0.1:8090/api/health",
    "msrc": "http://127.0.0.1:8091/api/health",
    "verifier": "http://127.0.0.1:8092/api/health",
    "mock-scitt": "http://127.0.0.1:8000/api/health",
}
for _ in range(80):
    try:
        if all(requests.get(url, timeout=1).status_code == 200 for url in services.values()):
            break
    except requests.RequestException:
        pass
    time.sleep(.1)
else:
    raise TimeoutError("split mock services did not become ready")
PY

printf '\nSplit mock demo is ready:\n'
printf '  Researcher: http://127.0.0.1:8090/\n'
printf '  MSRC:       http://127.0.0.1:8091/\n'
printf '  Verifier:   http://127.0.0.1:8092/\n'
printf '  Mock SCITT: http://127.0.0.1:8000/\n'
printf '\nKeep this process running. Press Ctrl+C to stop all services.\n'
wait "$RESEARCHER_PID"