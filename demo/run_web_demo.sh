#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# One-command interactive web demo: boot the app as a real CCF sandbox node,
# then serve the multi-role web UI (demo/webapp) against it. Open each role in
# its own browser window and play them side by side. Tears the node down on exit.
#
# Prereqs (all produced by the normal dev flow):
#   - the app is built:            ./docker/build-app.sh   (-> app/build/selective_disclosure)
#   - a CCF install is available:  ./.ccf-install          (symlink or INSTALL_DIR)
# The script creates or refreshes the sandbox venv and adds the web-only deps.
#
# Usage:
#   ./demo/run_web_demo.sh                 # serve on http://127.0.0.1:8080
#   PORT=9000 ./demo/run_web_demo.sh       # pick a port
set -euo pipefail
cd "$(dirname "$0")/.."

APP=app/build/selective_disclosure
VENV_DIR=.venv_ccf_sandbox
PORT=${PORT:-8080}
HOST=${HOST:-127.0.0.1}

# Resolve a CCF install: prefer an existing ./.ccf-install, else $INSTALL_DIR.
if [ ! -e .ccf-install ]; then
  if [ -n "${INSTALL_DIR:-}" ]; then
    ln -s "$INSTALL_DIR" .ccf-install
  else
    echo "error: no ./.ccf-install and INSTALL_DIR unset. Build/point at a CCF install first." >&2
    exit 1
  fi
fi

if [ ! -x "$APP" ]; then
  echo "error: app not built ($APP). Run ./docker/build-app.sh first." >&2
  exit 1
fi

echo "== Creating or refreshing $VENV_DIR (sandbox + verifier + web deps) =="
./scripts/setup-sandbox-venv.sh "$VENV_DIR"
"$VENV_DIR/bin/pip" install -q -r demo/webapp/requirements.txt

LOG="$(mktemp)"
NODE_PID=""
WEB_PID=""
cleanup() {
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
  [ -n "$NODE_PID" ] && kill -- "-$NODE_PID" 2>/dev/null || true
  rm -f "$LOG"
}
trap cleanup EXIT

echo "== Starting the ledger node (CCF sandbox) =="
# Own process group so we can tear down the whole tree on exit.
set -m
VENV_DIR="$VENV_DIR" .ccf-install/bin/sandbox.sh \
  --package "$APP" >"$LOG" 2>&1 &
NODE_PID=$!
set +m

echo -n "   waiting for the node to open"
for _ in $(seq 1 120); do
  if grep -q "Started CCF network" "$LOG" 2>/dev/null; then
    echo " ... up."
    break
  fi
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    echo; echo "error: node exited during startup. Log:" >&2; tail -30 "$LOG" >&2; exit 1
  fi
  echo -n "."
  sleep 1
done

echo "== Serving the web UI on http://$HOST:$PORT =="
echo "   open it in a browser, then pop out each role window."
echo "   (Ctrl+C to stop and tear the node down)"
DEMO_URL="https://127.0.0.1:8000" DEMO_COMMON_DIR="workspace/sandbox_common" \
  "$VENV_DIR/bin/python" -m uvicorn demo.webapp.server:app \
  --host "$HOST" --port "$PORT" &
WEB_PID=$!
wait "$WEB_PID"
