#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# One-command demo: boot the app as a real CCF sandbox node, run the narrated
# client/operator flow (demo/demo.py) against it, then tear the node down.
#
# Prereqs (all produced by the normal dev flow):
#   - the app is built:            ./docker/build-app.sh   (-> app/build/selective_disclosure)
#   - a CCF install is available:  ./.ccf-install          (symlink or INSTALL_DIR)
# The script creates a Python venv for the sandbox + demo on first run.
#
# Usage:
#   ./demo/run_demo.sh            # runs straight through
#   ./demo/run_demo.sh --step     # pauses between steps (nice for a live demo)
set -euo pipefail
cd "$(dirname "$0")/.."

APP=app/build/selective_disclosure
VENV_DIR=.venv_ccf_sandbox

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

# venv with the sandbox runtime + the demo's verifier deps.
if [ ! -f "$VENV_DIR/bin/activate" ]; then
  echo "== First run: creating $VENV_DIR (sandbox + demo deps) =="
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q -U pip
  "$VENV_DIR/bin/pip" install -q "ccf==${CCF_PY_VERSION:-7.0.6}"
  "$VENV_DIR/bin/pip" install -q -r .ccf-install/bin/requirements.txt
  "$VENV_DIR/bin/pip" install -q requests "cbor2<5.6" pycose -e tools/sd_cwt
fi

LOG="$(mktemp)"
NODE_PID=""
cleanup() {
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

echo
"$VENV_DIR/bin/python" demo/demo.py "$@"
