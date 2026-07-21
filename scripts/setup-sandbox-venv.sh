#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Create or refresh the shared CCF sandbox environment used by e2e tests and
# the demo. CCF is installed first because its cbor2 metadata conflicts with the
# older cbor2 release required by pycose; the second install intentionally
# selects the working version documented in test/e2e/requirements.txt.
set -euo pipefail
cd "$(dirname "$0")/.."

VENV_DIR=${1:-.venv_ccf_sandbox}
if [ ! -f .ccf-install/bin/requirements.txt ]; then
  echo "error: CCF sandbox requirements not found under ./.ccf-install" >&2
  exit 1
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q -U pip
fi

CCF_REQUIREMENT=$(grep -E '^ccf==' test/e2e/requirements-ccf.txt)
CCF_INSTALLED=$(
  "$VENV_DIR/bin/python" -c \
    'import importlib.metadata; print(importlib.metadata.version("ccf"))' \
    2>/dev/null || true
)
if [ "$CCF_REQUIREMENT" != "ccf==$CCF_INSTALLED" ]; then
  "$VENV_DIR/bin/pip" install -q -r test/e2e/requirements-ccf.txt
fi

"$VENV_DIR/bin/pip" install -q -r .ccf-install/bin/requirements.txt
"$VENV_DIR/bin/pip" install -q -r test/e2e/requirements.txt -e tools/sd_cwt
