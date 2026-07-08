#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# End-to-end CI: build the app, boot it as a real CCF sandbox node, and run the
# pytest e2e suite (test/e2e) against it. Mirrors the local dev flow.
#
# The e2e harness resolves the CCF install at ./.ccf-install and boots the node
# via sandbox.sh using the venv at ./.venv_ccf_sandbox. sandbox.sh would try to
# `pip install ccf==<rpm-version>`, but the exact RPM patch release is not always
# published to PyPI (e.g. 7.0.5 is missing); the adjacent 7.0.6 python client
# works against it (as it does locally). So we pre-create the venv here and
# sandbox.sh reuses it instead of doing that (broken) install.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${INSTALL_DIR:?INSTALL_DIR (CCF install prefix) must be set}"
VENV_DIR=.venv_ccf_sandbox
CCF_PY_VERSION=${CCF_PY_VERSION:-7.0.6}
APP=app/build/selective_disclosure

# The harness looks for sandbox.sh, start_network.py, the bundled infra package
# and the service certs under ./.ccf-install.
if [ ! -e .ccf-install ]; then
  ln -s "$INSTALL_DIR" .ccf-install
fi

echo "== Building the app =="
INSTALL_DIR="$INSTALL_DIR" ./docker/build-app.sh
test -x "$APP"

echo "== Creating the sandbox + e2e venv ($VENV_DIR) =="
if [ ! -f "$VENV_DIR/bin/activate" ]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q -U pip
  # ccf python client + the sandbox/infra runtime deps (loguru, httpx, ...).
  "$VENV_DIR/bin/pip" install -q "ccf==${CCF_PY_VERSION}"
  "$VENV_DIR/bin/pip" install -q -r .ccf-install/bin/requirements.txt
  # e2e verifier stack. sd_cwt pins cbor2<5.6 (see test/e2e/requirements.txt);
  # the resulting pip warning against ccf's cbor2>=5.6 ask is safe.
  "$VENV_DIR/bin/pip" install -q pytest pycose "cbor2<5.6" -e tools/sd_cwt
fi

echo "== Running the e2e suite =="
"$VENV_DIR/bin/python" -m pytest test/e2e -v
