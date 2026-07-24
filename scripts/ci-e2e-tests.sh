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
# published to PyPI. The shared setup script installs the compatible Python
# client and verifier dependencies before sandbox.sh reuses the environment.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${INSTALL_DIR:?INSTALL_DIR (CCF install prefix) must be set}"
VENV_DIR=.venv_ccf_sandbox
APP=app/build/selective_disclosure

# The harness looks for sandbox.sh, start_network.py, the bundled infra package
# and the service certs under ./.ccf-install.
if [ ! -e .ccf-install ]; then
  ln -s "$INSTALL_DIR" .ccf-install
fi

echo "== Building the app =="
INSTALL_DIR="$INSTALL_DIR" ./docker/build-app.sh
# The e2e conftest skips if these are missing; assert them here so a mislocated
# app/sandbox fails the CI job loudly instead of a silent all-skipped pass.
test -x "$APP"
test -f .ccf-install/bin/sandbox.sh

echo "== Creating or refreshing the sandbox + e2e venv ($VENV_DIR) =="
./scripts/setup-sandbox-venv.sh "$VENV_DIR"

echo "== Running the e2e suite =="
"$VENV_DIR/bin/python" -m pytest test/e2e -v
