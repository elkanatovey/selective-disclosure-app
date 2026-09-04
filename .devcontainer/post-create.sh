#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
set -euo pipefail
cd "$(dirname "$0")/.."

CCF_VERSION="${CCF_VERSION:-7.0.10}"
CCF_RPM_SHA256="${CCF_RPM_SHA256:-4c7f31109aba8893015f4466071d5d964f7117ae0233dd074c96e47eadafe1bc}"

if ! rpm -q "ccf_devel-${CCF_VERSION}-1.x86_64" >/dev/null 2>&1; then
  echo "== Installing CCF ${CCF_VERSION} (devel RPM) =="
  rpm_url="https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_devel_${CCF_VERSION}_x86_64.rpm"
  tmp_rpm="$(mktemp --suffix=.rpm)"
  curl -fsSL "$rpm_url" -o "$tmp_rpm"
  echo "${CCF_RPM_SHA256}  ${tmp_rpm}" | sha256sum -c -
  tdnf -y install "$tmp_rpm"
  rm -f "$tmp_rpm"
fi

./scripts/setup-dev.sh

cat <<'EOF'

Ready. Run checks with:

  PYTHON=.venv/bin/python ./scripts/check.sh

Start the mock demo with:

  ./scripts/run-mock-demo.sh

Start the MST demo with:

  ./scripts/run-mst-demo.sh

Demo URLs:
    http://127.0.0.1:8090/  Researcher
    http://127.0.0.1:8091/  MSRC
    http://127.0.0.1:8092/  Verifier
EOF
