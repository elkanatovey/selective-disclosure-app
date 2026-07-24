#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Codespaces / dev-container post-create: make the interactive web demo runnable
# out of the box. The base image (../Dockerfile) ships only the build toolchain,
# so this installs a matching CCF release and points ./.ccf-install at it — the
# one prerequisite run_web_demo.sh needs beyond the app build. Mirrors the CCF
# install step in .github/workflows/e2e.yml.
#
# Override the release with CCF_VERSION. Safe to re-run: each step is idempotent.
set -euo pipefail
cd "$(dirname "$0")/.."

CCF_VERSION="${CCF_VERSION:-7.0.6}"

if ! rpm -q "ccf_devel-${CCF_VERSION}" >/dev/null 2>&1; then
  echo "== Installing CCF ${CCF_VERSION} (devel RPM) =="
  rpm_url="https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_devel_${CCF_VERSION//-/_}_x86_64.rpm"
  tmp_rpm="$(mktemp --suffix=.rpm)"
  curl -fsSL "$rpm_url" -o "$tmp_rpm"
  tdnf -y install "$tmp_rpm"
  rm -f "$tmp_rpm"
fi

# Point ./.ccf-install at the RPM's install prefix (the dir holding bin/sandbox.sh).
if [ ! -e .ccf-install ]; then
  cfg="$(rpm -ql ccf_devel | grep -m1 '/ccf-config\.cmake$')"
  prefix="$(dirname "$(dirname "$cfg")")"
  ln -s "$prefix" .ccf-install
  echo "== Linked ./.ccf-install -> ${prefix} =="
fi

echo "== Building the app =="
./docker/build-app.sh

cat <<'EOF'

Ready. Start the interactive web demo with:

    ./demo/run_web_demo.sh        # serves http://127.0.0.1:8080

The forwarded port opens in your browser; pop out each role window from the nav.
EOF
