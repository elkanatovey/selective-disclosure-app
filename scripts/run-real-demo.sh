#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -z ${SCITT_SRC:-} && -d /tmp/scitt-ccf-ledger-main/.git ]]; then
  export SCITT_SRC=/tmp/scitt-ccf-ledger-main
fi
if [[ -z ${SCITT_INSTALL:-} && -x /tmp/scitt/bin/cchost ]]; then
  export SCITT_INSTALL=/tmp/scitt
fi
export SCITT_CI_WORK=${SCITT_DEMO_WORK:-/tmp/scitt-real-demo}
export SCITT_DEMO=1
exec "$ROOT/scripts/ci-scitt.sh"
