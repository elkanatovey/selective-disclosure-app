#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export SCITT_CI_WORK=${MST_DEMO_WORK:-/tmp/scitt-mst-demo}
export SCITT_DEMO=1
exec "$ROOT/scripts/ci-scitt.sh"
