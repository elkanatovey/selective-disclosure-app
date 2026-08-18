#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CCF_VERSION=${CCF_VERSION:-7.0.10}
CCF_RPM_SHA256=${CCF_RPM_SHA256:-4c7f31109aba8893015f4466071d5d964f7117ae0233dd074c96e47eadafe1bc}
SCITT_COMMIT=${SCITT_COMMIT:-28a3458f5c3ec2c2a00c868a97515fc278150546}
WORK=${SCITT_CI_WORK:-${RUNNER_TEMP:-/tmp}/scitt-ci}
SCITT_SRC=${SCITT_SRC:-$WORK/scitt-ccf-ledger}
SCITT_INSTALL=${SCITT_INSTALL:-$WORK/install}
VENV=${SCITT_CI_VENV:-$WORK/venv}
NETWORK=$WORK/network
ARTIFACTS=$WORK/artifacts
SCITT_PID=
WEB_PID=

cleanup(){
  status=$?
  if [[ $status -ne 0 ]]; then
    printf '\nSCITT log:\n'; tail -n 120 "$WORK/scitt.log" 2>/dev/null || true
    printf '\nWebapp log:\n'; tail -n 80 "$WORK/webapp.log" 2>/dev/null || true
  fi
  [[ -z "$WEB_PID" ]] || kill -- "-$WEB_PID" 2>/dev/null || true
  [[ -z "$SCITT_PID" ]] || kill -- "-$SCITT_PID" 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p "$WORK" "$ARTIFACTS"

if ! rpm -q "ccf_devel-${CCF_VERSION}-1.x86_64" >/dev/null 2>&1; then
  rpm_name="ccf_devel_${CCF_VERSION}_x86_64.rpm"
  curl -fL "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/${rpm_name}" -o "$WORK/ccf.rpm"
  echo "${CCF_RPM_SHA256}  $WORK/ccf.rpm" | sha256sum -c -
  tdnf install -y "$WORK/ccf.rpm"
fi

if [[ ! -d "$SCITT_SRC/.git" ]]; then
  git init "$SCITT_SRC"
  git -C "$SCITT_SRC" remote add origin https://github.com/microsoft/scitt-ccf-ledger.git
  git -C "$SCITT_SRC" fetch --depth=1 origin "$SCITT_COMMIT"
  git -C "$SCITT_SRC" checkout --detach FETCH_HEAD
fi
[[ $(git -C "$SCITT_SRC" rev-parse HEAD) == "$SCITT_COMMIT" ]]

if [[ ! -x "$SCITT_INSTALL/bin/cchost" ]]; then
  cmake -S "$SCITT_SRC/app" -B "$WORK/build" -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX="$SCITT_INSTALL" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DBUILD_TESTS=OFF
  cmake --build "$WORK/build" --target install
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
  source "$VENV/bin/activate"
  python -m pip install --disable-pip-version-check -q -U pip
  python -m pip install --disable-pip-version-check -q -e "$ROOT[test]" "ccf==$CCF_VERSION" "httpx==0.23.*" "loguru>=0.7,<0.8" "jwcrypto>=1.5,<2" "PyJWT>=2.10,<3" certifi requests
fi
source "$VENV/bin/activate"
export PYTHONPATH="$ROOT:$SCITT_SRC/pyscitt${PYTHONPATH:+:$PYTHONPATH}"

setsid python -m uvicorn webapp.app:app --app-dir "$ROOT" --host 127.0.0.1 --port 8090 >"$WORK/webapp.log" 2>&1 &
WEB_PID=$!
export CURL_CLIENT=ON INITIAL_MEMBER_COUNT=1
setsid python /opt/ccf/bin/start_network.py --binary-dir /opt/ccf/bin --package "$SCITT_INSTALL/bin/cchost" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/actions.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/validate.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/resolve.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/apply.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/scitt.js" \
  --workspace "$NETWORK" --label ci --node local://127.0.0.1:8000 \
  --initial-member-count 1 --initial-user-count 0 --initial-recovery-participant-count 1 \
  --ledger-chunk-bytes 5000000 --snapshot-tx-interval 10000 >"$WORK/scitt.log" 2>&1 &
SCITT_PID=$!

python - "$NETWORK/ci_common/service_cert.pem" <<'PY'
import sys,time
from pathlib import Path
import requests
cert=Path(sys.argv[1])
for _ in range(240):
    if cert.exists():
        try:
            response=requests.get('https://127.0.0.1:8000/node/network',verify=cert,timeout=1)
            if response.status_code==200 and response.json().get('service_status')=='Open':
              break
        except requests.RequestException:
            pass
    time.sleep(.25)
else:
    raise TimeoutError('SCITT did not become ready')
PY

COMMON=$NETWORK/ci_common
python -m pyscitt.cli.governance local_development --url https://127.0.0.1:8000 \
  --cacert "$COMMON/service_cert.pem" --member-key "$COMMON/member0_privk.pem" \
  --member-cert "$COMMON/member0_cert.pem" --service-trust-store "$ARTIFACTS/trust-store"

if [[ ${SCITT_DEMO:-0} == 1 ]]; then
  kill -- "-$WEB_PID" 2>/dev/null || true
  wait "$WEB_PID" 2>/dev/null || true
  WEB_PID=
  SCITT_URL=https://127.0.0.1:8000 SCITT_CA="$COMMON/service_cert.pem" \
    setsid python -m uvicorn webapp.app:app --app-dir "$ROOT" --host 0.0.0.0 --port 8090 >"$WORK/webapp.log" 2>&1 &
  WEB_PID=$!
  printf '\nReal SCITT demo is ready:\n'
  printf '  Researcher: http://127.0.0.1:8090/\n'
  printf '  MSRC:       http://127.0.0.1:8090/msrc\n'
  printf '  Verifier:   http://127.0.0.1:8090/verify\n'
  printf '  SCITT:      https://127.0.0.1:8000\n'
  printf '\nKeep this process running. Press Ctrl+C to stop the demo.\n'
  wait "$WEB_PID"
  exit
fi

node "$ROOT/scripts/scitt_flow.mjs" issue "$ARTIFACTS"
python "$ROOT/scripts/scitt_flow.py" submit --cacert "$COMMON/service_cert.pem" --output "$ARTIFACTS"
node "$ROOT/scripts/scitt_flow.mjs" present "$ARTIFACTS"
python "$ROOT/scripts/scitt_flow.py" verify --cacert "$COMMON/service_cert.pem" --output "$ARTIFACTS"
printf 'Real SCITT integration passed. Artifacts: %s\n' "$ARTIFACTS"