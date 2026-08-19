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
COMMON=$NETWORK/ci_common
SCITT_PID=
WEB_PID=
FOREIGN_WEB_PID=

cleanup(){
  status=$?
  if [[ $status -ne 0 ]]; then
    printf '\nSCITT log:\n'; tail -n 120 "$WORK/scitt.log" 2>/dev/null || true
    printf '\nWebapp log:\n'; tail -n 80 "$WORK/webapp.log" 2>/dev/null || true
    printf '\nForeign issuer log:\n'; tail -n 40 "$WORK/foreign-webapp.log" 2>/dev/null || true
  fi
  [[ -z "$FOREIGN_WEB_PID" ]] || kill -- "-$FOREIGN_WEB_PID" 2>/dev/null || true
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
  python -m pip install --disable-pip-version-check -q -e "$ROOT[test]" "ccf==$CCF_VERSION" "httpx==0.23.*" "loguru>=0.7,<0.8" "jwcrypto>=1.5,<2" "PyJWT>=2.10,<3" "pyasn1>=0.6,<0.7" "Jinja2>=3.1,<4" "matplotlib>=3.10,<4" "pandas>=2,<3" certifi requests
fi
source "$VENV/bin/activate"
export PYTHONPATH="$ROOT:$SCITT_SRC/pyscitt${PYTHONPATH:+:$PYTHONPATH}"
PYTHONPATH="/opt/ccf/bin:$PYTHONPATH" python -c "import infra.e2e_args, infra.network"

WEB_HOST=127.0.0.1
[[ ${SCITT_DEMO:-0} == 1 ]] && WEB_HOST=0.0.0.0
SCITT_URL=https://127.0.0.1:8000 SCITT_CA="$COMMON/service_cert.pem" \
  setsid python -m uvicorn webapp.app:app --app-dir "$ROOT" --host "$WEB_HOST" --port 8090 >"$WORK/webapp.log" 2>&1 &
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

python - "$COMMON" "$ARTIFACTS/trust-store" "$WORK/scitt-configuration.json" <<'PY'
import json, sys
from pathlib import Path
import requests
from pyscitt import governance
from pyscitt.client import Client
from pyscitt.cli.governance import setup_local_development
from pyscitt.local_key_sign_client import LocalKeySignClient

common = Path(sys.argv[1])
trust_store = Path(sys.argv[2])
configuration_path = Path(sys.argv[3])
client = Client(
    url="https://127.0.0.1:8000",
    cacert=str(common / "service_cert.pem"),
    member_auth=LocalKeySignClient(
        (common / "member0_cert.pem").read_text(),
        (common / "member0_privk.pem").read_text(),
    ),
)
setup_local_development(client, trust_store)

issuer = requests.get("http://127.0.0.1:8090/api/state", timeout=5).json()["issuer"]
ca_prefix = issuer.split("::", 1)[0] + "::"
policy = (
    "export function apply(phdr) { "
    f"const ca = {json.dumps(ca_prefix)}; "
    "if (typeof phdr.cwt.iss !== 'string' || !phdr.cwt.iss.startsWith(ca)) "
    "{ return 'Issuer is not endorsed by the MSRC CA'; } return true; }"
)
configuration = {
    "authentication": {"allowUnauthenticated": True},
    "policy": {"policyScript": policy},
}
configuration_path.write_text(json.dumps(configuration, indent=2))
print(f"Restricting SCITT issuers to MSRC CA {ca_prefix}")
proposal = governance.set_scitt_configuration_proposal(configuration)
client.governance.propose(proposal, must_pass=True)
PY

if [[ ${SCITT_DEMO:-0} == 1 ]]; then
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
setsid python -m uvicorn webapp.app:app --app-dir "$ROOT" --host 127.0.0.1 --port 8091 >"$WORK/foreign-webapp.log" 2>&1 &
FOREIGN_WEB_PID=$!
python - <<'PY'
import time
import requests

for _ in range(40):
  try:
    if requests.get("http://127.0.0.1:8091/api/state", timeout=1).status_code == 200:
      break
  except requests.RequestException:
    pass
  time.sleep(.1)
else:
  raise TimeoutError("foreign issuer service did not become ready")
PY
node "$ROOT/scripts/scitt_flow.mjs" issue "$ARTIFACTS/foreign" http://127.0.0.1:8091
kill -- "-$FOREIGN_WEB_PID" 2>/dev/null || true
wait "$FOREIGN_WEB_PID" 2>/dev/null || true
FOREIGN_WEB_PID=
python "$ROOT/scripts/scitt_flow.py" reject --cacert "$COMMON/service_cert.pem" --output "$ARTIFACTS/foreign"
printf 'Real SCITT integration passed. Artifacts: %s\n' "$ARTIFACTS"