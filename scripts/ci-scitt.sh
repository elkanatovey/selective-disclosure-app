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
VENV_STAMP=$VENV/.scitt-runtime-v5
NETWORK=$WORK/network
ARTIFACTS=$WORK/artifacts
COMMON=$NETWORK/ci_common
SCITT_PID=
RESEARCHER_PID=
MSRC_PID=
VERIFIER_PID=
FOREIGN_MSRC_PID=

cleanup(){
  status=$?
  if [[ $status -ne 0 ]]; then
    printf '\nSCITT log:\n'; tail -n 120 "$WORK/scitt.log" 2>/dev/null || true
    printf '\nResearcher log:\n'; tail -n 80 "$WORK/researcher.log" 2>/dev/null || true
    printf '\nMSRC log:\n'; tail -n 80 "$WORK/msrc.log" 2>/dev/null || true
    printf '\nVerifier log:\n'; tail -n 80 "$WORK/verifier.log" 2>/dev/null || true
    printf '\nForeign MSRC log:\n'; tail -n 40 "$WORK/foreign-msrc.log" 2>/dev/null || true
  fi
  [[ -z "$FOREIGN_MSRC_PID" ]] || kill -- "-$FOREIGN_MSRC_PID" 2>/dev/null || true
  [[ -z "$RESEARCHER_PID" ]] || kill -- "-$RESEARCHER_PID" 2>/dev/null || true
  [[ -z "$MSRC_PID" ]] || kill -- "-$MSRC_PID" 2>/dev/null || true
  [[ -z "$VERIFIER_PID" ]] || kill -- "-$VERIFIER_PID" 2>/dev/null || true
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

if [[ ! -x "$VENV/bin/python" || ! -f "$VENV_STAMP" ]]; then
  [[ -x "$VENV/bin/python" ]] || python3 -m venv "$VENV"
  "$VENV/bin/python" -m pip install --disable-pip-version-check -q -U pip
  "$VENV/bin/python" -m pip install --disable-pip-version-check -q -e "$ROOT" "ccf==$CCF_VERSION" "httpx==0.23.*" "loguru>=0.7,<0.8" "jwcrypto>=1.5,<2" "PyJWT>=2.10,<3" "pyasn1>=0.6,<0.7" "Jinja2>=3.1,<4" "matplotlib>=3.10,<4" "pandas>=2,<3" certifi
  touch "$VENV_STAMP"
fi
PYTHON=$VENV/bin/python
export PATH="$VENV/bin:$PATH"
PYTHONPATH="/opt/ccf/bin:$ROOT:$SCITT_SRC/pyscitt${PYTHONPATH:+:$PYTHONPATH}"
PYTHONPATH="$PYTHONPATH" "$PYTHON" -c "import ccf.cose, infra.e2e_args, infra.network, sd_cwt; assert hasattr(sd_cwt, 'verify')"

APP_HOST=127.0.0.1
[[ ${SCITT_DEMO:-0} == 1 ]] && APP_HOST=0.0.0.0
SCITT_URL=https://127.0.0.1:8000 SCITT_CA="$COMMON/service_cert.pem" \
  RESEARCHER_ORIGIN=http://127.0.0.1:8090 \
  setsid "$PYTHON" -m uvicorn webapp.msrc:app --app-dir "$ROOT" --host "$APP_HOST" --port 8091 >"$WORK/msrc.log" 2>&1 &
MSRC_PID=$!
MSRC_URL=http://127.0.0.1:8091 SCITT_URL=https://127.0.0.1:8000 SCITT_CA="$COMMON/service_cert.pem" \
  setsid "$PYTHON" -m uvicorn webapp.researcher:app --app-dir "$ROOT" --host "$APP_HOST" --port 8090 >"$WORK/researcher.log" 2>&1 &
RESEARCHER_PID=$!
MSRC_URL=http://127.0.0.1:8091 SCITT_URL=https://127.0.0.1:8000 SCITT_CA="$COMMON/service_cert.pem" \
  setsid "$PYTHON" -m uvicorn webapp.verifier:app --app-dir "$ROOT" --host "$APP_HOST" --port 8092 >"$WORK/verifier.log" 2>&1 &
VERIFIER_PID=$!
export CURL_CLIENT=ON INITIAL_MEMBER_COUNT=1
PYTHONPATH="$PYTHONPATH" setsid "$PYTHON" /opt/ccf/bin/start_network.py --binary-dir /opt/ccf/bin --package "$SCITT_INSTALL/bin/cchost" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/actions.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/validate.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/resolve.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/apply.js" \
  --constitution "$SCITT_INSTALL/share/scitt/constitution/scitt.js" \
  --workspace "$NETWORK" --label ci --node local://127.0.0.1:8000 \
  --initial-member-count 1 --initial-user-count 0 --initial-recovery-participant-count 1 \
  --ledger-chunk-bytes 5000000 --snapshot-tx-interval 10000 >"$WORK/scitt.log" 2>&1 &
SCITT_PID=$!

"$PYTHON" - "$NETWORK/ci_common/service_cert.pem" <<'PY'
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

PYTHONPATH="$PYTHONPATH" "$PYTHON" - "$COMMON" "$ARTIFACTS/trust-store" "$WORK/scitt-configuration.json" <<'PY'
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

issuer = requests.get("http://127.0.0.1:8091/api/public", timeout=5).json()["issuer"]
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
  printf '  MSRC:       http://127.0.0.1:8091/\n'
  printf '  Verifier:   http://127.0.0.1:8092/\n'
  printf '  SCITT:      https://127.0.0.1:8000\n'
  printf '\nKeep this process running. Press Ctrl+C to stop the demo.\n'
  wait "$RESEARCHER_PID"
  exit
fi

node "$ROOT/scripts/scitt_flow.mjs" issue "$ARTIFACTS"
"$PYTHON" "$ROOT/scripts/scitt_flow.py" submit --cacert "$COMMON/service_cert.pem" --output "$ARTIFACTS" --researcher-url http://127.0.0.1:8090
node "$ROOT/scripts/scitt_flow.mjs" present "$ARTIFACTS"
"$PYTHON" "$ROOT/scripts/scitt_flow.py" verify --cacert "$COMMON/service_cert.pem" --output "$ARTIFACTS"
"$PYTHON" - "$ARTIFACTS" <<'PY'
import json, sys
from pathlib import Path
import requests

artifacts = Path(sys.argv[1])
audience = json.loads((artifacts / "expected.json").read_text())["audience"]
response = requests.post(
  "http://127.0.0.1:8092/api/verify",
  params={"audience": audience},
  data=(artifacts / "disclosure.kbt.cose").read_bytes(),
  headers={"content-type": "application/cose"},
  timeout=30,
)
response.raise_for_status()
if not response.json()["valid"]:
  raise AssertionError("independent verifier rejected the real SCITT disclosure")
print(json.dumps({"phase": "verifier-app", "valid": True}))
PY
SCITT_URL=https://127.0.0.1:8000 SCITT_CA="$COMMON/service_cert.pem" \
  setsid "$PYTHON" -m uvicorn webapp.msrc:app --app-dir "$ROOT" --host 127.0.0.1 --port 8093 >"$WORK/foreign-msrc.log" 2>&1 &
FOREIGN_MSRC_PID=$!
"$PYTHON" - <<'PY'
import time
import requests

for _ in range(40):
  try:
    if requests.get("http://127.0.0.1:8093/api/public", timeout=1).status_code == 200:
      break
  except requests.RequestException:
    pass
  time.sleep(.1)
else:
  raise TimeoutError("foreign MSRC service did not become ready")
PY
node "$ROOT/scripts/scitt_flow.mjs" issue-foreign "$ARTIFACTS/foreign" http://127.0.0.1:8093
kill -- "-$FOREIGN_MSRC_PID" 2>/dev/null || true
wait "$FOREIGN_MSRC_PID" 2>/dev/null || true
FOREIGN_MSRC_PID=
"$PYTHON" "$ROOT/scripts/scitt_flow.py" reject --cacert "$COMMON/service_cert.pem" --output "$ARTIFACTS/foreign"
printf 'Real SCITT integration passed. Artifacts: %s\n' "$ARTIFACTS"