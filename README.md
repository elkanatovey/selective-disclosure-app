# Selective Disclosure Report Ledger

A confidential, append-only bug-report transparency ledger built on
[CCF](https://github.com/microsoft/CCF).

Reports are stored as redacted, service-signed
[SD-CWT](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/) tokens.
This enables proving a report's existence and ordering while masking its contents.
A vendor triaging
reports acts as the service Operator, a CCF user authorised by governance, and can
choose to selectively disclose individual fields of a stored report to users.
It can also prove statements about hidden fields in a stored report without revealing
the contents of the field.
This can be used to release evidence that a report is a duplicate of a previous report 
without revealing the full contents of the previous report.

The service is the sole signer. It builds and signs every statement, and
submitters only ever send raw content. Every statement has the same redacted
shape, with a uniform field count and decoy padding, so reports and follow-ups
are indistinguishable at rest.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design, threat model, and
API contract.

## Layout
- `app/` — the CCF application in C++: endpoints, token core, and confidential
  store.
- `tools/sd_cwt/` — a Python SD-CWT reference library that issues, redacts,
  presents, and verifies tokens. It is the conformance oracle for the C++ core
  and the researcher-side offline verifier of released unredacted tokens.
- `spec/` — CDDL schemas (RFC 8610) for the statement and API CBOR formats, the
  language-neutral contract both implementations follow.
- `third_party/CCF` — CCF as a git submodule, pinned to `ccf-7.0.5`.
- `docker/` — dev image and build helpers.
- `test/e2e/` — pytest end-to-end suite against a live sandbox node.

## Build
```bash
git submodule update --init --recursive   # first checkout
./docker/build-image.sh                   # build the toolchain image
./docker/dev.sh                           # enter dev container (repo at /workspace)

# Inside the container:
./docker/build-ccf.sh                     # build + install CCF
./docker/build-app.sh                     # build the app -> app/build/selective_disclosure
```
Build outputs land under the mounted repo, in `.ccf-install/` and `*/build/`, so
they persist across container restarts.

## Interactive Demo
The demo runs a narrated end-to-end walkthrough. It boots a node, submits a
report, retrieves the redacted token, then has the Operator pull the full report
and release a partial disclosure.
```bash
./demo/run_demo.sh          # add --step to pause between steps
```
The demo builds nothing itself. It needs the app built with
`./docker/build-app.sh` and a CCF install at `./.ccf-install`. It creates or
refreshes a Python venv for the sandbox and verifier, boots the node, runs
[`demo/demo.py`](demo/demo.py), and tears the node down on exit. See
[`demo/`](demo) for details.

### Interactive web demo
For a browser-based version with a page per role (member, client, operator,
researcher) that you can play in separate windows, with live updates:
```bash
./demo/run_web_demo.sh      # serves http://127.0.0.1:8080
```
Same prereqs as above. A small FastAPI backend holds the sandbox certs and acts
as the real ledger client (mutual TLS + CBOR/COSE + offline `sd_cwt`
verification); the browser talks JSON to it. See
[`demo/webapp/`](demo/webapp) for details.

## Run the node
The app is the node, a CCF 7.x standalone binary. Launch a single-node dev
sandbox with the installed `sandbox.sh`:
```bash
.ccf-install/bin/sandbox.sh --package app/build/selective_disclosure
```
This opens a node at `https://127.0.0.1:8000`, and application endpoints are
served under the `/app` prefix. The sandbox writes certs and member and user
keys to `workspace/sandbox_common/`:
- `service_cert.pem` — the service, or network, identity. Use it as the TLS root.
- `member0_*` — a governance member for control-plane actions.
- `user0_*` — a CCF user. This ledger treats `user0` as the Operator for the
  confidential-egress endpoints.

## API
The API takes CBOR in and returns COSE or CBOR out. All paths sit under `/app`.
There are ten endpoints, covering submission, public read and verify,
member-gated key registration, and Operator-only confidential egress such as
unredacted reads, selective disclosure, and follow-ups.

The full reference is [`docs/API.md`](docs/API.md), which lists every endpoint's
query params, request and response shapes, status codes, and auth. The design
rationale is in [`docs/DESIGN.md`](docs/DESIGN.md) §9, and a running node
self-documents through an auto-generated OpenAPI 3.0 document at `GET /app/api`.

### Quick check with `curl`
The no-auth endpoints work with `curl` using the sandbox's service cert as the
TLS root. Responses are CBOR, so pipe them through a decoder to read them:
```bash
CA=workspace/sandbox_common/service_cert.pem
# GET /version (CBOR -> JSON via a one-line decoder):
curl -s --cacert "$CA" https://127.0.0.1:8000/app/version \
  | python3 -c 'import sys,cbor2,json; print(json.dumps(cbor2.load(sys.stdin.buffer), default=repr))'
# -> {"app_version": "0.0.1", "schema_version": 1, "ccf_version": "ccf-7.0.5"}
```
`curl` is fine for smoke tests, but bodies are CBOR and submissions must be
CBOR-encoded, so the Python example below is the practical way to use the API.

## Python Example
Requires `pip install requests` and `pip install -e tools/sd_cwt`, which brings
in `cbor2`, `pycose`, and `cryptography`. Point it at a running sandbox.
```python
import cbor2, requests
from pathlib import Path

BASE = "https://127.0.0.1:8000/app"
COMMON = Path("workspace/sandbox_common")
CA = str(COMMON / "service_cert.pem")
member = (str(COMMON / "member0_cert.pem"), str(COMMON / "member0_privk.pem"))
operator = (str(COMMON / "user0_cert.pem"), str(COMMON / "user0_privk.pem"))

# 0) One-time: initialise the issuer signing key (governance / member-gated).
requests.post(f"{BASE}/signing-key", data=b"", cert=member, verify=CA)

# 1) Submit a report. The committed transaction id comes back in a header.
report = {"title": "heap overflow", "component": "parser",
          "severity": "high", "fingerprint": b"\xde\xad\xbe\xef"}
r = requests.post(f"{BASE}/reports", data=cbor2.dumps(report),
                  headers={"content-type": "application/cbor"}, verify=CA)
txid = r.headers["x-ms-ccf-transaction-id"]
print("committed:", txid)

# 2) Anyone can retrieve the redacted transparent statement + verify its receipt.
stmt = requests.get(f"{BASE}/statements/{txid}", verify=CA)   # application/cose

# 3) The Operator can read it unredacted, or selectively disclose one field.
disc = requests.post(
    f"{BASE}/operator/statements/{txid}/disclosure",
    data=cbor2.dumps({"fields": ["fingerprint"]}),  # prove the fingerprint only
    headers={"content-type": "application/cbor"}, cert=operator, verify=CA)

# 4) A researcher verifies the disclosed statement OFFLINE against the issuer key.
#    The issuer key is published and endorsed by the service identity via the
#    receipt in GET /signing-key (verify that endorsement to trust the key; see
#    test/e2e/helpers.py::verify_endorsed_key, exercised by
#    test_signing_key_is_endorsed in test/e2e/test_reports.py).
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pycose.keys import EC2Key
from pycose.keys.curves import P256
from sd_cwt import statement as st

issuer_pem = cbor2.loads(requests.get(f"{BASE}/signing-key", verify=CA).content)["key"]
nums = load_pem_public_key(issuer_pem).public_numbers()  # default curve P-256
issuer_key = EC2Key(crv=P256, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))

# validate_statement checks the issuer signature and resolves the presented
# disclosures. There is no key-binding token because the service is the sole
# signer.
out = st.validate_statement(disc.content, issuer_key)
print("disclosed:", out.disclosed)          # {1005: b'\xde\xad\xbe\xef'}, the fingerprint
assert out.disclosed[st.FINGERPRINT] == b"\xde\xad\xbe\xef"
```
For end-to-end examples with cryptographic verification through the `sd_cwt`
reference verifier, see `test/e2e/test_reports.py`. The reusable verify and
submit helpers it builds on live in `test/e2e/helpers.py`.

## Testing
```bash
# C++ unit tests (token core, parser, disclosure store, paging):
cmake -B app/build-test -S app -GNinja -DBUILD_TESTS=ON
ninja -C app/build-test unit_tests && ./app/build-test/unit_tests

# Python SD-CWT reference library:
pip install -e "tools/sd_cwt[test]" && pytest tools/sd_cwt

# End-to-end suite against a live sandbox node:
INSTALL_DIR=$PWD/.ccf-install ./scripts/ci-e2e-tests.sh
```

## Notes
- CCF is built from source as a submodule for dev purposes,
  and all CCF build options are left enabled. Parallelism is throttled
  in `docker/build-ccf.sh` through `NPROC_COMPILE` and `NPROC_LINK` to avoid
  running out of memory on 16 GB RAM machines.
