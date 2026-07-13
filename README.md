# Selective Disclosure Report Ledger

A confidential, append-only **bug-report transparency ledger** built on
[CCF](https://github.com/microsoft/CCF) (Confidential Consortium Framework).

Reports are registered as **redacted, service-signed
[SD-CWT](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/) tokens**
(Selective Disclosure CBOR Web Tokens): the ledger proves a report's
**existence, ordering, and integrity** to anyone, while its **contents stay
hidden**. A vendor triaging reports acts as the **Operator** (a CCF user
authorised by governance) and can then **selectively disclose** individual fields
of a stored report — for example to prove a new submission is a duplicate —
without revealing the rest.

The service itself is the **sole signer**: it constructs and signs every
statement (submitters send raw content, never signatures), and every statement
has an **identical redacted shape** (uniform field count, decoy padding), so
reports and follow-ups are indistinguishable at rest.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design, threat model, and
API contract.

## Layout
- `app/` — the CCF application (C++): endpoints, token core, confidential store.
- `tools/sd_cwt/` — a Python SD-CWT reference library (issue / redact / present /
  verify) used as the conformance oracle for the C++ core and as the
  researcher-side offline verifier.
- `spec/` — CDDL (RFC 8610) schemas for the statement + API CBOR formats — the
  language-neutral contract both implementations conform to.
- `third_party/CCF` — CCF as a git submodule, pinned to `ccf-7.0.5`.
- `docker/` — dev image + build helpers.
- `test/e2e/` — pytest end-to-end suite against a live sandbox node.

## Build (edit on host, build in container)
```bash
git submodule update --init --recursive   # first checkout
./docker/build-image.sh                   # build the toolchain image (once)
./docker/dev.sh                           # enter dev container (repo at /workspace)

# Inside the container:
./docker/build-ccf.sh                     # build + install CCF (slow, first time only)
./docker/build-app.sh                     # build the app -> app/build/selective_disclosure
```
Build outputs land under the mounted repo (`.ccf-install/`, `*/build/`) so they
persist across container restarts.

## Demo (one command)
For a narrated end-to-end walkthrough — boot a node, submit a report, retrieve
the redacted token, then have the Operator pull the full report and release a
*partial* disclosure — run:
```bash
./demo/run_demo.sh          # or: ./demo/run_demo.sh --step  (pause between steps)
```
It builds nothing itself; it just needs the app built (`./docker/build-app.sh`)
and a CCF install at `./.ccf-install`. On first run it creates a Python venv for
the sandbox + verifier, boots the node, runs [`demo/demo.py`](demo/demo.py), and
tears the node down on exit. See [`demo/`](demo) for details.

## Run the node
The app **is** the node (CCF 7.x standalone binary). Launch a single-node dev
sandbox with the installed `sandbox.sh`:
```bash
.ccf-install/bin/sandbox.sh --package app/build/selective_disclosure
```
This opens a node at `https://127.0.0.1:8000`; application endpoints are served
under the **`/app`** prefix. The sandbox writes certs and member/user keys to
`workspace/sandbox_common/`:
- `service_cert.pem` — the service (network) identity; use it as the TLS root.
- `member0_*` — a governance member (control-plane actions).
- `user0_*` — a CCF user; this ledger treats **`user0` as the Operator** for the
  confidential-egress endpoints.

## API
Formats: **CBOR in, COSE/CBOR out.** All paths are under `/app`. There are ten
endpoints — submission, public read/verify, member-gated key registration, and
Operator-only confidential egress (unredacted reads, selective disclosure,
follow-ups).

**The full reference is [`docs/API.md`](docs/API.md)** — every endpoint's query
params, request/response shapes, status codes, and auth. The design rationale is
in [`docs/DESIGN.md`](docs/DESIGN.md) §9, and a running node self-documents via an
auto-generated **OpenAPI 3.0** document at `GET /app/api`.

### Quick check with `curl`
The no-auth endpoints are reachable with `curl` using the sandbox's service cert
as the TLS root. Responses are **CBOR**, so pipe them through a decoder to read
them:
```bash
CA=workspace/sandbox_common/service_cert.pem
# GET /version (CBOR -> JSON via a one-line decoder):
curl -s --cacert "$CA" https://127.0.0.1:8000/app/version \
  | python3 -c 'import sys,cbor2,json; print(json.dumps(cbor2.load(sys.stdin.buffer), default=repr))'
# -> {"app_version": "0.0.1", "schema_version": 1, "ccf_version": "ccf-7.0.5"}
```
`curl` is handy for smoke tests, but because bodies are CBOR (and submissions
must be CBOR-encoded), the Python example below is the practical way to use the
API.

## Example (Python)
Requires `pip install requests` and `pip install -e tools/sd_cwt` (which brings in
`cbor2`, `pycose`, and `cryptography`). Point it at a running sandbox.
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

# 1) Submit a report (CBOR). The committed transaction id comes back in a header.
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
#    test/e2e/test_reports.py::_verify_endorsed_key).
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pycose.keys import EC2Key
from pycose.keys.curves import P256
from sd_cwt import statement as st

issuer_pem = cbor2.loads(requests.get(f"{BASE}/signing-key", verify=CA).content)["key"]
nums = load_pem_public_key(issuer_pem).public_numbers()  # default curve P-256
issuer_key = EC2Key(crv=P256, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))

# validate_statement checks the ISSUER SIGNATURE and resolves the presented
# disclosures (no key-binding token — the service is the sole signer).
out = st.validate_statement(disc.content, issuer_key)
print("disclosed:", out.disclosed)          # {1005: b'\xde\xad\xbe\xef'} (fingerprint)
assert out.disclosed[st.FINGERPRINT] == b"\xde\xad\xbe\xef"
```
(For end-to-end examples incl. cryptographic verification with the `sd_cwt`
reference verifier, see `test/e2e/test_reports.py`.)

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
- CCF is built **from source** (submodule) so the framework itself can be
  modified; all CCF build options are left enabled. Parallelism is throttled in
  `docker/build-ccf.sh` (`NPROC_COMPILE`, `NPROC_LINK`) to avoid OOM on 16 GB.
