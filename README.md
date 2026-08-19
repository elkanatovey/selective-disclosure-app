# Bug Report Submission

An end-to-end prototype for submitting a vulnerability report as a selectively
disclosable SD-CWT, registering the signed statement in SCITT, and later
presenting only the fields chosen by MSRC.

```text
Researcher browser
    -> signs SD-CWT with cnf = MSRC public key
    -> registers the redacted statement in SCITT
    -> delivers the transparent statement to MSRC
MSRC
    -> selects disclosures and signs a KBT
    -> sends the presentation to the verifier
Verifier
    -> checks trust, receipt, holder proof, audience, and disclosures
```

The repository supports two registry modes:

- **Mock mode** runs every service in one FastAPI process for a quick demo.
- **Real mode** registers statements with an actual local SCITT CCF Ledger and
    verifies its CCF receipt and Merkle inclusion proof. Governance endorsement
    and MSRC key custody remain local prototype services in both modes.

## What the prototype does

- Generates a non-exportable P-256 researcher signing key in the browser, or
    imports a private P-256 PKCS#8 PEM/JWK without uploading the private key.
- Fetches MSRC's public key automatically and places it in the SD-CWT `cnf`
    claim before signing.
- Encodes the strict nine-claim report profile. Missing fields receive random
    padding so the public statement always has the same shape.
- Splits normalized body text into independently redactable,
    position-preserving six-codepoint chunks. References are independently
    redactable as well.
- Sends only the redacted COSE Sign1 statement to SCITT, then gives MSRC the
    complete disclosures with the embedded SCITT receipt.
- Lets MSRC select fields and chunks, bind the presentation to an audience,
    sign a Key Binding Token (KBT) with the key named by `cnf`, and export it.
- Verifies the issuer signature and trust chain, SCITT receipt, KBT holder
    proof, expected audience, freshness, report schema, and disclosure hashes.

## Mock demo

Requires Python 3.11 or newer and a browser with WebCrypto support.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m uvicorn webapp.app:app --host 127.0.0.1 --port 8090
```

Keep that process running while completing the three roles:

1. Open `http://127.0.0.1:8090/`. Submit a report, then download **MSRC
     delivery** (`msrc-transparent-statement.cose`).
2. Open `http://127.0.0.1:8090/msrc`. Load the MSRC delivery, click fields or
     click and drag over body chunks to redact or restore them, enter the
     verifier audience, select **Sign disclosure**, and export the `.kbt.cose`.
3. Open `http://127.0.0.1:8090/verify`. Load the KBT and enter exactly the same
     expected audience. A valid presentation shows **Disclosure verified** and
     the independently disclosed report content.

For a negative check, verify the same KBT with a different expected audience.
The KBT proof and audience check fails and the overall result is
**Verification failed**.

Mock state and keys exist only in memory. Restarting the server invalidates
artifacts from the previous process. The mock receipt has no Merkle proof, so
that check is shown as unavailable rather than passed.

## Real SCITT demo

The real-ledger launcher is supported on x86-64 Azure Linux 3, matching the CI
job. It requires permission to install the pinned CCF RPM on its first run,
network access, and these system tools:

```bash
gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY
tdnf update -y
tdnf install -y --disablerepo azurelinux-official-ms-non-oss \
    build-essential ca-certificates curl git jq rpm-build python3-pip \
    nodejs procps tar util-linux zstd
```

Run those package commands as root in the Azure Linux environment. Then, from
the repository root, start the persistent demo:

```bash
./scripts/run-real-demo.sh
```

The first run downloads and verifies CCF `7.0.10`, clones and builds SCITT at
commit `28a3458f5c3ec2c2a00c868a97515fc278150546`, and creates an isolated Python
environment under `/tmp/scitt-real-demo`. It can take several minutes. Later
runs reuse the built SCITT tree and environment.

Wait for `Real SCITT demo is ready`, keep the command running, and follow the
same three-page walkthrough:

- Researcher: `http://127.0.0.1:8090/`
- MSRC: `http://127.0.0.1:8090/msrc`
- Verifier: `http://127.0.0.1:8090/verify`
- SCITT node: `https://127.0.0.1:8000`

The browser does not connect directly to the SCITT HTTPS endpoint. Its
same-origin requests go to FastAPI on port 8090, and FastAPI submits them to
SCITT. The backend uses CCF's generated service certificate as an explicit CA
and validates the node certificate for `127.0.0.1`; TLS verification is not
disabled. Opening port 8000 directly in a browser would require installing that
local service certificate as a trusted CA.

The researcher page header says **Real SCITT** in this mode. Registration,
transaction ID, receipt, and Merkle proof come from the local CCF node. Press
Ctrl+C in the launcher terminal to stop both services. Ports 8090 and 8000 must
be available before starting it.

## Tests

Run the unit and negative-path tests after installing the mock demo:

```bash
.venv/bin/python -m pytest -q
```

To run the non-interactive browser-crypto-to-real-ledger integration on Azure
Linux 3:

```bash
./scripts/ci-scitt.sh
```

The integration launches SCITT, applies local-development governance, issues
the SD-CWT with `webapp/static/sdcwt.js`, registers it through `/entries`, and
checks exact signed-byte preservation, standalone and embedded CCF receipts,
Merkle inclusion, holder proof, audience binding, schema, and disclosures. It
writes artifacts to `${RUNNER_TEMP:-/tmp}/scitt-ci/artifacts` and stops its
services when complete.

## Prototype security boundary

The MSRC page currently retrieves the prototype holder private key from the
FastAPI process. A deployment must authenticate the MSRC interface and keep
that key in browser-backed secure storage, an HSM, or another holder-controlled
signing service. Similarly, the mock governance endpoint is only a stand-in for
an actual governed issuer onboarding process.
