# Bug Report Submission

An end-to-end prototype for submitting a vulnerability report as a selectively
disclosable SD-CWT, registering it in SCITT, and presenting only the fields
chosen by MSRC.

## Architecture

Each role runs as an independent application with its own process and origin:

```text
Researcher :8090  --->  SCITT :8000
      |                    |
      v                    | receipt
MSRC :8091 <---------------+
      |
      | signed KBT
      v
Verifier :8092
```

| Service | Owns | Does not own |
| --- | --- | --- |
| Researcher | UI, submitted statement bytes, SCITT receipt verification | MSRC or SCITT private keys |
| MSRC | Researcher CA, holder key, delivery inbox, KBT signing | SCITT ledger state |
| Verifier | Public trust configuration only | Any private key or shared process state |
| SCITT | Ledger and receipt key | MSRC holder key |

The three applications share only [webapp/crypto.py](webapp/crypto.py), a
state-free adapter over the repository's Python `sd_cwt` reference package.
That package is pinned to commit
`9cf54783f2cb505b6bfed88cd8657c1e03bcd3c4` and performs strict draft-08
decoding, issuer signature checks, disclosure matching, and KBT signing and
verification. The Verifier derives the holder key from the signed statement's
`cnf` claim. The MSRC private key is never returned by an HTTP endpoint.

Browser issuance remains in JavaScript so the Researcher private key can stay
non-exportable in WebCrypto. CI verifies those browser-generated artifacts with
the Python reference. Real CCF receipt verification uses the official
`ccf.cose.verify_receipt` implementation. SD-CWT 0.0.2 supports `cbor2` 5.6
through 5.x, so the reference verifier and CCF tooling share one Python
environment.

## Researcher completion gate

The researcher page does not report success merely because SCITT returned an
HTTP response. Its backend must:

1. Verify the standalone SCITT receipt against the exact submitted statement.
2. Match the receipt transaction ID to the SCITT response header.
3. Fetch the transparent statement.
4. Verify that its signed bytes exactly match the browser-signed statement.
5. Verify the embedded receipt and transaction ID.

Only verified responses carry `x-receipt-verified: true`. The browser requires
that header on both registration and retrieval before delivering anything to
MSRC or displaying **Submission complete**.

## Mock demo

Requires Python 3.11 or newer and a browser with WebCrypto support.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
./scripts/run-mock-demo.sh
```

This starts four independent processes:

- Researcher: `http://127.0.0.1:8090/`
- MSRC: `http://127.0.0.1:8091/`
- Verifier: `http://127.0.0.1:8092/`
- Mock SCITT: `http://127.0.0.1:8000/`

Walk through the roles while the launcher remains running:

1. Submit at the Researcher app and download **MSRC delivery**.
2. Open the MSRC app, load `msrc-transparent-statement.cose`, select the fields
   and six-codepoint body chunks to disclose, enter the audience, sign, and
   download the `.kbt.cose` file.
3. Open the Verifier app, load the KBT, enter exactly the same expected
   audience, and inspect the independent verification results.

For a negative check, enter a different audience in the Verifier. The KBT proof
and audience check fails and the overall result is **Verification failed**.

Mock SCITT uses the same raw `application/cose` API as real SCITT:
`POST /entries` returns a COSE receipt and
`GET /entries/{txid}/statement` returns a transparent COSE statement. Its
ledger and all service keys are in memory and disappear when the launcher
stops. Mock receipts have no Merkle proof, so that check is reported as
unavailable.

## Real SCITT demo

The real-ledger launcher is supported on x86-64 Azure Linux 3, matching CI. It
requires permission to install the pinned CCF RPM, network access, and these
system tools:

```bash
gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY
tdnf update -y
tdnf install -y --disablerepo azurelinux-official-ms-non-oss \
  build-essential ca-certificates curl git jq rpm-build python3-pip \
  nodejs procps tar util-linux zstd
```

Run those package commands as root, then start the persistent demo:

```bash
./scripts/run-real-demo.sh
```

The first run downloads and verifies CCF `7.0.10`, builds SCITT commit
`28a3458f5c3ec2c2a00c868a97515fc278150546`, and creates a Python environment
for the applications and CCF tooling. Later runs reuse those installations. Wait for
`Real SCITT demo is ready`, then use the same three app URLs listed above. The
SCITT node is `https://127.0.0.1:8000`.

The launcher submits a real CCF governance proposal restricting registration
to `did:x509` identities rooted in that run's MSRC Researcher CA. SCITT verifies
the COSE signature and certificate chain before applying the policy. CI also
submits an otherwise valid statement from a foreign CA and requires SCITT to
reject it.

The browser does not connect directly to SCITT TLS. The Researcher backend uses
CCF's generated service certificate as an explicit CA and validates the node's
`127.0.0.1` identity. TLS verification is never disabled.

## Tests

```bash
.venv/bin/python -m pytest -q
```

The tests cover fixed-shape SD-CWT issuance, disclosure reconstruction,
`cnf`-derived KBT verification, wrong audience and wrong key rejection,
corrupted receipt rejection, public-only MSRC metadata, and route/state
separation across all apps.

Run the complete real-ledger integration on Azure Linux 3 with:

```bash
./scripts/ci-scitt.sh
```

It verifies exact signed-byte preservation, standalone and embedded CCF
receipts, Merkle inclusion, governed MSRC CA admission, foreign-CA rejection,
server-side holder signing, audience binding, schema, and disclosures.
Artifacts are written to `${RUNNER_TEMP:-/tmp}/scitt-ci/artifacts`.

## Project layout

- [webapp/researcher.py](webapp/researcher.py): Researcher UI and verified SCITT proxy.
- [webapp/msrc.py](webapp/msrc.py): MSRC CA, delivery validation, and KBT signing.
- [webapp/verifier.py](webapp/verifier.py): Stateless independent verification.
- [webapp/mock_scitt.py](webapp/mock_scitt.py): Standalone in-memory SCITT mock.
- [webapp/crypto.py](webapp/crypto.py): Shared state-free cryptographic operations.
- [webapp/static/sdcwt.js](webapp/static/sdcwt.js): Browser SD-CWT issuance and disclosure parsing.
- [scripts/run-mock-demo.sh](scripts/run-mock-demo.sh): Split mock launcher.
- [scripts/run-real-demo.sh](scripts/run-real-demo.sh): Split real-SCITT launcher.
- [scripts/ci-scitt.sh](scripts/ci-scitt.sh): Full real-ledger integration.

## Prototype boundaries

The MSRC CA and holder keys are ephemeral and unauthenticated researcher
endorsement is enabled for the demo. The Verifier retrieves the current MSRC
public trust metadata over its configured service connection. Production must
authenticate issuer onboarding and the MSRC UI, persist keys in an HSM or other
holder-controlled signer, and provision verifier trust anchors independently.