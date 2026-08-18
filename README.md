# Bug Report Submission

A minimal researcher-side SD-CWT web flow with real cryptography and local mocks.

```text
browser key -> mock governance endorsement
            -> redacted statement -> mock SCITT -> receipt
            -> full disclosure + receipt -> MSRC
```

The browser generates a non-exportable ephemeral P-256 issuer key. Mock
governance signs its public key certificate. The browser builds and signs the
strict nine-field report profile; absent fields use random padding and all
fields are redacted. The clear `cnf` claim contains MSRC's public key. SCITT
receives only the redacted COSE Sign1; MSRC receives every disclosure and the
embedded receipt.

Body text is NFC/newline-normalized and stored as independently redactable,
position-preserving six-codepoint chunks beneath the redacted `body` field.

The form exposes each report field separately. The researcher may either use a
fresh ephemeral key or upload a private P-256 key as PKCS#8 PEM/private JWK. An
uploaded key is imported locally and only its public JWK is sent for endorsement.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
uvicorn webapp.app:app --host 127.0.0.1 --port 8090
```

Open `http://127.0.0.1:8090`. Run tests with `pytest`.

Open `http://127.0.0.1:8090/msrc` for disclosure review. Load the downloaded
`msrc-transparent-statement.cose`, uncheck fields or individual body/reference
chunks to redact them, set the verifier audience, sign the Key Binding Token,
then export `*.kbt.cose`.

The prototype exposes the mock MSRC holder key to the MSRC browser page. A real
deployment must authenticate this page and keep that key in local secure storage
or an HSM rather than returning it from an HTTP endpoint.

Open `http://127.0.0.1:8090/verify` to verify an exported KBT against an
externally supplied expected audience. The verifier displays the selectively
disclosed report and separate status rows for COSE algorithms, issuer trust and
signature, the SCITT receipt, KBT proof/freshness/audience, and disclosure
consistency. Real Merkle inclusion remains explicitly unavailable in the mock.

## Interactive demo

Start the web server:

```bash
. .venv/bin/activate
uvicorn webapp.app:app --host 127.0.0.1 --port 8090
```

Then walk through the three roles:

1. Open `http://127.0.0.1:8090`, submit a report, and download **MSRC delivery**.
2. Open `http://127.0.0.1:8090/msrc`, load that `.cose` file, click or drag over
    six-character body spans to redact/restore them, set the audience, sign, and
    download the signed disclosure.
3. Open `http://127.0.0.1:8090/verify`, load the `.kbt.cose`, enter the same
    audience, and inspect the redacted report plus every verification result.

The local mock state is in memory, so keep the same server process running for
all three steps.

To run the same interactive pages against an actual local SCITT CCF Ledger
instead of the mock registry:

```bash
./scripts/run-real-demo.sh
```

The first run installs/builds the pinned CCF/SCITT dependencies when necessary.
Keep the command running, then use the same three URLs above. The submission
page header will say **Real SCITT**, and its transaction/receipt come from the
node on `https://127.0.0.1:8000`. Press Ctrl+C to stop both services.

## Real SCITT integration

CI pins CCF `7.0.10` and SCITT commit
`28a3458f5c3ec2c2a00c868a97515fc278150546`. On Azure Linux 3, run the same
browser-crypto-to-real-ledger test with:

```bash
./scripts/ci-scitt.sh
```

It builds and launches SCITT, configures local governance, issues the SD-CWT
with `webapp/static/sdcwt.js`, registers it through `/entries`, verifies the
real standalone and embedded CCF receipts, constructs a partial KBT, and verifies
the holder signature, audience, report schema, and disclosures. Generated
artifacts are written under `${RUNNER_TEMP:-/tmp}/scitt-ci/artifacts`.