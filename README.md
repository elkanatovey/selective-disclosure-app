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