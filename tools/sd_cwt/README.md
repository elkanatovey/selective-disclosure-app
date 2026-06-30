# sd_cwt

A minimal, domain-agnostic **Selective Disclosure CBOR Web Token (SD-CWT)**
implementation (custom profile of
[draft-ietf-spice-sd-cwt-08](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/)),
wrapping [`pycose`](https://pypi.org/project/pycose/) + `cbor2` + `hashlib`.

It implements the subset of SD-CWT used by this project (see `docs/DESIGN.md` §13):
map + array-element redaction, **nested/recursive redaction** at arbitrary depth,
disclosures in the unprotected header, hash-alg agility via the `sd_alg` header,
decoy padding, and CSPRNG randomness. Key Binding (KBT/`cnf`) and temporal
(`exp`/`nbf`) enforcement are deliberately out of scope — the transparency-service
receipt/seqno covers those concerns.

## Layout
- `src/sd_cwt/core.py` — `issue` / `present` / `verify` / `validate` + types.
- `tests/` — `pytest` round-trip / array / nesting / negative tests.

## Develop & test (inside the dev container)
```bash
cd tools/sd_cwt
python3 -m venv .venv && . .venv/bin/activate
pip install -e .[lint]      # pycose + cbor2 (pinned) + pytest + black/isort/mypy
./scripts/checks.sh         # format + types + tests (pass -f to auto-fix)
```

## API
```python
issue(claims, redact, signer, *,
      redact_elements=None,    # {key: {indices}}  top-level array elements
      redact_paths=None,       # [(503, "region"), (700, "a", "b", 1), ...]
      sd_alg=SHA256, pad_to=None) -> (token, [Disclosure])
present(token, selected) -> token
verify(token, pubkey)    -> VerifiedToken
validate(token, pubkey)  -> ValidatedClaims  # .clear, .disclosed
```

Redaction targets are paths from the root: `redact` covers whole top-level map
entries, `redact_elements` covers top-level array indices, and `redact_paths`
covers arbitrary depth (mixing map keys and array indices). Disclosing a redacted
parent reveals a still-redacted child (ancestor-disclosure rule).

`sd_cwt` is domain-agnostic (arbitrary CBOR claims); the report/note schema and
`parent_report` rules live in the application layer on top.
