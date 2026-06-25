# sd_cwt

A minimal, domain-agnostic **Selective Disclosure CBOR Web Token (SD-CWT)**
implementation (custom profile of
[draft-ietf-spice-sd-cwt-08](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/)),
wrapping [`pycose`](https://pypi.org/project/pycose/) + `cbor2` + `hashlib`.

It implements only the subset this project needs (see `docs/DESIGN.md` §13):
map + array-element redaction, disclosures in the unprotected header, hash-alg
agility via the `sd_alg` header, decoy padding, and CSPRNG randomness. Key
Binding (KBT/`cnf`) and temporal (`exp`/`nbf`) enforcement are deliberately out
of scope — the transparency-service receipt/seqno covers those concerns.

## Layout
- `src/sd_cwt/core.py` — `issue` / `present` / `verify` / `validate` + types.
- `tests/` — `pytest` round-trip tests (TDD).

## Develop & test (inside the dev container)
```bash
cd tools/sd_cwt
python3 -m venv .venv && . .venv/bin/activate
pip install -e .[test]
pytest -q
```

## API
```python
issue(claims, redact, signer, *, sd_alg=SHA256, pad_to=None) -> (token, [Disclosure])
present(token, selected) -> token
verify(token, pubkey)    -> VerifiedToken
validate(token, pubkey)  -> ValidatedClaims  # .clear, .disclosed
```

`sd_cwt` is domain-agnostic (arbitrary CBOR claims); the report/note schema and
`parent_report` rules live in the application layer on top.
