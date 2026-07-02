# sd_cwt

A minimal, domain-agnostic **Selective Disclosure CBOR Web Token (SD-CWT)**
implementation (custom profile of
[draft-ietf-spice-sd-cwt-08](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/)),
wrapping [`pycose`](https://pypi.org/project/pycose/) + `cbor2` + `hashlib`.

It implements the subset of SD-CWT used by this project (see `docs/DESIGN.md` §13):
map + array-element redaction, **nested/recursive redaction** at arbitrary depth,
disclosures in the unprotected header, hash-alg agility via the `sd_alg` header,
decoy padding, CSPRNG randomness, and **Key Binding Tokens** (`kbt_sign` /
`kbt_verify`) with RFC 8747 `cnf` proof-of-possession. The Redacted Claim Hash is
taken over the `bstr`-encoded disclosure (per the CDDL / Appendix G), matching the
reference example tokens. Untrusted input is checked against the draft-08 encoding
MUSTs (definite-length, map-key type/length, duplicate keys, nesting depth, finite
date-claim encodings, non-empty `sd_claims`) and both the KBT and SD-CWT audiences.

**Out of scope by design:** temporal *validity* comparison (`exp`/`nbf`/`iat`
against a clock), AEAD-encrypted disclosures, and pre-issuance To-Be-Redacted /
To-Be-Decoy tags.

## Layout
- `src/sd_cwt/core.py` — `issue` / `present` / `verify` / `validate` /
  `validate_trusted` / `match_disclosures` / `kbt_sign` / `kbt_verify` + types.
- `tests/` — `pytest` round-trip, array, nesting, negative, feature,
  conformance, and interop-vector tests.

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
      sd_alg=SHA256, pad_to=None,
      cnf=None) -> (token, [Disclosure])          # cnf: holder pubkey, enables KBT
present(token, selected) -> token
verify(token, pubkey)    -> VerifiedToken
validate(token, pubkey)  -> ValidatedClaims       # verify signature, then hash-match
validate_trusted(token)  -> ValidatedClaims       # skip signature (trust from elsewhere)
match_disclosures(payload, presented, *, sd_alg=SHA256) -> ValidatedClaims

# Key Binding Token (holder proof-of-possession over the cnf key)
kbt_sign(token, selected, holder, *, aud, iat=None, cti=None, cnonce=None) -> kbt
kbt_verify(kbt, issuer_pub, *, expected_aud, expected_cnonce=None) -> KBTResult
```

Redaction targets are paths from the root: `redact` covers whole top-level map
entries, `redact_elements` covers top-level array indices, and `redact_paths`
covers arbitrary depth (mixing map keys and array indices). Disclosing a redacted
parent reveals a still-redacted child (ancestor-disclosure rule).

`sd_cwt` is domain-agnostic (arbitrary CBOR claims); the report/note schema and
`parent_report` rules live in the application layer on top.
