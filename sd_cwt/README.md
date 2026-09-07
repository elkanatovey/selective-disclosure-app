# Bundled SD-CWT reference

These runtime modules were originally imported from `tools/sd_cwt` at commit
`9cf54783f2cb505b6bfed88cd8657c1e03bcd3c4`. Keeping them in this package makes
the demo installable without fetching code from another branch or repository.
They are maintained here and included in the repository's lint and format checks.

The portable token conformance tests live in `tests/sd_cwt`. Live report-profile
coverage lives in `tests/test_report_profile.py` and `tests/js/report-profile.test.mjs`,
with shared disclosure fixtures in `tests/fixtures/report-profile.json`.

`match_disclosures` allows partial disclosure by default. Applications that
require a complete report can pass `require_all=True` to reject any reachable
commitment without an opening, including nested map claims and array elements.

Staged integrations can use `ParsedToken.decode` and `ParsedKBT.decode` for
structural decoding only. `verify` produces a `VerifiedToken` after checking
the issuer signature. `ParsedKBT.verify` consumes that result only when it
belongs to the exact embedded statement, then checks holder proof, audiences,
and disclosures. Parsed views are defensive snapshots, not authenticity claims.
The existing `verify`, `validate`, and `kbt_verify` convenience APIs remain available.

The web application's report profile is defined in `webapp/report.py` and
`webapp/static/report-profile.json`. Browser report construction lives in
`webapp/static/report-profile.js`; the token core has no report-specific constructors.
