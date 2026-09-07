# Bundled SD-CWT reference

These runtime modules were originally imported from `tools/sd_cwt` at commit
`9cf54783f2cb505b6bfed88cd8657c1e03bcd3c4`. Keeping them in this package makes
the demo installable without fetching code from another branch or repository.
They are maintained here and included in the repository's lint and format checks.

The portable reference tests live in `tests/sd_cwt`. C++ conformance tests were
not imported because this demo does not contain the former C++ implementation.

`match_disclosures` allows partial disclosure by default. Applications that
require a complete report can pass `require_all=True` to reject any reachable
commitment without an opening, including nested map claims and array elements.
