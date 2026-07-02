# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Round-trip tests for the flat (top-level) map redaction path:
issue -> present -> verify -> validate.
"""

import pytest
from pycose.keys import EC2Key
from pycose.keys.curves import P256

import sd_cwt


@pytest.fixture
def signer() -> EC2Key:
    """A fresh EC P-256 key pair used as the issuer signing key."""
    return EC2Key.generate_key(crv=P256)


def test_issue_present_validate_full_roundtrip(signer):
    claims = {1: "https://issuer.example", 500: "heap overflow in parser", 501: "RCE"}

    token, discs = sd_cwt.issue(claims, redact={500, 501}, signer=signer)
    presented = sd_cwt.present(token, discs)  # disclose everything
    out = sd_cwt.validate(presented, signer)

    assert out.clear[1] == "https://issuer.example"
    assert out.disclosed[500] == "heap overflow in parser"
    assert out.disclosed[501] == "RCE"


def test_partial_disclosure_reveals_only_selected(signer):
    claims = {1: "iss", 500: "secret detail", 501: "RCE"}

    token, discs = sd_cwt.issue(claims, redact={500, 501}, signer=signer)
    only_501 = [d for d in discs if d.key == 501]
    presented = sd_cwt.present(token, only_501)
    out = sd_cwt.validate(presented, signer)

    assert out.disclosed.get(501) == "RCE"
    assert 500 not in out.disclosed  # undisclosed -> stays hidden


def test_redacted_token_hides_values_before_disclosure(signer):
    claims = {1: "iss", 501: "RCE"}

    token, _ = sd_cwt.issue(claims, redact={501}, signer=signer)
    v = sd_cwt.verify(token, signer)  # signature ok, but payload is redacted

    # The secret value must not appear in the signed (redacted) payload bytes.
    assert b"RCE" not in token


def test_decoy_padding_keeps_token_verifiable(signer):
    # Decoy count is asserted precisely in test_features; here just confirm a
    # padded token still verifies and discloses correctly.
    claims = {1: "iss", 501: "RCE"}

    token, discs = sd_cwt.issue(claims, redact={501}, signer=signer, pad_to=8)
    presented = sd_cwt.present(token, discs)
    out = sd_cwt.validate(presented, signer)

    assert out.disclosed[501] == "RCE"


def test_match_disclosures_matches_validate_on_trusted_payload(signer):
    """match_disclosures() (no signature check) matches validate()'s result."""
    import cbor2

    claims = {1: "iss", 500: "detail", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={500, 501}, signer=signer)
    presented = sd_cwt.present(token, discs)

    # Trusted path: verify once to obtain the payload, then match directly.
    v = sd_cwt.verify(presented, signer)
    uhdr = list(cbor2.loads(presented).value)[1]
    disclosures = uhdr[17]  # sd_claims

    direct = sd_cwt.match_disclosures(v.payload, disclosures, sd_alg=v.sd_alg)
    full = sd_cwt.validate(presented, signer)

    assert direct.clear == full.clear
    assert direct.disclosed == full.disclosed
    assert direct.disclosed[500] == "detail"
    assert direct.disclosed[501] == "RCE"


def test_match_disclosures_rejects_unmatched_disclosure(signer):
    """A disclosure with no matching Redacted Claim Hash is rejected."""
    import cbor2

    token, discs = sd_cwt.issue({1: "iss", 501: "RCE"}, redact={501}, signer=signer)
    presented = sd_cwt.present(token, discs)
    v = sd_cwt.verify(presented, signer)

    # A well-formed but foreign disclosure that matches nothing in the payload.
    foreign = cbor2.dumps([b"\x00" * 16, "bogus", 999])
    with pytest.raises(ValueError):
        sd_cwt.match_disclosures(v.payload, [foreign], sd_alg=v.sd_alg)


def test_validate_trusted_matches_validate(signer):
    """validate_trusted() (no signature check, no key) matches validate()."""
    claims = {1: "iss", 500: "detail", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={500, 501}, signer=signer)
    presented = sd_cwt.present(token, discs)

    trusted = sd_cwt.validate_trusted(presented)  # note: no key passed
    full = sd_cwt.validate(presented, signer)

    assert trusted.clear == full.clear
    assert trusted.disclosed == full.disclosed
    assert trusted.disclosed[500] == "detail"


def test_validate_trusted_rejects_foreign_disclosure(signer):
    """A presented disclosure matching no Redacted Claim Hash is still rejected."""
    import cbor2

    token, discs = sd_cwt.issue({1: "iss", 501: "RCE"}, redact={501}, signer=signer)
    presented = sd_cwt.present(token, discs)
    arr = list(cbor2.loads(presented).value)
    arr[1] = {17: [cbor2.dumps([b"\x00" * 16, "bogus", 999])]}  # swap disclosures
    forged = cbor2.dumps(cbor2.CBORTag(18, arr))
    with pytest.raises(ValueError):
        sd_cwt.validate_trusted(forged)


def test_validate_trusted_still_enforces_encoding_musts():
    """Encoding MUSTs (e.g. finite dates) fire even without a signature check."""
    import cbor2

    protected = cbor2.dumps({1: -7, 170: -16})
    payload = cbor2.dumps({1: "iss", 6: float("nan")})  # NaN iat (draft-08 s5.2)
    forged = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, b""]))
    with pytest.raises(ValueError):
        sd_cwt.validate_trusted(forged)
