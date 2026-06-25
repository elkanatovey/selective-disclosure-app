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
