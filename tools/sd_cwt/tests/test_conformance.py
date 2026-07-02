# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Conformance tests for draft-ietf-spice-sd-cwt-08 MUST requirements:
mandatory claims (cnf/iss/sub) and Key Binding Token presentation.
"""

import pytest
from pycose.keys import EC2Key
from pycose.keys.curves import P256

import sd_cwt


@pytest.fixture
def signer() -> EC2Key:
    """Issuer (assertion) key."""
    return EC2Key.generate_key(crv=P256)


@pytest.fixture
def holder() -> EC2Key:
    """Holder (confirmation) key — the party that signs the KBT."""
    return EC2Key.generate_key(crv=P256)


# --- Step 1: cnf embedding -------------------------------------------------


def test_cnf_embeds_holder_public_key(signer, holder):
    claims = {1: "https://issuer.example", 2: "https://holder.example", 500: "x"}
    token, _ = sd_cwt.issue(claims, redact={500}, signer=signer, cnf=holder)

    v = sd_cwt.verify(token, signer)
    assert 8 in v.payload  # cnf claim present (RFC 8747)
    cose_key = v.payload[8][1]  # cnf = {1: COSE_Key}
    assert cose_key[1] == 2  # kty: EC2
    assert cose_key[-2] == holder.x  # x coordinate
    assert cose_key[-3] == holder.y  # y coordinate
    assert -4 not in cose_key  # private scalar MUST NOT be present


def test_cnf_public_key_only_not_in_token_bytes(signer, holder):
    claims = {1: "iss", 2: "sub"}
    token, _ = sd_cwt.issue(claims, redact=set(), signer=signer, cnf=holder)
    assert holder.d not in token  # private key material never serialised


# --- Step 2: Key Binding Token round-trip ----------------------------------

AUD = "https://verifier.example/app"


def test_kbt_roundtrip_discloses_selected(signer, holder):
    claims = {1: "iss", 2: "sub", 500: "secret detail", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={500, 501}, signer=signer, cnf=holder)
    only_501 = [d for d in discs if d.key == 501]

    kbt = sd_cwt.kbt_sign(token, only_501, holder, aud=AUD, iat=1725244237)
    result = sd_cwt.kbt_verify(kbt, signer, expected_aud=AUD)

    assert result.aud == AUD
    assert result.claims.disclosed[501] == "RCE"
    assert 500 not in result.claims.disclosed


def test_kbt_rejects_wrong_holder_key(signer, holder):
    """A KBT signed by a key other than the cnf key MUST fail."""
    claims = {1: "iss", 2: "sub", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={501}, signer=signer, cnf=holder)

    attacker = EC2Key.generate_key(crv=P256)
    kbt = sd_cwt.kbt_sign(token, discs, attacker, aud=AUD, iat=1725244237)
    with pytest.raises(ValueError):
        sd_cwt.kbt_verify(kbt, signer, expected_aud=AUD)


def test_kbt_rejects_wrong_audience(signer, holder):
    claims = {1: "iss", 2: "sub", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={501}, signer=signer, cnf=holder)
    kbt = sd_cwt.kbt_sign(token, discs, holder, aud=AUD, iat=1725244237)
    with pytest.raises(ValueError):
        sd_cwt.kbt_verify(kbt, signer, expected_aud="https://evil.example")


def test_kbt_requires_iat_or_cti(signer, holder):
    claims = {1: "iss", 2: "sub", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={501}, signer=signer, cnf=holder)
    with pytest.raises(ValueError):
        sd_cwt.kbt_sign(token, discs, holder, aud=AUD)  # neither iat nor cti


def test_kbt_forbids_iss_sub(signer, holder):
    """draft-08 s8.1: iss/sub MUST NOT be present in the KBT payload."""
    claims = {1: "iss", 2: "sub", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={501}, signer=signer, cnf=holder)
    kbt = sd_cwt.kbt_sign(token, discs, holder, aud=AUD, iat=1725244237)

    import cbor2

    kbt_arr = cbor2.loads(kbt).value
    kbt_payload = cbor2.loads(kbt_arr[2])
    assert 1 not in kbt_payload  # no iss
    assert 2 not in kbt_payload  # no sub


def test_kbt_cnonce_roundtrip(signer, holder):
    claims = {1: "iss", 2: "sub", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={501}, signer=signer, cnf=holder)
    nonce = b"\x8c\x0f_R;\x95\xbe\xa4"
    kbt = sd_cwt.kbt_sign(token, discs, holder, aud=AUD, iat=1725244237, cnonce=nonce)

    result = sd_cwt.kbt_verify(kbt, signer, expected_aud=AUD, expected_cnonce=nonce)
    assert result.cnonce == nonce

    with pytest.raises(ValueError):
        sd_cwt.kbt_verify(kbt, signer, expected_aud=AUD, expected_cnonce=b"wrong")


# --- Step 3: robustness MUSTs ----------------------------------------------

import cbor2  # noqa: E402
from cbor2 import CBORTag  # noqa: E402
from pycose.algorithms import Es256  # noqa: E402
from pycose.headers import Algorithm  # noqa: E402
from pycose.messages import Sign1Message  # noqa: E402


def _sign_raw_payload(signer, payload_bytes: bytes) -> bytes:
    """Sign arbitrary (possibly hostile) payload bytes as an SD-CWT COSE_Sign1."""
    msg = Sign1Message(
        phdr={Algorithm: Es256, 16: 293, 170: -16}, uhdr={}, payload=payload_bytes
    )
    msg.key = signer
    return msg.encode()


def test_verify_rejects_indefinite_length_payload(signer):
    indef = bytes.fromhex("bf016169ff")  # indefinite-length map {1: "i"}
    token = _sign_raw_payload(signer, indef)
    with pytest.raises(ValueError):
        sd_cwt.verify(token, signer)


def test_verify_rejects_duplicate_map_keys(signer):
    dup = bytes.fromhex("a201616101616a")  # map(2){1:"a", 1:"j"}
    token = _sign_raw_payload(signer, dup)
    with pytest.raises(ValueError):
        sd_cwt.verify(token, signer)


def test_verify_rejects_excessive_nesting_depth(signer):
    payload = bytes([0x81] * 17) + bytes([0x00])  # 17 nested 1-element arrays
    token = _sign_raw_payload(signer, payload)
    with pytest.raises(ValueError):
        sd_cwt.verify(token, signer)


def test_validate_rejects_empty_sd_claims(signer, holder):
    claims = {1: "iss", 2: "sub", 501: "RCE"}
    token, _ = sd_cwt.issue(claims, redact={501}, signer=signer, cnf=holder)

    tag = cbor2.loads(token)
    arr = list(tag.value)
    uhdr = dict(arr[1]) if arr[1] else {}
    uhdr[17] = []  # present-but-empty sd_claims (draft-08 s9 step 2: invalid)
    arr[1] = uhdr
    bad = cbor2.dumps(CBORTag(tag.tag, arr))

    with pytest.raises(ValueError):
        sd_cwt.validate(bad, signer)


def test_conformant_token_still_validates(signer, holder):
    """The scanner must not reject well-formed definite-length tokens."""
    claims = {1: "iss", 2: "sub", 500: "a", 501: "RCE"}
    token, discs = sd_cwt.issue(claims, redact={500, 501}, signer=signer, cnf=holder)
    presented = sd_cwt.present(token, discs)
    out = sd_cwt.validate(presented, signer)
    assert out.disclosed[501] == "RCE"
