# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Negative tests: verification must reject tampered or malformed tokens."""

import cbor2
import pytest
from cbor2 import CBORTag
from pycose.keys import EC2Key
from pycose.keys.curves import P256

import sd_cwt


@pytest.fixture
def signer() -> EC2Key:
    return EC2Key.generate_key(crv=P256)


def _retag(token: bytes, arr: list) -> bytes:
    """Re-encode a COSE_Sign1 array without re-signing."""
    return cbor2.dumps(CBORTag(18, arr))


def test_tampered_payload_rejected(signer):
    token, _ = sd_cwt.issue({1: "iss", 9: "honest"}, set(), signer)
    arr = list(cbor2.loads(token).value)
    arr[2] = cbor2.dumps({1: "iss", 9: "forged"})  # swap the signed payload
    forged = _retag(token, arr)
    with pytest.raises(Exception):
        sd_cwt.verify(forged, signer)


def test_tampered_protected_header_rejected(signer):
    token, _ = sd_cwt.issue({1: "iss"}, set(), signer)
    arr = list(cbor2.loads(token).value)
    protected = cbor2.loads(arr[0])
    protected[99] = "injected"  # mutate the signed protected header
    arr[0] = cbor2.dumps(protected)
    forged = _retag(token, arr)
    with pytest.raises(Exception):
        sd_cwt.verify(forged, signer)


def test_zeroed_signature_rejected(signer):
    token, _ = sd_cwt.issue({1: "iss"}, set(), signer)
    arr = list(cbor2.loads(token).value)
    arr[3] = bytes(len(arr[3]))  # all-zero signature of the right length
    forged = _retag(token, arr)
    with pytest.raises(Exception):
        sd_cwt.verify(forged, signer)


def test_garbage_bytes_rejected(signer):
    with pytest.raises(Exception):
        sd_cwt.verify(b"\xde\xad\xbe\xef not a cose token", signer)


def test_truncated_token_rejected(signer):
    token, _ = sd_cwt.issue({1: "iss"}, set(), signer)
    with pytest.raises(Exception):
        sd_cwt.verify(token[: len(token) // 2], signer)


def test_validate_rejects_tampered_payload(signer):
    token, discs = sd_cwt.issue({1: "iss", 501: "RCE"}, {501}, signer)
    presented = sd_cwt.present(token, discs)
    arr = list(cbor2.loads(presented).value)
    payload = cbor2.loads(arr[2])
    payload[1] = "forged"  # tamper a clear claim
    arr[2] = cbor2.dumps(payload)
    forged = _retag(presented, arr)
    with pytest.raises(Exception):
        sd_cwt.validate(forged, signer)


# --- Duplicate disclosed claim key rejection (draft-08 s9 step 8) ----------

import hashlib  # noqa: E402
import secrets  # noqa: E402

from cbor2 import CBORSimpleValue  # noqa: E402
from pycose.algorithms import Es256  # noqa: E402
from pycose.headers import Algorithm  # noqa: E402
from pycose.messages import Sign1Message  # noqa: E402

REDACTED_KEYS = CBORSimpleValue(59)


def _sign(signer, payload: dict, uhdr: dict) -> bytes:
    """Sign a crafted payload with a chosen (unsigned) unprotected header.

    Lets a test forge the attacker-controlled disclosures in `sd_claims` (17)
    while keeping a valid Issuer signature over the payload.
    """
    msg = Sign1Message(
        phdr={Algorithm: Es256, 16: 293, 170: -16},
        uhdr=uhdr,
        payload=cbor2.dumps(payload),
    )
    msg.key = signer
    return msg.encode()


def _map_disclosure(value, key):
    """Return (encoded bstr, digest) for a [salt, value, key] disclosure.

    The Redacted Claim Hash is over the `bstr-encoded-salted` form (the CBOR
    byte string wrapping the array), matching the library and the reference
    example tokens.
    """
    encoded = cbor2.dumps([secrets.token_bytes(16), value, key])
    return encoded, hashlib.sha256(cbor2.dumps(encoded)).digest()


def test_validate_rejects_disclosed_key_dup_of_clear_key(signer):
    """A disclosure revealing key 1 where 1 already exists in the clear is invalid."""
    disc, dig = _map_disclosure("forged", 1)  # key 1 collides with clear iss
    payload = {1: "iss", REDACTED_KEYS: [dig]}
    token = _sign(signer, payload, {17: [disc]})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_rejects_two_disclosures_same_key(signer):
    """Two disclosures at the same level revealing the same key 500 is invalid."""
    disc1, dig1 = _map_disclosure("a", 500)
    disc2, dig2 = _map_disclosure("b", 500)  # same key, different salt/value
    payload = {1: "iss", REDACTED_KEYS: [dig1, dig2]}
    token = _sign(signer, payload, {17: [disc1, disc2]})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_allows_same_key_at_different_levels(signer):
    """A disclosed key equal to a clear key at another level is NOT a duplicate."""
    disc, dig = _map_disclosure("us", 1)  # key 1 nested inside 503
    payload = {1: "iss", 503: {REDACTED_KEYS: [dig]}}
    token = _sign(signer, payload, {17: [disc]})
    out = sd_cwt.validate(token, signer)
    assert out.clear[1] == "iss"
    assert out.clear[503][1] == "us"


# --- Map-key type / length limits (draft-08 s5.3) --------------------------


def test_validate_rejects_bytestring_map_key(signer):
    """A byte-string map key is not a legal SD-CWT claim key."""
    payload = {1: "iss", b"\x00\x01": "x"}
    token = _sign(signer, payload, {})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_rejects_oversized_text_map_key(signer):
    """A text map key longer than 255 octets is rejected."""
    payload = {1: "iss", "k" * 256: "x"}
    token = _sign(signer, payload, {})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_rejects_float_map_key(signer):
    """A floating-point map key is not a legal SD-CWT claim key."""
    payload = {1: "iss", 1.5: "x"}
    token = _sign(signer, payload, {})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_allows_255_octet_text_map_key(signer):
    """A text map key of exactly 255 octets is allowed."""
    key = "k" * 255
    payload = {1: "iss", key: "x"}
    token = _sign(signer, payload, {})
    out = sd_cwt.validate(token, signer)
    assert out.clear[key] == "x"


# --- Finite date-claim encodings (draft-08 s5.2) ---------------------------


def test_validate_rejects_nan_iat(signer):
    """iat encoded as NaN is rejected."""
    payload = {1: "iss", 6: float("nan")}
    token = _sign(signer, payload, {})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_rejects_infinite_exp(signer):
    """exp encoded as +Infinity is rejected."""
    payload = {1: "iss", 4: float("inf")}
    token = _sign(signer, payload, {})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_rejects_oversized_float_nbf(signer):
    """nbf encoded as a float beyond 2^53 is rejected."""
    payload = {1: "iss", 5: 1e19}
    token = _sign(signer, payload, {})
    with pytest.raises(ValueError):
        sd_cwt.validate(token, signer)


def test_validate_allows_integer_iat(signer):
    """An ordinary integer iat passes the encoding check."""
    payload = {1: "iss", 6: 1725244200}
    token = _sign(signer, payload, {})
    out = sd_cwt.validate(token, signer)
    assert out.clear[6] == 1725244200
