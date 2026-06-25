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
