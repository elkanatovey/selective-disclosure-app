"""Feature tests for sd_cwt: hash-alg agility, decoys, tamper rejection,
and COSE-compatibility (a plain COSE verifier can check the signature)."""

import cbor2
import pytest
from cbor2 import CBORSimpleValue
from pycose.keys import EC2Key
from pycose.keys.curves import P256
from pycose.messages import CoseMessage

import sd_cwt
from sd_cwt.core import REDACTED_CLAIM_KEYS


@pytest.fixture
def signer() -> EC2Key:
    return EC2Key.generate_key(crv=P256)


def test_standard_cose_verifier_accepts_signature(signer):
    # A plain pycose verifier (no SD-CWT awareness) verifies the signature.
    token, _ = sd_cwt.issue({1: "iss", 501: "RCE"}, {501}, signer)
    msg = CoseMessage.decode(token)
    msg.key = signer
    assert msg.verify_signature() is True


def test_hash_alg_agility_sha384(signer):
    token, discs = sd_cwt.issue(
        {1: "iss", 501: "RCE"}, {501}, signer, sd_alg=sd_cwt.HashAlg.SHA_384
    )
    assert sd_cwt.verify(token, signer).sd_alg == sd_cwt.HashAlg.SHA_384
    presented = sd_cwt.present(token, discs)
    assert sd_cwt.validate(presented, signer).disclosed[501] == "RCE"


def test_decoy_padding_fixes_slot_count(signer):
    token, _ = sd_cwt.issue({1: "iss", 501: "RCE"}, {501}, signer, pad_to=8)
    v = sd_cwt.verify(token, signer)
    assert len(v.payload[CBORSimpleValue(REDACTED_CLAIM_KEYS)]) == 8


def test_wrong_key_fails_verify(signer):
    token, _ = sd_cwt.issue({1: "iss"}, set(), signer)
    other = EC2Key.generate_key(crv=P256)
    with pytest.raises(Exception):
        sd_cwt.verify(token, other)


def test_tampered_disclosure_rejected(signer):
    token, discs = sd_cwt.issue({1: "iss", 501: "RCE"}, {501}, signer)
    d = discs[0]
    forged = sd_cwt.Disclosure(
        salt=d.salt, value="XSS", key=501, encoded=cbor2.dumps([d.salt, "XSS", 501])
    )
    presented = sd_cwt.present(token, [forged])
    with pytest.raises(ValueError):
        sd_cwt.validate(presented, signer)


def test_no_disclosures_yields_only_clear(signer):
    token, _ = sd_cwt.issue({1: "iss", 501: "RCE"}, {501}, signer)
    out = sd_cwt.validate(token, signer)  # nothing presented
    assert out.clear[1] == "iss"
    assert out.disclosed == {}
