# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for array-element redaction (CBOR tag 60)."""

import cbor2
import pytest
from cbor2 import CBORTag
from pycose.keys import EC2Key
from pycose.keys.curves import P256

import sd_cwt
from sd_cwt.core import REDACTED_ELEMENT_TAG


@pytest.fixture
def signer() -> EC2Key:
    return EC2Key.generate_key(crv=P256)


def test_array_full_disclosure_roundtrip(signer):
    claims = {1: "iss", 502: ["2019", "2021", "2023"]}
    token, discs = sd_cwt.issue(
        claims, redact=set(), signer=signer, redact_elements={502: {0, 1}}
    )
    # Array-element disclosures have no claim key.
    assert sum(1 for d in discs if d.key is None) == 2

    presented = sd_cwt.present(token, discs)
    out = sd_cwt.validate(presented, signer)
    assert out.clear[502] == ["2019", "2021", "2023"]


def test_array_partial_disclosure_omits_undisclosed(signer):
    claims = {502: ["a", "b", "c"]}
    token, discs = sd_cwt.issue(
        claims, redact=set(), signer=signer, redact_elements={502: {0, 2}}
    )
    only_a = [d for d in discs if d.value == "a"]
    presented = sd_cwt.present(token, only_a)
    out = sd_cwt.validate(presented, signer)
    # "b" was never redacted (clear); "a" disclosed; "c" redacted+undisclosed -> omitted.
    assert out.clear[502] == ["a", "b"]


def test_redacted_array_hides_values_and_uses_tag60(signer):
    claims = {502: ["secret0", "keep1"]}
    token, _ = sd_cwt.issue(
        claims, redact=set(), signer=signer, redact_elements={502: {0}}
    )
    assert b"secret0" not in token

    arr = sd_cwt.verify(token, signer).payload[502]
    assert isinstance(arr[0], CBORTag) and arr[0].tag == REDACTED_ELEMENT_TAG
    assert arr[1] == "keep1"


def test_tampered_array_disclosure_rejected(signer):
    claims = {502: ["x", "y"]}
    token, discs = sd_cwt.issue(
        claims, redact=set(), signer=signer, redact_elements={502: {0}}
    )
    d = discs[0]
    forged = sd_cwt.Disclosure(
        salt=d.salt, value="forged", key=None, encoded=cbor2.dumps([d.salt, "forged"])
    )
    presented = sd_cwt.present(token, [forged])
    with pytest.raises(ValueError):
        sd_cwt.validate(presented, signer)


def test_mixed_map_and_array_redaction(signer):
    claims = {1: "iss", 500: "secret-map", 502: ["e0", "e1"]}
    token, discs = sd_cwt.issue(
        claims, redact={500}, signer=signer, redact_elements={502: {1}}
    )
    presented = sd_cwt.present(token, discs)
    out = sd_cwt.validate(presented, signer)
    assert out.clear[1] == "iss"
    assert out.disclosed[500] == "secret-map"
    assert out.clear[502] == ["e0", "e1"]
