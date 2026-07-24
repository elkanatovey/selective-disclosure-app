# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for nested / recursive redaction via `redact_paths`."""

import pytest
from pycose.keys import EC2Key
from pycose.keys.curves import P256

import sd_cwt


@pytest.fixture
def signer() -> EC2Key:
    return EC2Key.generate_key(crv=P256)


def test_nested_map_partial_disclosure(signer):
    claims = {
        1: "iss",
        503: {"country": "us", "region": "California", "postal": "94188xyz"},
    }
    token, discs = sd_cwt.issue(
        claims,
        redact=set(),
        signer=signer,
        redact_paths=[(503, "region"), (503, "postal")],
    )

    # Hidden values absent from the signed token; country stays clear.
    assert b"California" not in token
    assert b"94188xyz" not in token
    assert sd_cwt.verify(token, signer).payload[503]["country"] == "us"

    # Disclose only region.
    region = [d for d in discs if d.value == "California"]
    out = sd_cwt.validate(sd_cwt.present(token, region), signer)
    assert out.clear[503]["country"] == "us"
    assert out.clear[503]["region"] == "California"
    assert "postal" not in out.clear[503]


def test_deeply_nested_map_and_array_path(signer):
    claims = {700: {"a": {"b": ["x", "secretY", "z"]}}}
    token, discs = sd_cwt.issue(
        claims,
        redact=set(),
        signer=signer,
        redact_paths=[(700, "a", "b", 1)],  # redact the element "secretY"
    )
    assert b"secretY" not in token

    # Undisclosed -> element omitted.
    out0 = sd_cwt.validate(token, signer)
    assert out0.clear[700]["a"]["b"] == ["x", "z"]

    # Disclosed -> element restored in place.
    out1 = sd_cwt.validate(sd_cwt.present(token, discs), signer)
    assert out1.clear[700]["a"]["b"] == ["x", "secretY", "z"]


def test_ancestor_disclosure_rule(signer):
    # Redact a whole sub-map AND a key inside it. Disclosing the child without
    # its parent must fail; disclosing parent reveals a still-redacted sub-map,
    # and adding the child disclosure resolves it.
    claims = {800: {"inner": "innerSecret", "kept": "keptVal"}}
    token, discs = sd_cwt.issue(
        claims,
        redact={800},
        signer=signer,
        redact_paths=[(800, "inner")],
    )

    parent = [d for d in discs if d.key == 800]
    child = [d for d in discs if d.value == "innerSecret"]

    # Child alone (no parent) is not resolvable -> rejected.
    with pytest.raises(ValueError):
        sd_cwt.validate(sd_cwt.present(token, child), signer)

    # Parent alone: sub-map revealed, "kept" visible, "inner" still redacted/omitted.
    out_parent = sd_cwt.validate(sd_cwt.present(token, parent), signer)
    assert out_parent.disclosed[800]["kept"] == "keptVal"
    assert "inner" not in out_parent.disclosed[800]

    # Parent + child: fully resolved.
    out_both = sd_cwt.validate(sd_cwt.present(token, parent + child), signer)
    assert out_both.disclosed[800]["inner"] == "innerSecret"
    assert out_both.disclosed[800]["kept"] == "keptVal"


def test_redact_paths_equivalent_to_top_level_shortcuts(signer):
    claims = {1: "iss", 500: "secret", 502: ["e0", "e1"]}
    token, discs = sd_cwt.issue(
        claims,
        redact=set(),
        signer=signer,
        redact_paths=[(500,), (502, 1)],
    )
    out = sd_cwt.validate(sd_cwt.present(token, discs), signer)
    assert out.clear[1] == "iss"
    assert out.disclosed[500] == "secret"
    assert out.clear[502] == ["e0", "e1"]


@pytest.mark.parametrize(
    "redaction",
    [
        {"redact": {999}},
        {"redact": set(), "redact_elements": {502: {2}}},
        {"redact": set(), "redact_paths": [()]},
        {"redact": set(), "redact_paths": [(700, "missing")]},
        {"redact": set(), "redact_paths": [(700, "items", -1)]},
        {"redact": set(), "redact_paths": [(700, "items", "0")]},
        {"redact": set(), "redact_paths": [(700, "scalar", "child")]},
    ],
)
def test_issue_rejects_unresolved_redaction_paths(signer, redaction):
    claims = {502: ["a", "b"], 700: {"items": ["x"], "scalar": "value"}}

    with pytest.raises(ValueError):
        sd_cwt.issue(claims, signer=signer, **redaction)
