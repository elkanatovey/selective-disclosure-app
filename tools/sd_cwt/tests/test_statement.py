# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for the unified bug-report statement schema (sd_cwt.statement).

A `report` and a `note` are the SAME object shape; role is derived purely from
`parent`. Strict uniformity: every statement carries all content fields as
redacted entries (absent ones garbage-padded), so a bare redacted token leaks
nothing but `iss` + `iat` and a constant redacted-hash count.
"""

import pytest
from pycose.keys import EC2Key
from pycose.keys.curves import P256

import sd_cwt
from sd_cwt import statement as st


@pytest.fixture
def signer() -> EC2Key:
    return EC2Key.generate_key(crv=P256)


def _iss_iat():
    return {"iss": "https://ledger.example/tee", "iat": 1_700_000_000}


def test_strict_uniformity_minimal_vs_full_have_identical_shape(signer):
    # A one-field note and a fully-populated report must be indistinguishable
    # at the redacted-token level: same clear keys, same redacted-hash count.
    minimal, _ = st.issue_statement(signer, **_iss_iat(), fingerprint=b"abc")
    full, _ = st.issue_statement(
        signer,
        **_iss_iat(),
        parent=b"\x11" * 32,
        title="heap overflow",
        body="details ...",
        component="parser",
        severity="high",
        fingerprint=b"abc",
        references=["CVE-2025-0001", "https://x/y"],
        patch="fixed in 1.2.3",
        patch_date=1_700_100_000,
    )

    assert st.redacted_shape(minimal) == st.redacted_shape(full)
    clear_keys, n_redacted = st.redacted_shape(minimal)
    assert clear_keys == (st.ISS, st.IAT)
    assert n_redacted == len(st.CONTENT_FIELDS) == 9


def test_parent_always_present_even_for_root(signer):
    # A root (no parent) still carries a redacted parent slot.
    root, discs = st.issue_statement(signer, **_iss_iat(), body="x")
    _, n_redacted = st.redacted_shape(root)
    assert n_redacted == len(st.CONTENT_FIELDS)
    # parent has a disclosure (garbage sentinel) that the holder *could* reveal.
    assert any(d.key == st.PARENT for d in discs)


def test_report_roundtrip_reveals_only_selected(signer):
    token, discs = st.issue_statement(
        signer, **_iss_iat(), title="t", body="secret body", severity="high"
    )
    presented = sd_cwt.present(token, st.disclosures_for(discs, "severity"))
    out = st.validate_statement(presented, signer)

    assert out.disclosed[st.SEVERITY] == "high"
    assert st.BODY not in out.disclosed
    assert st.TITLE not in out.disclosed
    assert out.clear[st.ISS] == "https://ledger.example/tee"
    assert out.clear[st.IAT] == 1_700_000_000
    assert b"secret body" not in token  # never in the signed redacted payload


def test_report_vs_note_derived_from_parent(signer):
    parent_hash = b"\x22" * 32
    note, note_discs = st.issue_statement(signer, **_iss_iat(), parent=parent_hash)
    root, root_discs = st.issue_statement(signer, **_iss_iat(), body="orig")

    # Disclosing parent on the note yields the real referenced hash (=> note).
    note_p = sd_cwt.present(note, st.disclosures_for(note_discs, "parent"))
    assert st.validate_statement(note_p, signer).disclosed[st.PARENT] == parent_hash

    # The root's parent is a garbage sentinel, not any real statement hash.
    root_p = sd_cwt.present(root, st.disclosures_for(root_discs, "parent"))
    assert st.validate_statement(root_p, signer).disclosed[st.PARENT] != parent_hash


def test_references_array_roundtrips(signer):
    refs = ["CVE-2025-0001", "https://example/adv"]
    token, discs = st.issue_statement(signer, **_iss_iat(), references=refs)
    presented = sd_cwt.present(token, st.disclosures_for(discs, "references"))
    out = st.validate_statement(presented, signer)
    assert out.disclosed[st.REFERENCES] == refs


def test_fingerprint_duplicate_proof_reveals_nothing_else(signer):
    fp = b"\xde\xad\xbe\xef" * 4
    a, a_discs = st.issue_statement(signer, **_iss_iat(), fingerprint=fp, body="A")
    b, b_discs = st.issue_statement(signer, **_iss_iat(), fingerprint=fp, body="B")

    a_out = st.validate_statement(
        sd_cwt.present(a, st.disclosures_for(a_discs, "fingerprint")), signer
    )
    b_out = st.validate_statement(
        sd_cwt.present(b, st.disclosures_for(b_discs, "fingerprint")), signer
    )

    assert a_out.disclosed[st.FINGERPRINT] == b_out.disclosed[st.FINGERPRINT] == fp
    # nothing but fingerprint is exposed on either side
    assert set(a_out.disclosed) == {st.FINGERPRINT}
    assert set(b_out.disclosed) == {st.FINGERPRINT}


def test_input_type_validation(signer):
    with pytest.raises(TypeError):
        st.issue_statement(signer, iss=123, iat=1)  # iss must be str
    with pytest.raises(TypeError):
        st.issue_statement(signer, **_iss_iat(), severity=5)  # severity must be str
    with pytest.raises(TypeError):
        st.issue_statement(signer, **_iss_iat(), parent="not-bytes")  # parent bytes


def test_schema_validation_rejects_unexpected_clear_claim(signer):
    # Hand-craft a token with an out-of-schema clear claim -> validation rejects.
    claims = {st.ISS: "iss", st.IAT: 1, 999: "rogue"}
    token, _ = sd_cwt.issue(claims, redact=set(), signer=signer)
    with pytest.raises(ValueError):
        st.validate_statement(token, signer)
