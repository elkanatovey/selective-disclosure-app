# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Loading, restricting and verifying a real transparent statement."""

import cbor2
import pytest
from sd_cwt import statement as st

from demo.redaction.statement_tool import (
    SD_CLAIMS_LABEL,
    bare_statement,
    load,
    restrict,
    sample_statement,
    st_body_text,
    verify,
)

TEXT = "finding: the parser overflows on a long thumbnail header.\n" * 4


@pytest.fixture(scope="module")
def token():
    return sample_statement(TEXT, title="heap overflow", severity="high")


def _sd_claims(tok):
    return (list(cbor2.loads(tok).value)[1] or {}).get(SD_CLAIMS_LABEL, [])


def test_load_reassembles_the_body(token):
    out = load(token)
    assert out.total == -(-len(TEXT) // st.BODY_CHUNK_CHARS)
    assert out.text == TEXT
    assert out.fields["title"] == "heap overflow"
    assert not out.has_receipt


def test_restrict_keeps_only_the_named_chunks(token):
    kept = load(restrict(token, [0, 1, 5])).chunks
    assert sorted(kept) == [0, 1, 5]
    assert st_body_text(kept) == TEXT[:12] + TEXT[30:36]


def test_restrict_leaves_the_signed_bytes_untouched(token):
    before, after = list(cbor2.loads(token).value), list(
        cbor2.loads(restrict(token, [0])).value
    )
    assert before[0] == after[0]  # protected header
    assert before[2] == after[2]  # payload
    assert before[3] == after[3]  # signature


def test_restrict_preserves_the_claims_digest(token):
    # The receipt is bound to these bytes, so it must survive any restriction.
    assert bare_statement(restrict(token, [2])) == bare_statement(token)


def test_restrict_keeps_non_chunk_openings(token):
    stripped = restrict(token, [])
    out = load(stripped)
    assert out.chunks == {}
    assert out.fields["title"] == "heap overflow"  # other fields still disclosed


def test_restricting_everything_still_validates(token):
    # body's own opening stays attached, so the committed count survives even
    # when no chunk is revealed.
    out = load(restrict(token, []))
    assert out.revealed == 0
    assert out.total == load(token).total


def test_verify_reports_a_missing_receipt_without_failing(token):
    out = verify(token, None)
    assert out.valid
    assert out.disclosures_ok
    assert not out.has_receipt
    assert out.chunk_count == load(token).total


def test_verify_rejects_a_tampered_chunk(token):
    claims = list(_sd_claims(token))
    for i, enc in enumerate(claims):
        d = cbor2.loads(enc)
        if len(d) == 3 and isinstance(d[1], str) and d[2] == 0:
            claims[i] = cbor2.dumps([d[0], d[1] + "!", d[2]])
            break
    tag = cbor2.loads(token)
    arr = list(tag.value)
    arr[1] = {**dict(arr[1]), SD_CLAIMS_LABEL: claims}
    tampered = cbor2.dumps(cbor2.CBORTag(tag.tag, arr))

    out = verify(tampered, None)
    assert not out.disclosures_ok and not out.valid


def test_chunk_index_colliding_with_a_field_key_is_not_dropped():
    # Chunk index 1001 shares its key with `title`; openings are told apart by
    # digest, not by key, so restricting must not disturb the title.
    long_text = "x" * (1100 * st.BODY_CHUNK_CHARS)
    tok = sample_statement(long_text, title="keep me")
    out = load(restrict(tok, [1001]))
    assert out.chunks == {1001: "xxxxxx"}
    assert out.fields["title"] == "keep me"


def test_withholding_a_field_removes_it_and_its_bytes(token):
    red = restrict(token, [0], keep_fields={"title"})
    out = load(red)
    assert out.fields["title"] == "heap overflow"
    assert "severity" not in out.fields
    assert b"high" not in red


def test_body_container_is_kept_whenever_a_chunk_is(token):
    # `body` is deliberately absent from keep_fields.
    out = load(restrict(token, [0, 1], keep_fields={"title"}))
    assert out.total > 0
    assert sorted(out.chunks) == [0, 1]


def test_withholding_body_drops_its_chunks(token):
    out = load(restrict(token, range(50), keep_fields={"title"} - {"body"}))
    assert out.total > 0  # chunks requested, so the container is kept

    gone = load(restrict(token, [], keep_fields={"title"}))
    assert gone.total == 0
    assert gone.text == ""


def test_withholding_a_container_drops_its_nested_openings():
    tok = sample_statement("some body text here", references=["CVE-1", "CVE-2"])
    red = restrict(tok, [0], keep_fields={"title"})
    assert load(red) is not None  # nested element openings would fail validation
    assert b"CVE-1" not in red
