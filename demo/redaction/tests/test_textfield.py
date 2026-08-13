# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Issue / reveal / verify over a chunk-redacted free-text field."""

import cbor2
import pytest
from cbor2 import CBORSimpleValue, CBORTag
from sd_cwt.core import REDACTED_CLAIM_KEYS, SD_CLAIMS_LABEL

from demo.redaction.textfield import BODY, issue_text, new_key, reveal, verify_text

TEXT = "The quick brown fox jumps over the lazy dog. " * 20
IAT = 1_700_000_000


@pytest.fixture(scope="module")
def key():
    return new_key()


@pytest.fixture(scope="module")
def issued(key):
    return issue_text(TEXT, key, iat=IAT)


def _arr(token):
    return list(cbor2.loads(token).value)


def _with_disclosures(token, discs):
    tag = cbor2.loads(token)
    arr = list(tag.value)
    uhdr = dict(arr[1] or {})
    uhdr[SD_CLAIMS_LABEL] = discs
    arr[1] = uhdr
    return cbor2.dumps(CBORTag(tag.tag, arr))


def test_signed_payload_shows_one_hash_for_the_whole_field(issued):
    payload = cbor2.loads(_arr(issued.token)[2])
    assert BODY not in payload
    assert len(payload[CBORSimpleValue(REDACTED_CLAIM_KEYS)]) == 1


def test_issue_attaches_no_disclosures(issued):
    assert SD_CLAIMS_LABEL not in (_arr(issued.token)[1] or {})


def test_revealing_never_touches_the_signed_bytes(issued):
    before, after = _arr(issued.token), _arr(reveal(issued, [0, 1, 5]))
    assert before[0] == after[0]  # protected header
    assert before[2] == after[2]  # payload
    assert before[3] == after[3]  # signature


def test_verify_returns_exactly_the_revealed_chunks(issued, key):
    out = verify_text(reveal(issued, [0, 3, 7]), key)
    assert out.valid and out.field_revealed
    assert sorted(out.revealed) == [0, 3, 7]
    assert out.chunk_count == issued.chunk_count


def test_full_disclosure_reconstructs_the_document(issued, key):
    out = verify_text(reveal(issued, range(issued.chunk_count)), key)
    assert "".join(out.spans()) == issued.text


def test_withheld_chunk_leaves_a_hole_at_its_index(issued, key):
    hidden = 4
    keep = [i for i in range(issued.chunk_count) if i != hidden]
    out = verify_text(reveal(issued, keep), key)
    assert out.withheld == [hidden]
    assert out.spans()[hidden] is None
    assert out.spans()[hidden - 1] == issued.chunks[hidden - 1]


def test_field_alone_shows_the_count_but_no_text(issued, key):
    out = verify_text(reveal(issued, []), key)
    assert out.valid and out.field_revealed
    assert out.revealed == {}
    assert out.chunk_count == issued.chunk_count


def test_withholding_the_field_reveals_nothing(issued, key):
    out = verify_text(reveal(issued, [], include_field=False), key)
    assert out.valid
    assert not out.field_revealed
    assert out.chunk_count == 0


def test_tampered_disclosure_is_rejected(issued, key):
    discs = list(_arr(reveal(issued, [0, 1, 2]))[1][SD_CLAIMS_LABEL])
    salt, value, claim = cbor2.loads(discs[-1])
    discs[-1] = cbor2.dumps([salt, value + "!", claim])
    out = verify_text(_with_disclosures(issued.token, discs), key)
    assert out.signature_ok
    assert not out.disclosures_ok


def test_foreign_disclosure_is_rejected(issued, key):
    other = issue_text("a completely different document body", key, iat=IAT)
    discs = list(_arr(reveal(issued, [0]))[1][SD_CLAIMS_LABEL])
    discs.append(other.chunk_disclosures[0].encoded)
    out = verify_text(_with_disclosures(issued.token, discs), key)
    assert not out.disclosures_ok


def test_bad_signature_is_rejected(issued):
    out = verify_text(issued.token, new_key())
    assert not out.signature_ok and not out.valid


def test_unknown_chunk_index_is_rejected(issued):
    with pytest.raises(ValueError):
        reveal(issued, [issued.chunk_count])


def test_empty_text_is_rejected(key):
    with pytest.raises(ValueError):
        issue_text("", key)


def test_unredacted_field_variant(key):
    issued = issue_text(TEXT, key, redact_field=False, iat=IAT)
    assert issued.field_disclosure is None
    out = verify_text(reveal(issued, [1, 2]), key)
    assert out.valid and out.field_revealed
    assert sorted(out.revealed) == [1, 2]
    assert out.chunk_count == issued.chunk_count


def test_120k_character_document(key):
    issued = issue_text("x" * 120_000, key, iat=IAT)
    assert issued.chunk_count == 4000
    out = verify_text(reveal(issued, range(0, 4000, 2)), key)
    assert out.valid
    assert out.chunk_count == 4000
    assert len(out.revealed) == 2000
