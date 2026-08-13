# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Chunking round-trip and boundary behaviour."""

import pytest

from demo.redaction.chunking import chunk, normalise

SAMPLE = "Héllo wörld.\r\nSecond line — with an em dash.\rThird.\n\U0001f600 emoji."


def test_join_reproduces_normalised_text():
    text = normalise(SAMPLE)
    assert "".join(chunk(text)) == text


def test_line_endings_normalised():
    assert "\r" not in normalise(SAMPLE)
    assert normalise("a\r\nb\rc") == "a\nb\nc"


def test_every_chunk_is_full_except_the_last():
    text = normalise(SAMPLE * 4)
    chunks = chunk(text, 30)
    assert all(len(c) == 30 for c in chunks[:-1])
    assert 0 < len(chunks[-1]) <= 30


def test_astral_codepoint_is_never_split():
    text = "\U0001f600" * 40  # each emoji is one codepoint, two UTF-16 units
    chunks = chunk(text, 30)
    assert [len(c) for c in chunks] == [30, 10]
    assert "".join(chunks) == text


def test_size_must_be_positive():
    with pytest.raises(ValueError):
        chunk("abc", 0)


def test_empty_text_yields_no_chunks():
    assert chunk("") == []
