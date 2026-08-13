# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Fixed-size splitting of free text into individually redactable chunks."""

from __future__ import annotations

import unicodedata

CHUNK_CHARS = 30


def normalise(text: str) -> str:
    """NFC-normalise `text` and convert every line ending to a bare newline.

    Both sides must agree byte-for-byte on the document before it is chunked,
    so normalisation happens once here rather than at each comparison site.
    """
    return unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))


def chunk(text: str, size: int = CHUNK_CHARS) -> list[str]:
    """Split already-normalised `text` into `size`-codepoint chunks.

    The final chunk may be shorter. `"".join(chunk(t)) == t`, so disclosing
    every chunk reproduces the document exactly.

    Slicing a `str` cuts on codepoints, so no chunk can hold a partial UTF-8
    sequence and each one is a valid CBOR text string. A combining mark can
    still fall into the next chunk, which only affects how a boundary renders.
    """
    if size < 1:
        raise ValueError("chunk size must be positive")
    return [text[i : i + size] for i in range(0, len(text), size)]
