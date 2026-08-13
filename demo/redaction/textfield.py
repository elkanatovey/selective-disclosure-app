# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Carry a large free-text field in an SD-CWT as individually redactable chunks.

The field's value is a map of chunk index -> chunk text with every entry
redacted, so the signed token commits to one Redacted Claim Hash per chunk and
reveals none of them. Revealing text later only attaches those entries'
disclosures to a copy of the unprotected header; the payload and the signature
never change.

Chunks are map entries rather than array elements because undisclosed array
elements are dropped during validation and reindex the survivors (draft-08 s9
step 10), which would erase where each hole was.

By default the field itself is redacted too, so an undisclosed token shows a
single hash for the whole field, and the field must be disclosed before any
chunk can be (the ancestor-disclosure rule). That is the shape a report
statement needs, where every content field is present and redacted.

Scope: one text field per token. Issuance returns a flat disclosure list, and
the field is told apart from its chunks by having a map value rather than a
text one. Placing this beside the other report fields needs the per-disclosure
path that the C++ core records (`sdcwt::Disclosure::path`, DESIGN.md s8) and
the Python oracle does not yet carry.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any, Iterable, Optional

import cbor2
from cbor2 import CBORSimpleValue
from pycose.keys import EC2Key
from pycose.keys.curves import P256
from sd_cwt import Disclosure, issue, present, validate, verify
from sd_cwt.core import REDACTED_CLAIM_KEYS, SD_CLAIMS_LABEL

from .chunking import CHUNK_CHARS, chunk, normalise

ISS = 1
IAT = 6
BODY = 1002  # `body` in spec/statement.cddl

DEFAULT_ISS = "https://demo.example"

_REDACTED_KEY = CBORSimpleValue(REDACTED_CLAIM_KEYS)


def new_key() -> EC2Key:
    """Generate an ephemeral P-256 issuer key."""
    return EC2Key.generate_key(crv=P256)


@dataclass
class IssuedText:
    """A fully redacted token and the holder's disclosures for its text field."""

    token: bytes
    claim_key: int
    chunks: list[str]
    chunk_disclosures: dict[int, Disclosure] = dc_field(default_factory=dict)
    field_disclosure: Optional[Disclosure] = None

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)

    @property
    def text(self) -> str:
        return "".join(self.chunks)


def issue_text(
    text: str,
    signer: Any,
    *,
    claim_key: int = BODY,
    iss: str = DEFAULT_ISS,
    iat: Optional[int] = None,
    redact_field: bool = True,
    size: int = CHUNK_CHARS,
) -> IssuedText:
    """Chunk `text` and issue it as a fully redacted SD-CWT claim."""
    chunks = chunk(normalise(text), size)
    if not chunks:
        raise ValueError("text is empty")

    claims: dict[Any, Any] = {
        ISS: iss,
        IAT: int(time.time()) if iat is None else iat,
        claim_key: dict(enumerate(chunks)),
    }
    paths: list[tuple] = [(claim_key, i) for i in range(len(chunks))]
    if redact_field:
        paths.append((claim_key,))

    token, disclosures = issue(claims, paths, signer)

    by_index = {d.key: d for d in disclosures if isinstance(d.value, str)}
    if len(by_index) != len(chunks):
        raise RuntimeError("unexpected disclosure set for the text field")
    return IssuedText(
        token=token,
        claim_key=claim_key,
        chunks=chunks,
        chunk_disclosures=by_index,
        field_disclosure=next(
            (d for d in disclosures if isinstance(d.value, dict)), None
        ),
    )


def reveal(
    issued: IssuedText,
    indices: Iterable[int],
    *,
    include_field: bool = True,
) -> bytes:
    """Return a copy of `issued.token` disclosing only `indices`.

    The field's own disclosure is attached whenever it exists, so a presentation
    that reveals no chunk still shows how many chunks were withheld. Dropping it
    with `include_field=False` yields a token that discloses nothing at all.
    """
    wanted = set(indices)
    unknown = wanted - set(range(issued.chunk_count))
    if unknown:
        raise ValueError(f"no such chunk index: {sorted(unknown)[:5]}")

    selected = []
    if include_field and issued.field_disclosure is not None:
        selected.append(issued.field_disclosure)
    selected.extend(issued.chunk_disclosures[i] for i in sorted(wanted))
    return present(issued.token, selected)


@dataclass
class VerifiedText:
    """Outcome of checking a presented token against the issuer public key."""

    signature_ok: bool
    disclosures_ok: bool
    field_revealed: bool
    chunk_count: int
    revealed: dict[int, str] = dc_field(default_factory=dict)
    error: Optional[str] = None

    @property
    def valid(self) -> bool:
        return self.signature_ok and self.disclosures_ok

    @property
    def withheld(self) -> list[int]:
        return [i for i in range(self.chunk_count) if i not in self.revealed]

    def spans(self) -> list[Optional[str]]:
        """Chunk texts in order, with `None` wherever a chunk was withheld."""
        return [self.revealed.get(i) for i in range(self.chunk_count)]


def _chunk_count(token: bytes, payload: Any, claim_key: int) -> int:
    """Total committed chunks, from the payload or the field's own disclosure."""
    node = payload.get(claim_key) if isinstance(payload, dict) else None
    if isinstance(node, dict):
        return len(node.get(_REDACTED_KEY, []))

    uhdr = cbor2.loads(token).value[1] or {}
    for encoded in uhdr.get(SD_CLAIMS_LABEL, []):
        decoded = cbor2.loads(encoded)
        if len(decoded) == 3 and isinstance(decoded[1], dict):
            return len(decoded[1].get(_REDACTED_KEY, []))
    return 0


def verify_text(token: bytes, pubkey: Any, *, claim_key: int = BODY) -> VerifiedText:
    """Verify the signature, then hash-match the presented chunk disclosures."""
    try:
        verified = verify(token, pubkey)
    except Exception as exc:  # untrusted input: any decode/verify failure is a reject
        return VerifiedText(False, False, False, 0, error=str(exc))

    try:
        claims = validate(token, pubkey)
    except Exception as exc:
        return VerifiedText(True, False, False, 0, error=str(exc))

    node = claims.disclosed.get(claim_key, claims.clear.get(claim_key))
    if not isinstance(node, dict):
        return VerifiedText(True, True, False, 0)

    revealed = {
        k: v for k, v in node.items() if isinstance(k, int) and isinstance(v, str)
    }
    count = _chunk_count(token, verified.payload, claim_key)
    return VerifiedText(True, True, True, count, revealed)
