# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Client-side redaction of a transparent statement.

Consumes exactly what ``GET /operator/statements/{txid}`` returns: the signed
statement with every opening attached and the CCF receipt embedded. Withholding
a chunk drops its opening from a copy of the unprotected header, so the payload
and signature are untouched and the receipt still verifies -- no re-issue, no
service round trip.

Trust is receipt-anchored: the embedded receipt proves the service committed
these bytes, so disclosures are hash-matched with ``validate_statement_trusted``
rather than by re-checking the issuer signature (DESIGN.md section 9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable, Optional

import cbor2
from sd_cwt import HashAlg
from sd_cwt import statement as st

# `_disclosure_digest` is imported rather than reimplemented so the two cannot
# drift; it is the only way to tell body's chunk openings from same-keyed
# content-field openings (chunk index 1001 collides with `title`).
from sd_cwt.core import _disclosure_digest

RECEIPTS_LABEL = 394
SD_CLAIMS_LABEL = 17
REDACTED_CLAIM_KEYS = cbor2.CBORSimpleValue(59)


def _arr(token: bytes) -> list:
    return list(cbor2.loads(token).value)


def _sd_claims(token: bytes) -> list:
    return (_arr(token)[1] or {}).get(SD_CLAIMS_LABEL, [])


def _with_sd_claims(token: bytes, claims: list) -> bytes:
    tag = cbor2.loads(token)
    arr = list(tag.value)
    uhdr = dict(arr[1] or {})
    if claims:
        uhdr[SD_CLAIMS_LABEL] = claims
    else:
        uhdr.pop(SD_CLAIMS_LABEL, None)  # draft-08 s8: omit when empty
    arr[1] = uhdr
    return cbor2.dumps(cbor2.CBORTag(tag.tag, arr))


def bare_statement(token: bytes) -> bytes:
    """The originally signed bytes: the statement with an empty unprotected
    header. This is what the CCF claims digest was bound over, so it is stable
    across any choice of disclosures."""
    tag = cbor2.loads(token)
    arr = list(tag.value)
    arr[1] = {}
    return cbor2.dumps(cbor2.CBORTag(tag.tag, arr))


def _chunk_digests(token: bytes) -> set:
    """Digests listed inside body's own opening -- exactly its chunk openings."""
    for enc in _sd_claims(token):
        d = cbor2.loads(enc)
        if len(d) == 3 and d[2] == st.BODY and isinstance(d[1], dict):
            return set(d[1].get(REDACTED_CLAIM_KEYS, []))
    return set()


@dataclass
class Loaded:
    """A transparent statement with its body split back into chunks."""

    token: bytes
    chunks: dict[int, str] = field(default_factory=dict)
    fields: dict[str, Any] = field(default_factory=dict)
    has_receipt: bool = False
    # Chunks the payload commits to, which exceeds len(chunks) once some have
    # been withheld. Taken from body's own opening, so it needs body disclosed.
    total: int = 0

    @property
    def text(self) -> str:
        return st_body_text(self.chunks)

    @property
    def revealed(self) -> int:
        return len(self.chunks)

    def spans(self) -> list[Optional[str]]:
        return [self.chunks.get(i) for i in range(self.total)]


def st_body_text(chunks: dict[int, str]) -> str:
    """Join disclosed chunks in index order. Withheld chunks are absent, so this
    is the visible text, not necessarily the original."""
    return "".join(chunks[i] for i in sorted(chunks))


def load(token: bytes) -> Loaded:
    """Hash-match the attached openings and split out the body chunks."""
    out = st.validate_statement_trusted(token)
    body = out.disclosed.get(st.BODY)
    chunks = body if isinstance(body, dict) else {}
    others = {
        st.NAME_BY_FIELD[k]: v
        for k, v in out.disclosed.items()
        if k != st.BODY and k in st.NAME_BY_FIELD
    }
    return Loaded(
        token=token,
        chunks={k: v for k, v in chunks.items() if isinstance(k, int)},
        fields=others,
        has_receipt=RECEIPTS_LABEL in (_arr(token)[1] or {}),
        total=len(_chunk_digests(token)),
    )


def restrict(token: bytes, keep: Iterable[int]) -> bytes:
    """Return a copy of `token` keeping only `keep`'s body chunk openings.

    Every non-chunk opening is preserved, including body's own -- without it the
    chunk hashes are unreachable and the remaining openings would not validate.
    """
    wanted = set(keep)
    by_digest = _chunk_digests(token)
    kept = []
    for enc in _sd_claims(token):
        if _disclosure_digest(HashAlg.SHA_256, enc) not in by_digest:
            kept.append(enc)
            continue
        if cbor2.loads(enc)[2] in wanted:
            kept.append(enc)
    return _with_sd_claims(token, kept)


@dataclass
class Verified:
    has_receipt: bool
    receipt_ok: bool
    disclosures_ok: bool
    chunk_count: int
    revealed: int = 0
    error: Optional[str] = None

    @property
    def valid(self) -> bool:
        return self.disclosures_ok and (self.receipt_ok or not self.has_receipt)


def verify(token: bytes, service_cert_pem: Optional[bytes]) -> Verified:
    """Check the embedded receipt against the service identity, then hash-match
    the attached openings. A locally issued sample has no receipt, so absence is
    reported rather than treated as a failure."""
    receipts = (_arr(token)[1] or {}).get(RECEIPTS_LABEL)
    has_receipt = bool(receipts) and service_cert_pem is not None

    receipt_ok, err = False, None
    if has_receipt:
        import ccf.cose
        from cryptography.x509 import load_pem_x509_certificate

        try:
            ccf.cose.verify_receipt(
                receipts[0],
                load_pem_x509_certificate(service_cert_pem).public_key(),
                sha256(bare_statement(token)).digest(),
            )
            receipt_ok = True
        except Exception as exc:  # untrusted input: any failure is a reject
            err = str(exc)

    try:
        loaded = load(token)
    except Exception as exc:
        return Verified(has_receipt, receipt_ok, False, 0, 0, err or str(exc))
    return Verified(has_receipt, receipt_ok, True, loaded.total, loaded.revealed, err)


def sample_statement(text: str, **fields: Any) -> bytes:
    """Issue a statement locally, all openings attached, so the tool is usable
    without a ledger. Uses the real schema; it just has no receipt."""
    from pycose.keys import EC2Key
    from pycose.keys.curves import P256
    from sd_cwt import present

    key = EC2Key.generate_key(crv=P256)
    token, discs = st.issue_statement(
        key, iss="https://demo.example", iat=1700000000, body=text, **fields
    )
    return present(token, discs)
