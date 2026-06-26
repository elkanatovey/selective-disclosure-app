# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Minimal Selective Disclosure CBOR Web Token (SD-CWT) — custom profile.

Based on draft-ietf-spice-sd-cwt-08, covering the subset used by this project.

Implemented:
  * COSE_Sign1 issuer-signed CWT (via pycose).
  * Flat (top-level) map-entry redaction: Redacted Claim Hash in
    `redacted_claim_keys` (CBOR simple(59)); disclosures `[salt, value, key]`
    in the unprotected header (`sd_claims`, label 17).
  * Hash-algorithm agility driven by the protected `sd_alg` header
    (SHA-256/384/512).
  * Decoy padding via `pad_to=N` for a uniform token shape.

Not implemented:
  * Array-element redaction (CBOR tag 60).
  * Nested / recursive redaction.

Out of scope by design:
  * Key Binding Token / `cnf` (the transparency-service receipt covers it).
  * Temporal (`exp`/`nbf`) enforcement (time comes from the ledger receipt/seqno).

Security: all cryptographic randomness (salts, decoys) uses a CSPRNG (`secrets`).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional, Union

import cbor2
from cbor2 import CBORSimpleValue, CBORTag
from pycose.algorithms import Es256, Es384, Es512
from pycose.headers import Algorithm
from pycose.keys.curves import P256, P384, P521
from pycose.messages import CoseMessage, Sign1Message

# --- COSE / CWT / SD-CWT labels (draft-ietf-spice-sd-cwt-08) ---
TYP_LABEL = 16
SD_CLAIMS_LABEL = 17  # unprotected header: array of disclosures
SD_ALG_LABEL = 170  # protected header: redaction hash algorithm
SD_CWT_TYP = 293  # application/sd-cwt
REDACTED_CLAIM_KEYS = 59  # CBOR simple(59): marks redacted map keys
REDACTED_ELEMENT_TAG = 60  # CBOR tag: marks a redacted array element

SALT_LEN = 16  # 128-bit salt, CSPRNG


class HashAlg(IntEnum):
    """COSE algorithm identifiers for the SD-CWT `sd_alg` header."""

    SHA_256 = -16
    SHA_384 = -43
    SHA_512 = -44


ClaimKey = Union[int, str]


@dataclass
class Disclosure:
    """A Salted Disclosed Claim. `key` is None for redacted array elements."""

    salt: bytes
    value: Any
    key: Optional[ClaimKey] = None
    encoded: bytes = b""  # cbor([salt, value, key]) or cbor([salt, value])
    digest: bytes = b""  # sd_alg(encoded)


@dataclass
class VerifiedToken:
    """Result of signature verification: header + raw (still-redacted) payload."""

    protected: dict
    payload: Any
    sd_alg: HashAlg


@dataclass
class ValidatedClaims:
    """Reconstructed claim set after hash-matching presented disclosures."""

    clear: dict
    disclosed: dict


def csprng(n: int) -> bytes:
    """Return `n` cryptographically secure random bytes (CSPRNG)."""
    return secrets.token_bytes(n)


_HASH = {
    HashAlg.SHA_256: hashlib.sha256,
    HashAlg.SHA_384: hashlib.sha384,
    HashAlg.SHA_512: hashlib.sha512,
}
_CRV_ALG = {P256: Es256, P384: Es384, P521: Es512}


def _digest(sd_alg: HashAlg, data: bytes) -> bytes:
    return _HASH[HashAlg(sd_alg)](data).digest()


def _digest_size(sd_alg: HashAlg) -> int:
    return _HASH[HashAlg(sd_alg)]().digest_size


def _sign_alg(signer: Any):
    """Pick the COSE signing algorithm from the key's curve (default ES256)."""
    return _CRV_ALG.get(getattr(signer, "crv", P256), Es256)


def _cose_array(token: bytes) -> list:
    """Decode a tagged COSE_Sign1 into its [protected, unprotected, payload, sig] list."""
    return list(cbor2.loads(token).value)


def issue(
    claims: dict[ClaimKey, Any],
    redact: set[ClaimKey],
    signer: Any,
    *,
    sd_alg: HashAlg = HashAlg.SHA_256,
    pad_to: Optional[int] = None,
    protected_extra: Optional[dict] = None,
) -> tuple[bytes, list[Disclosure]]:
    """Build a redacted SD-CWT and sign it.

    Flat (top-level) map redaction only. Returns (signed COSE_Sign1 token bytes
    with NO disclosures attached, all generated disclosures).
    """
    payload: dict[Any, Any] = {}
    disclosures: list[Disclosure] = []
    digests: list[bytes] = []

    for key, value in claims.items():
        if key in redact:
            salt = csprng(SALT_LEN)
            encoded = cbor2.dumps([salt, value, key])
            dig = _digest(sd_alg, encoded)
            disclosures.append(
                Disclosure(salt=salt, value=value, key=key, encoded=encoded, digest=dig)
            )
            digests.append(dig)
        else:
            payload[key] = value

    if pad_to is not None:
        size = _digest_size(sd_alg)
        while len(digests) < pad_to:
            digests.append(csprng(size))  # decoy digest (matches no disclosure)

    if digests:
        digests.sort()  # hide real-vs-decoy ordering; salts already randomise
        payload[CBORSimpleValue(REDACTED_CLAIM_KEYS)] = digests

    phdr: dict[Any, Any] = {
        Algorithm: _sign_alg(signer),
        SD_ALG_LABEL: int(sd_alg),
        TYP_LABEL: SD_CWT_TYP,
    }
    if protected_extra:
        phdr.update(protected_extra)

    msg = Sign1Message(phdr=phdr, uhdr={}, payload=cbor2.dumps(payload))
    msg.key = signer
    return msg.encode(), disclosures


def present(token: bytes, selected: list[Disclosure]) -> bytes:
    """Attach exactly `selected` disclosures to the token's unprotected header.

    Operates on the COSE_Sign1 structure directly so the signature (over the
    protected header + payload) is preserved — no re-signing, no private key.
    """
    tag = cbor2.loads(token)
    arr = list(tag.value)
    uhdr = dict(arr[1]) if arr[1] else {}
    uhdr[SD_CLAIMS_LABEL] = [d.encoded for d in selected]
    arr[1] = uhdr
    return cbor2.dumps(CBORTag(tag.tag, arr))


def verify(token: bytes, pubkey: Any) -> VerifiedToken:
    """Verify the COSE_Sign1 signature; return header + redacted payload."""
    msg = CoseMessage.decode(token)
    if not isinstance(msg, Sign1Message):
        raise ValueError("not a COSE_Sign1 message")
    msg.key = pubkey
    if not msg.verify_signature():
        raise ValueError("COSE signature verification failed")

    arr = _cose_array(token)
    protected = cbor2.loads(arr[0]) if arr[0] else {}
    sd_alg = HashAlg(protected.get(SD_ALG_LABEL, int(HashAlg.SHA_256)))
    payload = cbor2.loads(msg.payload)
    return VerifiedToken(protected=protected, payload=payload, sd_alg=sd_alg)


def validate(token: bytes, pubkey: Any) -> ValidatedClaims:
    """Verify, then hash-match presented disclosures into clear/disclosed claims."""
    verified = verify(token, pubkey)

    arr = _cose_array(token)
    uhdr = arr[1] if len(arr) > 1 and arr[1] else {}
    presented = uhdr.get(SD_CLAIMS_LABEL, [])

    redacted_key = CBORSimpleValue(REDACTED_CLAIM_KEYS)
    redacted = set(verified.payload.get(redacted_key, []))
    clear = {k: v for k, v in verified.payload.items() if k != redacted_key}

    disclosed: dict[Any, Any] = {}
    for encoded in presented:
        if _digest(verified.sd_alg, encoded) not in redacted:
            raise ValueError("presented disclosure does not match any redacted hash")
        _salt, value, key = cbor2.loads(encoded)
        disclosed[key] = value

    return ValidatedClaims(clear=clear, disclosed=disclosed)
