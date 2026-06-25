"""Minimal Selective Disclosure CBOR Web Token (SD-CWT) — custom profile.

Based on draft-ietf-spice-sd-cwt-08, implementing only the subset we need.

Implemented:
  * COSE_Sign1 issuer-signed CWT (via pycose).
  * Map-entry redaction      -> Redacted Claim Hash in `redacted_claim_keys`
                                (CBOR simple(59)).
  * Array-element redaction  -> Redacted Claim Hash wrapped in CBOR tag 60.
  * Disclosures `[salt, value, key]` (map) / `[salt, value]` (array element) in
    the unprotected header (`sd_claims`, label 17).
  * Hash-alg agility driven by the protected `sd_alg` header (SHA-256/384/512).
  * Decoy padding via `pad_to=N` (uniform token shape).
  * Nesting/recursion (designed for; flat first).

Deliberately omitted:
  * Key Binding Token / `cnf` (the transparency-service receipt replaces it).
  * Temporal (`exp`/`nbf`) enforcement (time comes from the ledger receipt/seqno).

Security: ALL cryptographic randomness (salts, decoys) uses a CSPRNG (`secrets`).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional, Union

# --- COSE / CWT / SD-CWT labels (draft-ietf-spice-sd-cwt-08) ---
TYP_LABEL = 16
SD_CLAIMS_LABEL = 17          # unprotected header: array of disclosures
SD_ALG_LABEL = 170           # protected header: redaction hash algorithm
SD_CWT_TYP = 293             # application/sd-cwt
REDACTED_CLAIM_KEYS = 59     # CBOR simple(59): marks redacted map keys
REDACTED_ELEMENT_TAG = 60    # CBOR tag: marks a redacted array element

SALT_LEN = 16                # 128-bit salt, CSPRNG


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
    encoded: bytes = b""      # cbor([salt, value, key]) or cbor([salt, value])
    digest: bytes = b""       # sd_alg(encoded)


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

    Returns (signed COSE_Sign1 token bytes, all generated disclosures).
    """
    raise NotImplementedError


def present(token: bytes, selected: list[Disclosure]) -> bytes:
    """Attach exactly `selected` disclosures to the token's unprotected header."""
    raise NotImplementedError


def verify(token: bytes, pubkey: Any) -> VerifiedToken:
    """Verify the COSE_Sign1 signature; return header + redacted payload."""
    raise NotImplementedError


def validate(token: bytes, pubkey: Any) -> ValidatedClaims:
    """Verify, then hash-match presented disclosures into clear/disclosed claims."""
    raise NotImplementedError
