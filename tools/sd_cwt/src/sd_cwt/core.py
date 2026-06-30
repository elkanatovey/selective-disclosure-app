# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Minimal Selective Disclosure CBOR Web Token (SD-CWT) — custom profile.

Based on draft-ietf-spice-sd-cwt-08, covering the subset used by this project.

Implemented:
  * COSE_Sign1 issuer-signed CWT (via pycose).
  * Flat (top-level) map-entry redaction: Redacted Claim Hash in
    `redacted_claim_keys` (CBOR simple(59)); disclosures `[salt, value, key]`
    in the unprotected header (`sd_claims`, label 17).
  * Flat array-element redaction: element replaced inline by its Redacted Claim
    Hash wrapped in CBOR tag 60; disclosures `[salt, value]` (no key).
  * Nested / recursive redaction at arbitrary depth via `redact_paths`,
    including the ancestor-disclosure rule (a disclosed parent may reveal a
    still-redacted child).
  * Hash-algorithm agility driven by the protected `sd_alg` header
    (SHA-256/384/512).
  * Decoy padding via `pad_to=N` for a uniform token shape.

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


def _redact_node(node: Any, paths: list, sd_alg: HashAlg, disclosures: list) -> Any:
    """Recursively redact `node` at the given relative `paths`.

    Each path is a non-empty tuple of map keys / array indices. A length-1 path
    redacts that whole entry/element at this level; longer paths recurse first
    (so disclosing a redacted parent reveals a still-redacted child — the
    ancestor-disclosure rule). Appends generated disclosures to `disclosures`.
    """
    direct = set()
    deeper: dict[Any, list] = {}
    for p in paths:
        if len(p) == 1:
            direct.add(p[0])
        else:
            deeper.setdefault(p[0], []).append(tuple(p[1:]))

    if isinstance(node, dict):
        out: dict[Any, Any] = {}
        digests: list[bytes] = []
        for key, value in node.items():
            child = (
                _redact_node(value, deeper[key], sd_alg, disclosures)
                if key in deeper
                else value
            )
            if key in direct:
                salt = csprng(SALT_LEN)
                encoded = cbor2.dumps([salt, child, key])
                dig = _digest(sd_alg, encoded)
                disclosures.append(
                    Disclosure(
                        salt=salt, value=child, key=key, encoded=encoded, digest=dig
                    )
                )
                digests.append(dig)
            else:
                out[key] = child
        if digests:
            digests.sort()  # hide real-vs-decoy ordering; salts already randomise
            out[CBORSimpleValue(REDACTED_CLAIM_KEYS)] = digests
        return out

    if isinstance(node, list):
        out_list: list[Any] = []
        for i, elem in enumerate(node):
            child = (
                _redact_node(elem, deeper[i], sd_alg, disclosures)
                if i in deeper
                else elem
            )
            if i in direct:
                salt = csprng(SALT_LEN)
                encoded = cbor2.dumps([salt, child])
                dig = _digest(sd_alg, encoded)
                disclosures.append(
                    Disclosure(
                        salt=salt, value=child, key=None, encoded=encoded, digest=dig
                    )
                )
                out_list.append(CBORTag(REDACTED_ELEMENT_TAG, dig))
            else:
                out_list.append(child)
        return out_list

    raise ValueError("redaction path descends into a non-container value")


def issue(
    claims: dict[ClaimKey, Any],
    redact: set[ClaimKey],
    signer: Any,
    *,
    redact_elements: Optional[dict[ClaimKey, set[int]]] = None,
    redact_paths: Optional[list[tuple]] = None,
    sd_alg: HashAlg = HashAlg.SHA_256,
    pad_to: Optional[int] = None,
    protected_extra: Optional[dict] = None,
) -> tuple[bytes, list[Disclosure]]:
    """Build a redacted SD-CWT and sign it.

    Redaction targets are expressed as paths from the root:
      * `redact` — whole top-level map entries (shorthand for `(key,)`).
      * `redact_elements` — `{key: {indices}}` top-level array elements
        (shorthand for `(key, index)`).
      * `redact_paths` — arbitrary-depth paths, e.g. `(503, "region")` or
        `(700, "a", "b", 1)`, mixing map keys and array indices.

    Returns (signed COSE_Sign1 token bytes with NO disclosures attached, all
    generated disclosures).
    """
    paths: list[tuple] = [(k,) for k in redact]
    for key, indices in (redact_elements or {}).items():
        paths += [(key, i) for i in indices]
    paths += list(redact_paths or [])

    disclosures: list[Disclosure] = []
    payload = _redact_node(claims, paths, sd_alg, disclosures)

    if pad_to is not None:
        size = _digest_size(sd_alg)
        red_key = CBORSimpleValue(REDACTED_CLAIM_KEYS)
        digests = list(payload.get(red_key, []))
        while len(digests) < pad_to:
            digests.append(csprng(size))  # decoy digest (matches no disclosure)
        digests.sort()
        payload[red_key] = digests

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
    """Verify, then hash-match presented disclosures into clear/disclosed claims.

    Resolution is recursive: a disclosed map entry or array element may itself
    contain further redactions, resolved by additional disclosures (the
    ancestor-disclosure rule). Top-level map disclosures populate `disclosed`;
    everything else (clear claims, arrays, nested maps) is resolved under
    `clear`. Undisclosed redactions are omitted, and any presented disclosure
    that matches no reachable Redacted Claim Hash is rejected.
    """
    verified = verify(token, pubkey)

    arr = _cose_array(token)
    uhdr = arr[1] if len(arr) > 1 and arr[1] else {}
    presented = uhdr.get(SD_CLAIMS_LABEL, [])

    redacted_key = CBORSimpleValue(REDACTED_CLAIM_KEYS)

    by_map: dict[bytes, tuple] = {}  # digest -> (key, value)
    by_elem: dict[bytes, Any] = {}  # digest -> element value
    for encoded in presented:
        dig = _digest(verified.sd_alg, encoded)
        decoded = cbor2.loads(encoded)
        if len(decoded) == 3:
            _salt, value, key = decoded
            by_map[dig] = (key, value)
        elif len(decoded) == 2:
            _salt, value = decoded
            by_elem[dig] = value
        else:
            raise ValueError("malformed disclosure")

    consumed: set[bytes] = set()

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            out: dict[Any, Any] = {}
            for dig in node.get(redacted_key, []):
                if dig in by_map:
                    consumed.add(dig)
                    key, value = by_map[dig]
                    out[key] = resolve(value)
                # undisclosed redacted map key (or decoy) -> omitted
            for key, value in node.items():
                if key == redacted_key:
                    continue
                out[key] = resolve(value)
            return out
        if isinstance(node, list):
            out_list: list[Any] = []
            for elem in node:
                if isinstance(elem, CBORTag) and elem.tag == REDACTED_ELEMENT_TAG:
                    if elem.value in by_elem:
                        consumed.add(elem.value)
                        out_list.append(resolve(by_elem[elem.value]))
                    # undisclosed redacted element -> omitted
                else:
                    out_list.append(resolve(elem))
            return out_list
        return node

    full = resolve(verified.payload)

    unconsumed = (set(by_map) | set(by_elem)) - consumed
    if unconsumed:
        raise ValueError("presented disclosure does not match any redacted hash")

    # Top-level split: disclosed = top-level map disclosures; clear = the rest.
    disclosed: dict[Any, Any] = {}
    for dig in verified.payload.get(redacted_key, []):
        if dig in by_map:
            key, _value = by_map[dig]
            disclosed[key] = full[key]
    clear = {k: v for k, v in full.items() if k not in disclosed}

    return ValidatedClaims(clear=clear, disclosed=disclosed)
