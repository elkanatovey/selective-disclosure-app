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
  * Decoy padding via `pad_to=N` for a uniform token shape; each decoy is a
    salt-only disclosure `[salt]` returned to the holder (draft-08 s10).
  * Key Binding Token presentation & verification (`kbt_sign` / `kbt_verify`):
    holder proof-of-possession over the RFC 8747 `cnf` key, `kcwt` (13) header,
    `application/kb+cwt` (typ 294), KBT + SD-CWT audience and `cnonce` binding
    (draft-08 s8/s9).
  * Encoding MUSTs enforced on untrusted input: definite-length only (s5.1),
    finite exp/nbf/iat encodings (s5.2), map-key type/length limits (s5.3),
    duplicate-map-key rejection (s5.4), max nesting depth 16 (s5.5), and
    non-empty `sd_claims` (s9 step 2).
  * Duplicate-claim-key rejection at validation: a disclosure whose Claim Key
    collides with another disclosed key or a non-redacted key at the same map
    level invalidates the whole SD-CWT (s9 step 8).

Note on array-element redaction: an undisclosed redacted element is dropped from
the reconstructed claim set, which shortens the array and shifts the indices of
later elements (draft-08 s9, step 10). Where element position carries meaning,
prefer redacting whole map entries (which never reindex) or redacting the entire
array as one entry.

Out of scope by design:
  * Temporal *validity* checks (comparing `exp`/`nbf`/`iat` against a clock or
    each other) -- time ordering comes from the ledger receipt/seqno; only the
    s5.2 encoding checks on those claims are enforced.
  * AEAD-encrypted disclosures (`sd_aead*`) and pre-issuance To-Be-Redacted tags.

Security: all cryptographic randomness (salts, decoys) uses a CSPRNG (`secrets`).
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional, Union

import cbor2
from cbor2 import CBORSimpleValue, CBORTag
from pycose.algorithms import Es256, Es384, Es512
from pycose.headers import Algorithm
from pycose.keys import EC2Key
from pycose.keys.curves import P256, P384, P521
from pycose.messages import CoseMessage, Sign1Message

# --- COSE / CWT / SD-CWT labels (draft-ietf-spice-sd-cwt-08) ---
TYP_LABEL = 16
SD_CLAIMS_LABEL = 17  # unprotected header: array of disclosures
KCWT_LABEL = 13  # KBT protected header: embedded issued SD-CWT (RFC 9528)
SD_ALG_LABEL = 170  # protected header: redaction hash algorithm
SD_CWT_TYP = 293  # application/sd-cwt
KB_CWT_TYP = 294  # application/kb+cwt (Key Binding Token)
REDACTED_CLAIM_KEYS = 59  # CBOR simple(59): marks redacted map keys
REDACTED_ELEMENT_TAG = 60  # CBOR tag: marks a redacted array element

# CWT claim keys used by the KBT / SD-CWT payloads.
ISS = 1
SUB = 2
AUD = 3
EXP = 4
NBF = 5
IAT = 6
CTI = 7
CNF = 8
CNONCE = 39

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
    encoded: bytes = (
        b""  # cbor([salt, value, key]) / cbor([salt, value]) / cbor([salt])
    )
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


@dataclass
class KBTResult:
    """Result of verifying a Key Binding Token: bound claims + KBT metadata."""

    claims: ValidatedClaims
    aud: Any
    cnonce: Optional[bytes] = None


def csprng(n: int) -> bytes:
    """Return `n` cryptographically secure random bytes (CSPRNG)."""
    return secrets.token_bytes(n)


_HASH = {
    HashAlg.SHA_256: hashlib.sha256,
    HashAlg.SHA_384: hashlib.sha384,
    HashAlg.SHA_512: hashlib.sha512,
}
_CRV_ALG = {P256: Es256, P384: Es384, P521: Es512}
_CRV_BY_ID = {1: P256, 2: P384, 3: P521}  # COSE EC curve identifiers


def _digest(sd_alg: HashAlg, data: bytes) -> bytes:
    return _HASH[HashAlg(sd_alg)](data).digest()


def _sign_alg(signer: Any):
    """Pick the COSE signing algorithm from the key's curve (default ES256)."""
    return _CRV_ALG.get(getattr(signer, "crv", P256), Es256)


def _cnf_from_key(key: Any) -> dict:
    """Build an RFC 8747 `cnf` claim `{1: COSE_Key}` holding `key`'s PUBLIC part.

    Only the EC2 public coordinates are copied; the private scalar is never
    included. The confirmation key is caller-supplied policy — the token layer
    is agnostic to whether it is a stable or per-token key.
    """
    crv = getattr(key, "crv", P256)
    cose_key = {
        1: 2,  # kty: EC2
        -1: getattr(crv, "identifier", 1),  # crv
        -2: key.x,  # x coordinate
        -3: key.y,  # y coordinate
    }
    return {1: cose_key}  # cnf confirmation method 1 = COSE_Key


def _key_from_cnf(cnf: dict) -> EC2Key:
    """Reconstruct a public EC2 verification key from a `cnf` `{1: COSE_Key}`."""
    if not isinstance(cnf, dict) or 1 not in cnf:
        raise ValueError("cnf claim missing or not a COSE_Key confirmation")
    cose_key = cnf[1]
    if not isinstance(cose_key, dict) or cose_key.get(1) != 2:
        raise ValueError("cnf confirmation key is not an EC2 COSE_Key")
    crv_id = cose_key.get(-1)
    crv = _CRV_BY_ID.get(crv_id) if isinstance(crv_id, int) else None
    if crv is None:
        raise ValueError("cnf confirmation key uses an unsupported curve")
    return EC2Key(crv=crv, x=cose_key[-2], y=cose_key[-3])


def _cose_array(token: bytes) -> list:
    """Decode a tagged COSE_Sign1 into its [protected, unprotected, payload, sig] list."""
    return list(cbor2.loads(token).value)


MAX_DEPTH = 16  # draft-08 s5.5: reject Claims Sets nested beyond 16 levels


def _scan_cbor(data: bytes, off: int, depth: int, is_key: bool = False) -> int:
    """Structurally scan one CBOR item, enforcing draft-08 encoding MUSTs.

    Rejects indefinite-length items (s5.1), duplicate map keys (s5.4), and
    nesting deeper than `MAX_DEPTH` (s5.5). When `is_key` is set, also enforces
    the map-key type/length limits (s5.3): only uint, negint, text string of at
    most 255 octets, or the simple(59) redaction marker may be a map key.
    Returns the offset just past the scanned item. `cbor2` accepts all of these
    silently, so decoders of untrusted tokens must enforce them explicitly.
    """
    if depth > MAX_DEPTH:
        raise ValueError("CBOR nesting exceeds maximum depth (draft-08 s5.5)")
    if off >= len(data):
        raise ValueError("truncated CBOR")
    ib = data[off]
    off += 1
    mt = ib >> 5  # major type
    ai = ib & 0x1F  # additional info
    if ai == 31:
        raise ValueError("indefinite-length CBOR is forbidden (draft-08 s5.1)")
    if ai < 24:
        arg = ai
    elif ai == 24:
        arg = data[off]
        off += 1
    elif ai == 25:
        arg = int.from_bytes(data[off : off + 2], "big")
        off += 2
    elif ai == 26:
        arg = int.from_bytes(data[off : off + 4], "big")
        off += 4
    elif ai == 27:
        arg = int.from_bytes(data[off : off + 8], "big")
        off += 8
    else:
        raise ValueError("reserved CBOR additional-info value")

    if is_key and not (
        mt in (0, 1)  # unsigned / negative integer
        or (mt == 3 and arg <= 255)  # text string, at most 255 octets
        or (mt == 7 and ai <= 24 and arg == 59)  # simple(59) redaction marker
    ):
        raise ValueError("invalid SD-CWT map key type or length (draft-08 s5.3)")

    if mt in (0, 1, 7):  # uint / negint / simple / float: no further payload
        return off
    if mt in (2, 3):  # byte string / text string
        return off + arg
    if mt == 4:  # array
        for _ in range(arg):
            off = _scan_cbor(data, off, depth + 1)
        return off
    if mt == 5:  # map
        seen: set[bytes] = set()
        for _ in range(arg):
            key_start = off
            off = _scan_cbor(data, off, depth + 1, is_key=True)
            key_bytes = data[key_start:off]
            if key_bytes in seen:
                raise ValueError("duplicate map key (draft-08 s5.4)")
            seen.add(key_bytes)
            off = _scan_cbor(data, off, depth + 1)
        return off
    # mt == 6: tag — scan the single tagged item (tag itself is not a claims level)
    return _scan_cbor(data, off, depth)


def _check_cbor(data: bytes) -> None:
    """Assert `data` is a single conformant CBOR item with no trailing bytes."""
    if _scan_cbor(data, 0, 0) != len(data):
        raise ValueError("trailing bytes after CBOR item")


_MAX_DATE = 2**53  # draft-08 s5.2: |value| > 2^53 loses integer precision as float


def _check_date_claims(claims: Any) -> None:
    """Reject malformed `exp`/`nbf`/`iat` encodings (draft-08 s5.2).

    Those claims MUST be finite numbers; NaN, +/-Infinity, and floats whose
    magnitude exceeds 2^53 are forbidden. This validates the *encoding* only;
    comparing the values against a clock is out of scope (the ledger receipt
    provides the authoritative time ordering).
    """
    if not isinstance(claims, dict):
        return
    for label in (EXP, NBF, IAT):
        if label not in claims:
            continue
        val = claims[label]
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            raise ValueError("exp/nbf/iat must be a finite number (draft-08 s5.2)")
        if isinstance(val, float) and not math.isfinite(val):
            raise ValueError("exp/nbf/iat must not be NaN or Infinity (draft-08 s5.2)")
        if not -_MAX_DATE <= val <= _MAX_DATE:
            raise ValueError("exp/nbf/iat magnitude exceeds 2^53 (draft-08 s5.2)")


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
    cnf: Optional[Any] = None,
) -> tuple[bytes, list[Disclosure]]:
    """Build a redacted SD-CWT and sign it.

    Redaction targets are expressed as paths from the root:
      * `redact` — whole top-level map entries (shorthand for `(key,)`).
      * `redact_elements` — `{key: {indices}}` top-level array elements
        (shorthand for `(key, index)`).
      * `redact_paths` — arbitrary-depth paths, e.g. `(503, "region")` or
        `(700, "a", "b", 1)`, mixing map keys and array indices.

    `cnf`, if given, is a public key embedded as the RFC 8747 confirmation
    claim (8) in the clear payload; the holder of the matching private key
    binds presentations via a Key Binding Token (`kbt_sign`). Whose key this is
    (stable holder, per-token, ...) is caller/deployment policy.

    Returns (signed COSE_Sign1 token bytes with NO disclosures attached, all
    generated disclosures).
    """
    paths: list[tuple] = [(k,) for k in redact]
    for key, indices in (redact_elements or {}).items():
        paths += [(key, i) for i in indices]
    paths += list(redact_paths or [])

    work: dict[ClaimKey, Any] = dict(claims)
    if cnf is not None:
        work[8] = _cnf_from_key(cnf)  # RFC 8747 confirmation claim (clear)

    disclosures: list[Disclosure] = []
    payload = _redact_node(work, paths, sd_alg, disclosures)

    if pad_to is not None:
        red_key = CBORSimpleValue(REDACTED_CLAIM_KEYS)
        digests = list(payload.get(red_key, []))
        while len(digests) < pad_to:
            salt = csprng(SALT_LEN)
            encoded = cbor2.dumps([salt])  # decoy: salt-only Salted Disclosed Claim
            dig = _digest(sd_alg, encoded)
            disclosures.append(
                Disclosure(salt=salt, value=None, key=None, encoded=encoded, digest=dig)
            )
            digests.append(dig)
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
    if selected:
        uhdr[SD_CLAIMS_LABEL] = [d.encoded for d in selected]
    else:
        uhdr.pop(SD_CLAIMS_LABEL, None)  # draft-08 s8: omit sd_claims when empty
    arr[1] = uhdr
    return cbor2.dumps(CBORTag(tag.tag, arr))


def verify(token: bytes, pubkey: Any) -> VerifiedToken:
    """Verify the COSE_Sign1 signature; return header + redacted payload."""
    _check_cbor(token)
    msg = CoseMessage.decode(token)
    if not isinstance(msg, Sign1Message):
        raise ValueError("not a COSE_Sign1 message")
    msg.key = pubkey
    if not msg.verify_signature():
        raise ValueError("COSE signature verification failed")

    arr = _cose_array(token)
    if arr[0]:
        _check_cbor(arr[0])  # protected header bytes
    _check_cbor(msg.payload)  # claims payload (indefinite/dup/depth MUSTs)
    protected = cbor2.loads(arr[0]) if arr[0] else {}
    sd_alg = HashAlg(protected.get(SD_ALG_LABEL, int(HashAlg.SHA_256)))
    payload = cbor2.loads(msg.payload)
    _check_date_claims(payload)
    return VerifiedToken(protected=protected, payload=payload, sd_alg=sd_alg)


def _presented_from_arr(arr: list) -> list:
    """Extract the `sd_claims` disclosures from a COSE array (reject empty header)."""
    uhdr = arr[1] if len(arr) > 1 and arr[1] else {}
    if SD_CLAIMS_LABEL in uhdr and not uhdr[SD_CLAIMS_LABEL]:
        raise ValueError("empty sd_claims header is invalid (draft-08 s9 step 2)")
    return uhdr.get(SD_CLAIMS_LABEL, [])


def match_disclosures(
    payload: Any,
    presented: list,
    *,
    sd_alg: HashAlg = HashAlg.SHA_256,
) -> ValidatedClaims:
    """Hash-match presented disclosures against an already-trusted claims payload.

    This is the disclosure-resolution core of `validate()` with NO signature
    verification. Call it directly only when the Issuer signature over `payload`
    is already trusted -- for example, `payload` came from a prior `verify()`, or
    the token was read from a trusted store. Otherwise use `validate()`, which
    verifies the COSE signature first.

    `payload` is the decoded (still-redacted) CWT claims map; `presented` is the
    list of bstr-encoded Salted Disclosed Claims (the `sd_claims` header value).
    Resolution is recursive and enforces the same MUSTs as `validate()`: every
    presented disclosure must match a reachable Redacted Claim Hash, and a
    disclosed key must not duplicate another key at the same level (s9 step 8).
    Top-level map disclosures populate `disclosed`; everything else resolves
    under `clear`. Raw Redacted Claim Hashes are never surfaced.
    """
    redacted_key = CBORSimpleValue(REDACTED_CLAIM_KEYS)

    by_map: dict[bytes, tuple] = {}  # digest -> (key, value)
    by_elem: dict[bytes, Any] = {}  # digest -> element value
    by_decoy: set[bytes] = set()  # digest of a salt-only decoy disclosure
    for encoded in presented:
        _check_cbor(encoded)  # disclosures are attacker-supplied, unsigned
        dig = _digest(sd_alg, encoded)
        decoded = cbor2.loads(encoded)
        if len(decoded) == 3:
            _salt, value, key = decoded
            by_map[dig] = (key, value)
        elif len(decoded) == 2:
            _salt, value = decoded
            by_elem[dig] = value
        elif len(decoded) == 1:
            by_decoy.add(dig)
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
                    if key in out:
                        raise ValueError(
                            "disclosed claim key duplicates another disclosed key "
                            "at the same level (draft-08 s9 step 8)"
                        )
                    out[key] = resolve(value)
                elif dig in by_decoy:
                    consumed.add(dig)
                # undisclosed redacted map key (or undisclosed decoy) -> omitted
            for key, value in node.items():
                if key == redacted_key:
                    continue
                if key in out:
                    raise ValueError(
                        "disclosed claim key duplicates a non-redacted claim key "
                        "at the same level (draft-08 s9 step 8)"
                    )
                out[key] = resolve(value)
            return out
        if isinstance(node, list):
            out_list: list[Any] = []
            for elem in node:
                if isinstance(elem, CBORTag) and elem.tag == REDACTED_ELEMENT_TAG:
                    if elem.value in by_elem:
                        consumed.add(elem.value)
                        out_list.append(resolve(by_elem[elem.value]))
                    elif elem.value in by_decoy:
                        consumed.add(elem.value)
                    # undisclosed redacted element (or decoy) -> omitted
                else:
                    out_list.append(resolve(elem))
            return out_list
        return node

    full = resolve(payload)

    unconsumed = (set(by_map) | set(by_elem) | by_decoy) - consumed
    if unconsumed:
        raise ValueError("presented disclosure does not match any redacted hash")

    # Top-level split: disclosed = top-level map disclosures; clear = the rest.
    disclosed: dict[Any, Any] = {}
    for dig in payload.get(redacted_key, []):
        if dig in by_map:
            key, _value = by_map[dig]
            disclosed[key] = full[key]
    clear = {k: v for k, v in full.items() if k not in disclosed}

    return ValidatedClaims(clear=clear, disclosed=disclosed)


def validate(token: bytes, pubkey: Any) -> ValidatedClaims:
    """Verify, then hash-match presented disclosures into clear/disclosed claims.

    Resolution is recursive: a disclosed map entry or array element may itself
    contain further redactions, resolved by additional disclosures (the
    ancestor-disclosure rule). Top-level map disclosures populate `disclosed`;
    everything else (clear claims, arrays, nested maps) is resolved under
    `clear`. Undisclosed redactions are omitted, and any presented disclosure
    that matches no reachable Redacted Claim Hash is rejected. Raw Redacted
    Claim Hashes (the `simple(59)` array and `tag(60)` wrappers) are never
    surfaced in the returned claims — only resolved values appear. The
    signature-free hash-matching core is exposed as `match_disclosures`.
    """
    verified = verify(token, pubkey)
    presented = _presented_from_arr(_cose_array(token))
    return match_disclosures(verified.payload, presented, sd_alg=verified.sd_alg)


def validate_trusted(token: bytes) -> ValidatedClaims:
    """Hash-match disclosures WITHOUT verifying the COSE signature.

    For callers whose trust in the token comes from elsewhere -- e.g. a CCF
    transparency receipt proving the SD-CWT is committed to the ledger -- rather
    than from re-checking the Issuer signature. It still enforces the structural
    and encoding MUSTs (definite-length, map-key limits, nesting depth, finite
    date claims, non-empty `sd_claims`) and hash-matches every disclosure against
    the Redacted Claim Hashes in the (trusted) payload, so a tampered or foreign
    disclosure is still rejected. `token` MUST be exactly the bytes the receipt
    covers. Use `validate()` when the Issuer signature is itself the trust anchor.
    """
    _check_cbor(token)
    arr = _cose_array(token)
    if arr[0]:
        _check_cbor(arr[0])  # protected header bytes
    _check_cbor(arr[2])  # claims payload (indefinite/dup/depth/key MUSTs)
    protected = cbor2.loads(arr[0]) if arr[0] else {}
    sd_alg = HashAlg(protected.get(SD_ALG_LABEL, int(HashAlg.SHA_256)))
    payload = cbor2.loads(arr[2])
    _check_date_claims(payload)
    presented = _presented_from_arr(arr)
    return match_disclosures(payload, presented, sd_alg=sd_alg)


def kbt_sign(
    token: bytes,
    selected: list[Disclosure],
    holder: Any,
    *,
    aud: Any,
    iat: Optional[int] = None,
    cti: Optional[bytes] = None,
    cnonce: Optional[bytes] = None,
    exp: Optional[int] = None,
    nbf: Optional[int] = None,
) -> bytes:
    """Wrap an issued SD-CWT in a holder-signed Key Binding Token (draft-08 s8).

    Attaches `selected` disclosures to the SD-CWT, embeds it in the KBT `kcwt`
    (13) protected header, and signs the KBT with the `holder` private key —
    which MUST match the SD-CWT `cnf` confirmation key. The payload carries the
    target `aud` and MUST include `iat` or `cti`; `iss`/`sub` are forbidden and
    are never added.
    """
    if iat is None and cti is None:
        raise ValueError("KBT payload MUST contain iat or cti (draft-08 s8.1)")

    presented = present(token, selected)
    sd_cwt_tag = cbor2.loads(presented)  # tagged COSE_Sign1 of the issued SD-CWT

    phdr: dict[Any, Any] = {
        Algorithm: _sign_alg(holder),
        TYP_LABEL: KB_CWT_TYP,
        KCWT_LABEL: sd_cwt_tag,
    }

    payload: dict[int, Any] = {AUD: aud}
    if iat is not None:
        payload[IAT] = iat
    if cti is not None:
        payload[CTI] = cti
    if exp is not None:
        payload[EXP] = exp
    if nbf is not None:
        payload[NBF] = nbf
    if cnonce is not None:
        payload[CNONCE] = cnonce

    msg = Sign1Message(phdr=phdr, uhdr={}, payload=cbor2.dumps(payload))
    msg.key = holder
    return msg.encode()


def kbt_verify(
    kbt: bytes,
    issuer_pub: Any,
    *,
    expected_aud: Any,
    expected_cnonce: Optional[bytes] = None,
) -> KBTResult:
    """Verify a Key Binding Token and its embedded SD-CWT (draft-08 s9).

    Steps: parse the KBT; extract the embedded SD-CWT from the `kcwt` header and
    verify the issuer signature over it; recover the `cnf` key from the SD-CWT
    payload and verify the KBT signature against it (proof of possession); check
    both the KBT and SD-CWT audiences (s9 step 9), time-claim presence, and
    optional `cnonce`; finally hash-match the presented disclosures into the
    validated claim set.
    """
    outer = cbor2.loads(kbt)
    if not isinstance(outer, CBORTag) or not isinstance(outer.value, list):
        raise ValueError("KBT is not a tagged COSE_Sign1")
    _check_cbor(kbt)
    kbt_arr = outer.value
    if kbt_arr[0]:
        _check_cbor(kbt_arr[0])  # KBT protected header (embeds the SD-CWT)
    _check_cbor(kbt_arr[2])  # KBT payload
    kbt_phdr = cbor2.loads(kbt_arr[0]) if kbt_arr[0] else {}
    if kbt_phdr.get(TYP_LABEL) != KB_CWT_TYP:
        raise ValueError("KBT typ header is not application/kb+cwt (294)")

    sd_cwt_tag = kbt_phdr.get(KCWT_LABEL)
    if not isinstance(sd_cwt_tag, CBORTag):
        raise ValueError("KBT kcwt header does not contain an embedded SD-CWT")
    sd_cwt_bytes = cbor2.dumps(sd_cwt_tag)

    # Issuer signature + cnf recovery come from validating the embedded SD-CWT.
    verified = verify(sd_cwt_bytes, issuer_pub)
    cnf = verified.payload.get(CNF)
    if cnf is None:
        raise ValueError("embedded SD-CWT has no cnf claim (draft-08 requires it)")
    holder_pub = _key_from_cnf(cnf)

    # Proof of possession: the KBT signature MUST verify under the cnf key.
    kbt_msg = CoseMessage.decode(kbt)
    if not isinstance(kbt_msg, Sign1Message):
        raise ValueError("KBT is not a COSE_Sign1 message")
    kbt_msg.key = holder_pub
    if not kbt_msg.verify_signature():
        raise ValueError("KBT signature verification failed (cnf key mismatch)")

    kbt_payload = cbor2.loads(kbt_arr[2]) if kbt_arr[2] else {}
    _check_date_claims(kbt_payload)
    if ISS in kbt_payload or SUB in kbt_payload:
        raise ValueError("KBT payload MUST NOT contain iss or sub (draft-08 s8.1)")
    if IAT not in kbt_payload and CTI not in kbt_payload:
        raise ValueError("KBT payload MUST contain iat or cti (draft-08 s8.1)")
    if kbt_payload.get(AUD) != expected_aud:
        raise ValueError("KBT audience does not match the intended verifier")
    # draft-08 s9 step 9: an SD-CWT audience, if the Issuer set one, MUST also
    # correspond to the intended recipient (it need not equal the KBT audience).
    sd_cwt_aud = verified.payload.get(AUD)
    if sd_cwt_aud is not None and sd_cwt_aud != expected_aud:
        raise ValueError("SD-CWT audience does not match the intended verifier")

    cnonce = kbt_payload.get(CNONCE)
    if expected_cnonce is not None and cnonce != expected_cnonce:
        raise ValueError("KBT cnonce does not match the expected nonce")

    claims = validate(sd_cwt_bytes, issuer_pub)
    return KBTResult(claims=claims, aud=kbt_payload.get(AUD), cnonce=cnonce)
