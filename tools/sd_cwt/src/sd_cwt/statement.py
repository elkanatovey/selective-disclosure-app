# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Unified bug-report statement schema, layered on the ``sd_cwt`` token core.

A **report** and a **note/follow-up** are the *same object shape*: an SD-CWT
statement with a fixed set of content claims plus an always-present ``parent``.
Their role is derived purely from ``parent`` -- a *root* (report) has a garbage
sentinel there; a *child* (note) has a real parent-statement hash. There is no
explicit ``statement_type`` claim, so a redacted token cannot reveal whether a
parent exists until the holder discloses it.

Visibility
----------
* **Clear** (standard CWT keys, service-set): ``iss`` (1), ``iat`` (6). Plus the
  ``sd_alg`` machinery header added by the token core.
* **Selectively-disclosable** (all content, private-use keys): ``parent`` and
  every other field below.

Strict uniformity
-----------------
Every statement always carries *all* content fields as redacted entries. Absent
fields are padded with a random garbage sentinel (exactly as ``parent`` is when
there is no real parent). Consequently a bare redacted token always exposes the
same clear keys and the same, constant redacted-hash count regardless of how
much content it actually carries -- leaking neither field presence nor the
report-vs-note distinction.

This module is format-only: it produces inputs for :func:`sd_cwt.issue` and
validates decoded statements. It knows nothing about the on-chain service. Since
the transparency service (a TEE) is the sole signer, the authoritative statement
construction lives in the C++ enclave; this Python module is the reference
oracle and the researcher-side verification tooling.
"""

from typing import Any, Optional

import cbor2
from cbor2 import CBORSimpleValue, CBORTag

from .core import (
    REDACTED_CLAIM_KEYS,
    REDACTED_ELEMENT_TAG,
    Disclosure,
    ValidatedClaims,
    csprng,
    issue,
    validate,
    validate_trusted,
)

# --- Clear header claims (standard CWT, RFC 8392) --------------------------
ISS = 1
IAT = 6

# --- Content claims (private-use block); all selectively-disclosable -------
PARENT = 1000
TITLE = 1001
BODY = 1002
COMPONENT = 1003
SEVERITY = 1004
FINGERPRINT = 1005
REFERENCES = 1006
PATCH = 1007
PATCH_DATE = 1008

#: Content fields, in canonical order. Every statement carries all of them.
CONTENT_FIELDS: tuple[int, ...] = (
    PARENT,
    TITLE,
    BODY,
    COMPONENT,
    SEVERITY,
    FINGERPRINT,
    REFERENCES,
    PATCH,
    PATCH_DATE,
)

#: Claims that stay in the clear.
CLEAR_FIELDS: tuple[int, ...] = (ISS, IAT)

#: Ergonomic keyword-name -> content claim key.
FIELD_BY_NAME: dict[str, int] = {
    "parent": PARENT,
    "title": TITLE,
    "body": BODY,
    "component": COMPONENT,
    "severity": SEVERITY,
    "fingerprint": FINGERPRINT,
    "references": REFERENCES,
    "patch": PATCH,
    "patch_date": PATCH_DATE,
}
NAME_BY_FIELD: dict[int, str] = {v: k for k, v in FIELD_BY_NAME.items()}

#: Accepted value types per content field (strict uniformity is type-agnostic
#: for padding, but real inputs are validated).
_TYPES: dict[int, tuple[type, ...]] = {
    PARENT: (bytes,),
    TITLE: (str,),
    BODY: (str,),
    COMPONENT: (str,),
    SEVERITY: (str,),
    FINGERPRINT: (bytes, str),
    REFERENCES: (list,),
    PATCH: (str,),
    PATCH_DATE: (int,),
}

#: Length (bytes) of the random garbage sentinel padding absent content fields.
PAD_LEN = 16

_REDACTED_CLAIM_KEYS = 59  # simple(59): "redacted_claim_keys" placeholder key


def build_claims(iss: str, iat: int, fields: dict[int, Any]) -> dict[Any, Any]:
    """Assemble a full, strictly-uniform claims map.

    ``iss``/``iat`` go in the clear; every content field is included, real value
    when provided else a random garbage sentinel. Inputs are type-checked.
    """
    if not isinstance(iss, str):
        raise TypeError("iss must be a str")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise TypeError("iat must be an int")

    unknown = set(fields) - set(CONTENT_FIELDS)
    if unknown:
        raise ValueError(f"unknown content field(s): {sorted(unknown)}")

    claims: dict[Any, Any] = {ISS: iss, IAT: iat}
    for key in CONTENT_FIELDS:
        value = fields.get(key)
        if value is None:
            claims[key] = csprng(PAD_LEN)  # garbage sentinel (never disclosed)
            continue
        if not isinstance(value, _TYPES[key]):
            allowed = "/".join(t.__name__ for t in _TYPES[key])
            raise TypeError(f"{NAME_BY_FIELD[key]} must be {allowed}")
        claims[key] = value
    return claims


def issue_statement(
    signer: Any,
    *,
    iss: str,
    iat: int,
    parent: Optional[bytes] = None,
    title: Optional[str] = None,
    body: Optional[str] = None,
    component: Optional[str] = None,
    severity: Optional[str] = None,
    fingerprint: Optional[Any] = None,
    references: Optional[list] = None,
    patch: Optional[str] = None,
    patch_date: Optional[int] = None,
) -> tuple[bytes, list[Disclosure]]:
    """Build and sign a strictly-uniform statement token.

    Returns ``(token, disclosures)`` where ``token`` is the signed COSE_Sign1
    with NO disclosures attached (all content redacted) and ``disclosures`` are
    the salted disclosures for every content field (real and padded). Use
    :func:`disclosures_for` to select which to present.
    """
    fields = {
        PARENT: parent,
        TITLE: title,
        BODY: body,
        COMPONENT: component,
        SEVERITY: severity,
        FINGERPRINT: fingerprint,
        REFERENCES: references,
        PATCH: patch,
        PATCH_DATE: patch_date,
    }
    claims = build_claims(iss, iat, fields)
    # Redact each `references` element individually (in addition to the whole
    # field) so a single reference can later be disclosed without revealing its
    # siblings. Only when present as a list (an absent field is a garbage
    # sentinel with no elements). Mirrors the C++ token core (statement.cpp).
    redact_elements: Optional[dict[Any, set[int]]] = None
    if references is not None:
        redact_elements = {REFERENCES: set(range(len(references)))}
    return issue(
        claims,
        redact=set(CONTENT_FIELDS),
        signer=signer,
        redact_elements=redact_elements,
    )


def _nested_hashes(value: Any) -> list[bytes]:
    """The Redacted Claim Hashes referenced inside a disclosure's value: tag(60)
    array elements and simple(59) map-entry hashes, recursively."""
    out: list[bytes] = []
    if isinstance(value, list):
        for elem in value:
            if isinstance(elem, CBORTag) and elem.tag == REDACTED_ELEMENT_TAG:
                out.append(elem.value)
            else:
                out.extend(_nested_hashes(elem))
    elif isinstance(value, dict):
        redacted_key = CBORSimpleValue(REDACTED_CLAIM_KEYS)
        for key, val in value.items():
            if key == redacted_key:
                out.extend(val)  # list of map-entry hashes
            else:
                out.extend(_nested_hashes(val))
    return out


def disclosures_for(discs: list[Disclosure], *names: str) -> list[Disclosure]:
    """Select the disclosures needed to reveal the named content fields, e.g.
    ``"fingerprint"`` or ``"references"``. Naming a field reveals its whole
    value, so this pulls in the field's disclosure **and its descendant
    disclosures** (e.g. the individually-redacted ``references`` elements) by
    following the Redacted Claim Hashes nested in each included disclosure."""
    keys = set()
    for name in names:
        if name not in FIELD_BY_NAME:
            raise ValueError(f"unknown field name: {name!r}")
        keys.add(FIELD_BY_NAME[name])

    by_digest = {d.digest: d for d in discs}
    selected: list[Disclosure] = []
    seen: set[bytes] = set()
    frontier = [d for d in discs if d.key in keys]
    while frontier:
        d = frontier.pop()
        if d.digest in seen:
            continue
        seen.add(d.digest)
        selected.append(d)
        for h in _nested_hashes(d.value):
            child = by_digest.get(h)
            if child is not None and child.digest not in seen:
                frontier.append(child)
    return selected


def _payload_of(token: bytes) -> dict:
    obj = cbor2.loads(token)
    arr = obj.value if hasattr(obj, "value") else obj  # unwrap COSE tag 18
    return cbor2.loads(arr[2])


def redacted_shape(token: bytes) -> tuple[tuple[int, ...], int]:
    """Return ``(sorted clear claim keys, redacted-hash count)`` of a token.

    Two statements with the same shape are indistinguishable at the redacted
    level -- the invariant strict uniformity guarantees.
    """
    payload = _payload_of(token)
    red_key = CBORSimpleValue(_REDACTED_CLAIM_KEYS)
    n_redacted = len(payload.get(red_key, []))
    clear_keys = tuple(sorted(k for k in payload if isinstance(k, int)))
    return clear_keys, n_redacted


def _check_schema(out: ValidatedClaims) -> ValidatedClaims:
    if ISS not in out.clear or IAT not in out.clear:
        raise ValueError("statement missing mandatory clear claim (iss/iat)")
    unknown_clear = set(out.clear) - set(CLEAR_FIELDS)
    if unknown_clear:
        raise ValueError(f"unexpected clear claim(s): {sorted(unknown_clear)}")
    unknown_disc = set(out.disclosed) - set(CONTENT_FIELDS)
    if unknown_disc:
        raise ValueError(f"unexpected disclosed claim(s): {sorted(unknown_disc)}")
    return out


def validate_statement(token: bytes, issuer_pub: Any) -> ValidatedClaims:
    """Verify the issuer signature, resolve disclosures, enforce the schema."""
    return _check_schema(validate(token, issuer_pub))


def validate_statement_trusted(token: bytes) -> ValidatedClaims:
    """Resolve disclosures + enforce the schema WITHOUT checking the signature.

    For callers whose trust comes from a transparency receipt rather than the
    issuer signature (see :func:`sd_cwt.validate_trusted`).
    """
    return _check_schema(validate_trusted(token))
