from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import cbor2
from cbor2 import CBORSimpleValue

import sd_cwt

PROFILE = json.loads((Path(__file__).parent / "static" / "report-profile.json").read_text())
FIELDS = tuple(PROFILE["fields"])
CONTENT_FIELDS = tuple(field["key"] for field in FIELDS)
FIELD_BY_NAME = {field["name"]: field["key"] for field in FIELDS}
BODY = FIELD_BY_NAME["body"]
REFERENCES = FIELD_BY_NAME["references"]
RCK = CBORSimpleValue(sd_cwt.core.REDACTED_CLAIM_KEYS)


def check_headers(protected: dict[Any, Any]) -> None:
    expected = {
        1: PROFILE["algorithm"],
        16: PROFILE["statementType"],
        170: PROFILE["hashAlgorithm"],
    }
    if any(protected.get(key) != value for key, value in expected.items()):
        raise ValueError("not the expected SD-CWT profile")


def check_payload(payload: dict[Any, Any]) -> None:
    if set(payload) != {1, 6, 8, RCK} or len(payload[RCK]) != len(CONTENT_FIELDS):
        raise ValueError("statement does not have the uniform report shape")


def resolve_all(payload: dict[Any, Any], presented: list[bytes]) -> dict[int, Any]:
    result = dict(sd_cwt.match_disclosures(payload, presented, require_all=True).disclosed)
    if set(result) != set(CONTENT_FIELDS):
        raise ValueError("disclosures do not match the report schema")
    if isinstance(result[BODY], dict):
        chunks = result[BODY]
        if sorted(chunks) != list(range(len(chunks))) or not all(
            isinstance(chunk, str) for chunk in chunks.values()
        ):
            raise ValueError("body chunks are invalid")
        result[BODY] = "".join(chunks[index] for index in range(len(chunks)))
    return result


def resolve_selected(payload: dict[Any, Any], presented: list[bytes]) -> dict[int, Any]:
    return dict(sd_cwt.match_disclosures(payload, presented).disclosed)


def describe_selected(
    payload: dict[Any, Any],
    presented: list[bytes],
    *,
    selected: dict[int, Any] | None = None,
) -> dict[str, Any]:
    if selected is None:
        selected = resolve_selected(payload, presented)
    fields = {}
    for field in FIELDS:
        if field["kind"] != "field":
            continue
        value = selected.get(field["key"])
        fields[field["name"]] = value.hex() if isinstance(value, bytes) else value
    body = selected.get(BODY)
    if isinstance(body, dict):
        openings = {
            hashlib.sha256(cbor2.dumps(encoded)).digest(): cbor2.loads(encoded)
            for encoded in presented
        }
        count = 0
        for digest in payload[RCK]:
            opening = openings.get(digest)
            if opening is not None and len(opening) == 3 and opening[2] == BODY:
                count = len(opening[1].get(RCK, []))
                break
        body_view = {"known": True, "chunks": [body.get(index) for index in range(count)]}
    else:
        body_view = {"known": False, "chunks": []}
    return {"fields": fields, "body": body_view, "references": selected.get(REFERENCES)}
