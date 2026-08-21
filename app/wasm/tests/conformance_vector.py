# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import json
import sys
from base64 import urlsafe_b64encode
from pathlib import Path

import cbor2
from pycose.keys import EC2Key
from pycose.keys.curves import P256

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools/sd_cwt/src"))
import sd_cwt
from sd_cwt.core import _cde


def as_hex(value: bytes) -> str:
    return value.hex()


def as_base64url(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode()


def validation_result(token: bytes, key: EC2Key) -> dict:
    validated = sd_cwt.validate(token, key)
    claims = {**validated.clear, **validated.disclosed}
    return {
        "token": as_hex(token),
        "claims": as_hex(cbor2.dumps(_cde(claims))),
        "clear": as_hex(cbor2.dumps(_cde(validated.clear))),
        "disclosed": as_hex(cbor2.dumps(_cde(validated.disclosed))),
    }


key = EC2Key.generate_key(crv=P256)
token, disclosures = sd_cwt.issue(
    {
        1: "https://issuer.example",
        500: "heap overflow in parser",
        501: "RCE",
    },
    [(500,), (501,)],
    key,
)
selected = [disclosure for disclosure in disclosures if disclosure.key == 501]
presented = sd_cwt.present(token, selected)
validated = sd_cwt.validate(presented, key)

_, foreign_disclosures = sd_cwt.issue(
    {1: "https://issuer.example", 777: "foreign"},
    [(777,)],
    key,
)
foreign_presented = sd_cwt.present(token, [foreign_disclosures[0]])

nested_token, nested_disclosures = sd_cwt.issue(
    {
        1: "https://issuer.example",
        700: {"a": {"b": "secret", "c": "visible sibling"}},
        1006: ["REF_A", "REF_B", "REF_C"],
    },
    [(700, "a"), (700, "a", "b"), (1006, 1)],
    key,
)
nested_presented = sd_cwt.present(nested_token, nested_disclosures)

decoy_token, decoy_disclosures = sd_cwt.issue(
    {1: "https://issuer.example", 500: "secret"},
    [(500,)],
    key,
    pad_to=3,
)
decoy_presented = sd_cwt.present(decoy_token, decoy_disclosures)

tag = cbor2.loads(token)
protected_header, _, payload, signature = list(tag.value)
to_be_signed = cbor2.dumps(["Signature1", protected_header, b"", payload])

print(
    json.dumps(
        {
            "token": as_hex(token),
            "selected": [as_hex(disclosure.encoded) for disclosure in selected],
            "presented": as_hex(presented),
            "protectedHeader": as_hex(protected_header),
            "payload": as_hex(payload),
            "signature": as_hex(signature),
            "toBeSigned": as_hex(to_be_signed),
            "publicJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": as_base64url(key.x),
                "y": as_base64url(key.y),
                "ext": True,
            },
            "claims": as_hex(
                cbor2.dumps(_cde({**validated.clear, **validated.disclosed}))
            ),
            "clear": as_hex(cbor2.dumps(_cde(validated.clear))),
            "disclosed": as_hex(cbor2.dumps(_cde(validated.disclosed))),
            "foreignPresented": as_hex(foreign_presented),
            "validationCases": [
                validation_result(nested_presented, key),
                validation_result(decoy_presented, key),
            ],
        }
    )
)
