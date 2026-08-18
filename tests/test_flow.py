import hashlib
import secrets
import time
import unicodedata

import cbor2
import pytest
from cbor2 import CBORTag
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from pycose.algorithms import Es256
from pycose.headers import Algorithm
from pycose.messages import Sign1Message

from webapp.app import (
    DeliveryBody,
    EndorseBody,
    KbtBody,
    RCK,
    SCITT_RECEIPTS,
    SD_CLAIMS,
    TokenBody,
    b64,
    cbor,
    endorse,
    get_state,
    mock_msrc,
    mock_scitt,
    mock_verifier,
    parts,
    private_cose,
    resolve_all,
    state,
    unb64,
    verify_bundle,
    with_uhdr,
)


def opening(value, key=None):
    item = [secrets.token_bytes(16), value]
    if key is not None:
        item.append(key)
    encoded = cbor(item)
    return encoded, hashlib.sha256(cbor(encoded)).digest()


def browser_style_report():
    signer = ec.generate_private_key(ec.SECP256R1())
    point = signer.public_key().public_numbers()
    endorsement = endorse(
        EndorseBody(
            public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": b64(point.x.to_bytes(32, "big")),
                "y": b64(point.y.to_bytes(32, "big")),
            }
        )
    )
    raw_body = "Cafe\u0301\r\n1234567 and more"
    body = unicodedata.normalize("NFC", raw_body.replace("\r\n", "\n").replace("\r", "\n"))
    body_chunks = [body[index : index + 6] for index in range(0, len(body), 6)]
    disclosures = []
    body_digests = []
    for index, chunk in enumerate(body_chunks):
        encoded, digest = opening(chunk, index)
        disclosures.append(encoded)
        body_digests.append(digest)
    values = {
        1000: secrets.token_bytes(16),
        1001: "private title",
        1002: {RCK: sorted(body_digests)},
        1003: "parser",
        1004: "high",
        1005: bytes.fromhex("deadbeef"),
        1007: secrets.token_bytes(16),
        1008: secrets.token_bytes(16),
    }
    nested, nested_digest = opening("CVE-2026-1042")
    values[1006] = [CBORTag(60, nested_digest)]
    disclosures.append(nested)
    digests = []
    for key, value in values.items():
        encoded, digest = opening(value, key)
        disclosures.append(encoded)
        digests.append(digest)
    iat = int(time.time())
    protected = cbor(
        {
            1: -7,
            3: "application/sd-cwt",
            15: {1: endorsement["issuer"], 2: "case-1", 6: iat},
            16: 293,
            33: [unb64(endorsement["leaf"]), unb64(endorsement["root"])],
            170: -16,
        }
    )
    payload = cbor(
        {
            1: endorsement["issuer"],
            6: iat,
            8: state.msrc_cnf,
            RCK: sorted(digests),
        }
    )
    message = Sign1Message(phdr_encoded=protected, uhdr={}, payload=payload)
    message.key = private_cose(signer)
    return message.encode(tag=True), disclosures, body


def test_external_signer_registration_and_msrc_delivery():
    redacted, disclosures, body = browser_style_report()
    payload = cbor2.loads(parts(redacted)[2])
    assert not hasattr(state, "issuer_key")
    assert set(payload) == {1, 6, 8, RCK}
    assert len(payload[RCK]) == 9
    assert b"private title" not in redacted

    decoded = [cbor2.loads(item) for item in disclosures]
    body_field = next(item for item in decoded if len(item) == 3 and item[2] == 1002)
    body_hashes = body_field[1][RCK]
    body_openings = [
        (encoded, item)
        for encoded, item in zip(disclosures, decoded)
        if len(item) == 3 and isinstance(item[2], int) and item[2] < 1000
    ]
    body_parts = {item[2]: item[1] for _, item in body_openings}
    assert len(body_hashes) == len(body_parts) > 1
    assert all(len(chunk) <= 6 for chunk in body_parts.values())
    assert {
        hashlib.sha256(cbor(encoded)).digest() for encoded, _ in body_openings
    } == set(body_hashes)
    assert "".join(body_parts[index] for index in range(len(body_parts))) == body
    assert "\r" not in body and "é" in body

    registration = mock_scitt(TokenBody(token=b64(redacted)))
    transparent = unb64(registration["transparent"])
    header = dict(parts(transparent)[1])
    assert SCITT_RECEIPTS in header
    header[SD_CLAIMS] = disclosures
    full = with_uhdr(redacted, header)
    assert all(parts(full)[index] == parts(redacted)[index] for index in (0, 2, 3))

    with pytest.raises(HTTPException):
        mock_scitt(TokenBody(token=b64(full)))
    with pytest.raises(HTTPException):
        mock_msrc(DeliveryBody(statement=registration["transparent"]))

    delivered = mock_msrc(DeliveryBody(statement=b64(full)))
    assert delivered["fields"] == 9
    assert delivered["txid"] == registration["txid"]
    assert resolve_all(payload, disclosures)[1002] == body


def test_public_state_contains_only_public_key_material():
    public = get_state()
    assert set(public["msrcJwk"]) == {"kty", "crv", "x", "y"}
    assert "d" not in public["msrcJwk"]

    with pytest.raises(HTTPException):
        endorse(EndorseBody(public_jwk={**public["msrcJwk"], "d": "secret"}))


def test_endorsed_chain_has_scitt_didx509_extensions():
    signer = ec.generate_private_key(ec.SECP256R1())
    point = signer.public_key().public_numbers()
    endorsement = endorse(
        EndorseBody(
            public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": b64(point.x.to_bytes(32, "big")),
                "y": b64(point.y.to_bytes(32, "big")),
            }
        )
    )
    leaf = x509.load_der_x509_certificate(unb64(endorsement["leaf"]))
    root = x509.load_der_x509_certificate(unb64(endorsement["root"]))
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    for certificate in (root, leaf):
        certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)


def test_kbt_selects_one_body_chunk_and_binds_audience():
    redacted, disclosures, _ = browser_style_report()
    registration = mock_scitt(TokenBody(token=b64(redacted)))
    transparent = unb64(registration["transparent"])
    decoded = [cbor2.loads(item) for item in disclosures]
    selected = [
        encoded
        for encoded, item in zip(disclosures, decoded)
        if len(item) == 3 and item[2] in {0, 1001, 1002}
    ]
    header = dict(parts(transparent)[1])
    header[SD_CLAIMS] = selected
    presented = with_uhdr(redacted, header)
    audience = "https://researcher.example/verifier"
    message = Sign1Message(
        phdr={Algorithm: Es256, 13: cbor2.loads(presented), 16: 294},
        uhdr={},
        payload=cbor({3: audience, 6: int(time.time())}),
    )
    message.key = private_cose(state.msrc_key)
    kbt = message.encode(tag=True)

    result = mock_verifier(KbtBody(token=b64(kbt), audience=audience))
    assert result["txid"] == registration["txid"]
    assert result["fields"] == [1001, 1002]
    detailed = verify_bundle(kbt, audience)
    assert detailed["valid"]
    assert {check["status"] for check in detailed["checks"]} == {"pass", "unavailable"}
    assert detailed["report"]["fields"]["title"] == "private title"
    assert detailed["report"]["body"]["chunks"][0] == "Café\n1"
    assert all(chunk is None for chunk in detailed["report"]["body"]["chunks"][1:])
    with pytest.raises(HTTPException):
        mock_verifier(KbtBody(token=b64(kbt), audience="https://wrong.example"))
    assert not verify_bundle(kbt, "https://wrong.example")["valid"]

    attacker = ec.generate_private_key(ec.SECP256R1())
    forged = Sign1Message(
        phdr={Algorithm: Es256, 13: cbor2.loads(presented), 16: 294},
        uhdr={},
        payload=cbor({3: audience, 6: int(time.time())}),
    )
    forged.key = private_cose(attacker)
    with pytest.raises(HTTPException):
        mock_verifier(KbtBody(token=b64(forged.encode(tag=True)), audience=audience))