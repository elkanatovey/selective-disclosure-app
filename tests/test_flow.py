import hashlib
import secrets
import time
import unicodedata
from dataclasses import dataclass

import cbor2
import pytest
import sd_cwt
from cbor2 import CBORTag
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pycose.algorithms import Es256
from pycose.headers import Algorithm
from pycose.messages import Sign1Message

import webapp.mock_scitt as mock_scitt_service
import webapp.msrc as msrc_service
import webapp.researcher as researcher_service
import webapp.verifier as verifier_service
from webapp.crypto import (
    RCK,
    SCITT_RECEIPTS,
    SD_CLAIMS,
    ReceiptTrust,
    b64,
    cbor,
    cert,
    create_mock_receipt,
    issuer_for_ca,
    parts,
    private_cose,
    public_cose_map,
    public_cose,
    public_jwk,
    resolve_all,
    sign_kbt,
    verify_bundle,
    verify_issuer,
    verify_standalone_receipt,
    verify_transparent_statement,
    with_uhdr,
)


@dataclass
class Authority:
    ca_key: ec.EllipticCurvePrivateKey
    ca_cert: x509.Certificate
    holder_key: ec.EllipticCurvePrivateKey
    issuer: str


def authority() -> Authority:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = cert("MSRC Researcher CA", ca_key.public_key(), ca_key)
    return Authority(
        ca_key=ca_key,
        ca_cert=ca_cert,
        holder_key=ec.generate_private_key(ec.SECP256R1()),
        issuer=issuer_for_ca(ca_cert),
    )


def opening(value, key=None):
    item = [secrets.token_bytes(16), value]
    if key is not None:
        item.append(key)
    encoded = cbor(item)
    return encoded, hashlib.sha256(cbor(encoded)).digest()


def browser_style_report(owner: Authority):
    signer = ec.generate_private_key(ec.SECP256R1())
    leaf = cert("Web Statement Issuer", signer.public_key(), owner.ca_key, owner.ca_cert)
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
    issued_at = int(time.time())
    protected = cbor(
        {
            1: -7,
            3: "application/sd-cwt",
            15: {1: owner.issuer, 2: "case-1", 6: issued_at},
            16: 293,
            33: [
                leaf.public_bytes(serialization.Encoding.DER),
                owner.ca_cert.public_bytes(serialization.Encoding.DER),
            ],
            170: -16,
        }
    )
    payload = cbor(
        {
            1: owner.issuer,
            6: issued_at,
            8: {1: public_cose_map(owner.holder_key.public_key())},
            RCK: sorted(digests),
        }
    )
    message = Sign1Message(phdr_encoded=protected, uhdr={}, payload=payload)
    message.key = private_cose(signer)
    return message.encode(tag=True), disclosures, body, leaf


def transparent_statement(owner: Authority):
    redacted, disclosures, body, leaf = browser_style_report(owner)
    scitt_key = ec.generate_private_key(ec.SECP256R1())
    txid = "1.7"
    receipt = create_mock_receipt(redacted, txid, scitt_key)
    transparent = with_uhdr(redacted, {SCITT_RECEIPTS: [cbor2.loads(receipt)]})
    trust = ReceiptTrust(mock_key=scitt_key.public_key())
    return redacted, disclosures, body, leaf, receipt, transparent, trust, txid


def test_report_and_receipts_round_trip_without_shared_state():
    owner = authority()
    redacted, disclosures, body, _, receipt, transparent, trust, txid = transparent_statement(owner)
    payload = verify_issuer(redacted, owner.ca_cert, owner.issuer, owner.holder_key.public_key())
    assert set(payload) == {1, 6, 8, RCK}
    assert len(payload[RCK]) == 9
    assert b"private title" not in redacted
    assert verify_standalone_receipt(receipt, redacted, trust) == txid
    assert verify_transparent_statement(transparent, trust) == {"txid": txid, "merkle": False}

    header = dict(parts(transparent)[1])
    header[SD_CLAIMS] = disclosures
    full = with_uhdr(redacted, header)
    assert resolve_all(payload, disclosures)[1002] == body
    assert all(parts(full)[index] == parts(redacted)[index] for index in (0, 2, 3))

    foreign = authority()
    with pytest.raises(ValueError, match="MSRC CA"):
        verify_issuer(redacted, foreign.ca_cert, foreign.issuer)


def test_verifier_uses_cnf_and_rejects_wrong_audience_or_key():
    owner = authority()
    redacted, disclosures, _, _, _, transparent, trust, txid = transparent_statement(owner)
    decoded = [cbor2.loads(item) for item in disclosures]
    selected = [
        encoded
        for encoded, item in zip(disclosures, decoded)
        if len(item) == 3 and item[2] in {0, 1001, 1002}
    ]
    audience = "https://researcher.example/verifier"
    full = with_uhdr(redacted, {**parts(transparent)[1], SD_CLAIMS: disclosures})
    kbt = sign_kbt(full, selected, owner.holder_key, audience)

    leaf = x509.load_der_x509_certificate(cbor2.loads(parts(redacted)[0])[33][0])
    reference = sd_cwt.kbt_verify(
        kbt,
        public_cose(leaf.public_key()),
        expected_aud=audience,
    )
    assert set(reference.claims.disclosed) == {1001, 1002}

    result = verify_bundle(kbt, audience, owner.ca_cert, owner.issuer, trust)
    assert result["valid"]
    assert result["report"]["txid"] == txid
    assert result["report"]["fields"]["title"] == "private title"
    assert result["report"]["body"]["chunks"][0] == "Café\n1"
    assert not verify_bundle(kbt, "https://wrong.example", owner.ca_cert, owner.issuer, trust)["valid"]

    presented = cbor2.loads(parts(kbt)[0])[13]
    forged = Sign1Message(
        phdr={Algorithm: Es256, 13: presented, 16: 294},
        uhdr={},
        payload=cbor({3: audience, 6: int(time.time())}),
    )
    forged.key = private_cose(ec.generate_private_key(ec.SECP256R1()))
    forged_result = verify_bundle(
        forged.encode(tag=True), audience, owner.ca_cert, owner.issuer, trust
    )
    assert not forged_result["valid"]
    assert next(
        check for check in forged_result["checks"] if check["name"] == "KBT proof and audience"
    )["status"] == "fail"


def test_researcher_completion_requires_verified_receipts(monkeypatch):
    owner = authority()
    redacted, _, _, _, receipt, transparent, trust, txid = transparent_statement(owner)

    class Upstream:
        def __init__(self, status_code, content=b"", headers=None):
            self.status_code = status_code
            self.content = content
            self.headers = headers or {}
            self.text = ""
            self.reason = ""

    monkeypatch.setattr(researcher_service, "receipt_trust", lambda: trust)
    monkeypatch.setattr(
        researcher_service.requests,
        "post",
        lambda *args, **kwargs: Upstream(
            201,
            receipt,
            {"x-ms-ccf-transaction-id": txid},
        ),
    )
    monkeypatch.setattr(
        researcher_service.requests,
        "get",
        lambda *args, **kwargs: Upstream(200, transparent),
    )
    researcher_service.state.entries.clear()
    client = TestClient(researcher_service.app)
    registered = client.post(
        "/entries?waitForCommit=true",
        content=redacted,
        headers={"content-type": "application/cose"},
    )
    assert registered.status_code == 201
    assert registered.headers["x-receipt-verified"] == "true"
    fetched = client.get(f"/entries/{txid}/statement")
    assert fetched.status_code == 200
    assert fetched.headers["x-receipt-verified"] == "true"

    damaged = bytearray(receipt)
    damaged[-1] ^= 1
    monkeypatch.setattr(
        researcher_service.requests,
        "post",
        lambda *args, **kwargs: Upstream(
            201,
            bytes(damaged),
            {"x-ms-ccf-transaction-id": txid},
        ),
    )
    rejected = client.post(
        "/entries?waitForCommit=true",
        content=redacted,
        headers={"content-type": "application/cose"},
    )
    assert rejected.status_code == 400
    assert "x-receipt-verified" not in rejected.headers


def test_apps_have_distinct_routes_and_private_state():
    routes = lambda service: {route.path for route in service.app.routes}
    researcher_routes = routes(researcher_service)
    msrc_routes = routes(msrc_service)
    verifier_routes = routes(verifier_service)
    scitt_routes = routes(mock_scitt_service)

    assert "/entries" in researcher_routes
    assert "/api/verify" not in researcher_routes
    assert "/deliveries" not in researcher_routes
    assert "/deliveries" in msrc_routes
    assert "/api/disclosures" in msrc_routes
    assert "/entries" not in msrc_routes
    assert "/api/verify" in verifier_routes
    assert "/entries" not in verifier_routes
    assert "/entries" in scitt_routes
    assert "/mock/msrc/key" not in msrc_routes

    assert set(vars(researcher_service.state)) == {"entries"}
    assert not hasattr(verifier_service, "state")
    public = msrc_service.public_state()
    assert set(public["msrcJwk"]) == {"kty", "crv", "x", "y"}
    assert "d" not in public["msrcJwk"]


def test_endorsed_chain_has_scitt_didx509_extensions():
    owner = authority()
    _, _, _, leaf = browser_style_report(owner)
    assert owner.ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert owner.ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    for certificate in (owner.ca_cert, leaf):
        certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)