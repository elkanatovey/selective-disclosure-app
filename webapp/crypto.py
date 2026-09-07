from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import cbor2
from cbor2 import CBORSimpleValue, CBORTag
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pycose.algorithms import Es256
from pycose.headers import Algorithm
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

import sd_cwt
from sd_cwt.statement import BODY, CONTENT_FIELDS, NAME_BY_FIELD, PARENT, REFERENCES

RCK = CBORSimpleValue(59)
SD_CLAIMS = 17
SCITT_RECEIPTS = 394


@dataclass(frozen=True)
class ReceiptTrust:
    real_ca: x509.Certificate | None = None
    mock_key: ec.EllipticCurvePublicKey | None = None

    @property
    def merkle(self) -> bool:
        return self.real_ca is not None


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def cbor(value: Any) -> bytes:
    return cbor2.dumps(value, canonical=True)


def cert(
    name: str,
    public_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey,
    issuer: x509.Certificate | None = None,
) -> x509.Certificate:
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    ca = issuer is None
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject if ca else issuer.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650 if ca else 30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer.public_key() if issuer is not None else public_key
            ),
            False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=None,
                decipher_only=None,
            ),
            True,
        )
        .sign(signing_key, hashes.SHA256())
    )


def private_cose(key: ec.EllipticCurvePrivateKey) -> CoseKey:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return CoseKey.from_pem_private_key(pem.decode())


def public_cose(key: ec.EllipticCurvePublicKey) -> CoseKey:
    pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return CoseKey.from_pem_public_key(pem.decode())


def public_cose_map(key: ec.EllipticCurvePublicKey) -> dict[int, Any]:
    point = key.public_numbers()
    return {
        1: 2,
        3: -7,
        -1: 1,
        -2: point.x.to_bytes(32, "big"),
        -3: point.y.to_bytes(32, "big"),
    }


def public_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    point = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64(point.x.to_bytes(32, "big")),
        "y": b64(point.y.to_bytes(32, "big")),
    }


def public_key_from_jwk(jwk: dict[str, str]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("expected a P-256 public JWK")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(unb64(jwk["x"]), "big"),
        int.from_bytes(unb64(jwk["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()


def public_key_from_cnf(cnf: Any) -> ec.EllipticCurvePublicKey:
    if not isinstance(cnf, dict) or not isinstance(cnf.get(1), dict):
        raise ValueError("cnf claim is missing its COSE key")
    key = cnf[1]
    if key.get(1) != 2 or key.get(-1) != 1:
        raise ValueError("cnf confirmation key is not P-256 EC2")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(key[-2], "big"),
        int.from_bytes(key[-3], "big"),
        ec.SECP256R1(),
    ).public_key()


def parts(token: bytes) -> list[Any]:
    tagged = cbor2.loads(token)
    if not isinstance(tagged, CBORTag) or tagged.tag != 18:
        raise ValueError("expected tagged COSE Sign1")
    return list(tagged.value)


def with_uhdr(token: bytes, header: dict[Any, Any]) -> bytes:
    value = parts(token)
    value[1] = header
    return cbor(CBORTag(18, value))


def issuer_for_ca(ca: x509.Certificate) -> str:
    root_hash = ca.fingerprint(hashes.SHA256())
    return f"did:x509:0:sha256:{b64(root_hash)}::subject:CN:Web Statement Issuer"


def verify_issuer(
    token: bytes,
    ca: x509.Certificate,
    issuer: str,
    holder_key: ec.EllipticCurvePublicKey | None = None,
) -> dict[Any, Any]:
    value = parts(token)
    protected = cbor2.loads(value[0])
    if protected.get(1) != -7 or protected.get(16) != 293 or protected.get(170) != -16:
        raise ValueError("not the expected SD-CWT profile")
    chain = protected.get(33)
    if not isinstance(chain, list) or len(chain) != 2:
        raise ValueError("missing issuer certificate chain")
    if chain[1] != ca.public_bytes(serialization.Encoding.DER):
        raise ValueError("issuer is not endorsed by the MSRC CA")
    leaf = x509.load_der_x509_certificate(chain[0])
    now = datetime.now(UTC)
    if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
        raise ValueError("issuer certificate is outside its validity period")
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("issuer leaf certificate must not be a CA")
    if leaf.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Web Statement Issuer")]):
        raise ValueError("issuer certificate subject does not match did:x509")
    ca.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        ec.ECDSA(leaf.signature_hash_algorithm),
    )
    verified = sd_cwt.verify(token, public_cose(leaf.public_key()))
    payload = verified.payload
    cwt = protected.get(15, {})
    if cwt.get(1) != issuer or payload.get(1) != issuer:
        raise ValueError("unexpected issuer")
    public_key_from_cnf(payload.get(8))
    if holder_key is not None and payload[8] != {1: public_cose_map(holder_key)}:
        raise ValueError("statement is bound to a different holder key")
    if set(payload) != {1, 6, 8, RCK} or len(payload[RCK]) != len(CONTENT_FIELDS):
        raise ValueError("statement does not have the uniform report shape")
    return payload


def create_mock_receipt(
    token: bytes,
    txid: str,
    signing_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    message = Sign1Message(
        phdr={Algorithm: Es256, 4: hashlib.sha256(b"mock-scitt").digest()[:8]},
        uhdr={},
        payload=cbor(
            {
                1: "mock-scitt",
                2: hashlib.sha256(token).digest(),
                3: txid,
                6: int(time.time()),
            }
        ),
    )
    message.key = private_cose(signing_key)
    return message.encode(tag=True)


def receipt_bytes(receipt: Any) -> bytes:
    return receipt if isinstance(receipt, bytes) else cbor(receipt)


def registration_txid(receipt: bytes) -> str:
    value = parts(receipt)
    for encoded in value[1].get(396, {}).get(-1, []):
        evidence = cbor2.loads(encoded).get(1, [None, ""])[1]
        if isinstance(evidence, str) and evidence.startswith("ce:"):
            return evidence.split(":", 2)[1]
    raise ValueError("receipt has no registration transaction ID")


def verify_standalone_receipt(
    receipt: bytes,
    statement: bytes,
    trust: ReceiptTrust,
) -> str:
    protected = cbor2.loads(parts(receipt)[0])
    if protected.get(1) not in {-7, -35}:
        raise ValueError("unsupported receipt algorithm")
    digest = hashlib.sha256(statement).digest()
    if trust.real_ca is not None:
        import ccf.cose

        ccf.cose.verify_receipt(receipt, trust.real_ca.public_key(), digest)
        return registration_txid(receipt)
    if trust.mock_key is None:
        raise ValueError("SCITT receipt trust is not configured")
    message = Sign1Message.decode(receipt)
    message.key = public_cose(trust.mock_key)
    if not message.verify_signature():
        raise ValueError("invalid SCITT receipt")
    claims = cbor2.loads(message.payload)
    if claims.get(2) != digest:
        raise ValueError("receipt does not bind this statement")
    return claims[3]


def verify_transparent_statement(
    statement: bytes,
    trust: ReceiptTrust,
) -> dict[str, Any]:
    value = parts(statement)
    receipts = value[1].get(SCITT_RECEIPTS, [])
    if len(receipts) != 1:
        raise ValueError("SCITT receipt is missing")
    bare = with_uhdr(statement, {})
    txid = verify_standalone_receipt(receipt_bytes(receipts[0]), bare, trust)
    return {"txid": txid, "merkle": trust.merkle}


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


def sign_kbt(
    statement: bytes,
    selected: list[bytes],
    holder_key: ec.EllipticCurvePrivateKey,
    audience: str,
) -> bytes:
    if not audience.strip():
        raise ValueError("audience is required")
    if not selected:
        raise ValueError("select at least one disclosure")
    value = parts(statement)
    payload = cbor2.loads(value[2])
    expected = public_key_from_cnf(payload.get(8)).public_numbers()
    if expected != holder_key.public_key().public_numbers():
        raise ValueError("signing key does not match the statement cnf")
    resolve_selected(payload, selected)
    disclosures = [sd_cwt.Disclosure(salt=b"", value=None, encoded=encoded) for encoded in selected]
    return sd_cwt.kbt_sign(
        statement,
        disclosures,
        private_cose(holder_key),
        aud=audience.strip(),
        iat=int(time.time()),
    )


def describe_selected(
    payload: dict[Any, Any],
    presented: list[bytes],
    *,
    selected: dict[int, Any] | None = None,
) -> dict[str, Any]:
    if selected is None:
        selected = resolve_selected(payload, presented)
    fields = {}
    for key, name in NAME_BY_FIELD.items():
        if key in (PARENT, BODY, REFERENCES):
            continue
        value = selected.get(key)
        fields[name] = value.hex() if isinstance(value, bytes) else value
    body = selected.get(BODY)
    if isinstance(body, dict):
        openings = {hashlib.sha256(cbor(item)).digest(): cbor2.loads(item) for item in presented}
        count = 0
        for digest in payload[RCK]:
            opening = openings.get(digest)
            if opening is not None and len(opening) == 3 and opening[2] == BODY:
                count = len(opening[1].get(RCK, []))
                break
        body_view = {"known": True, "chunks": [body.get(index) for index in range(count)]}
    else:
        body_view = {"known": False, "chunks": []}
    return {
        "fields": fields,
        "body": body_view,
        "references": selected.get(REFERENCES),
    }


def verify_bundle(
    token: bytes,
    audience: str,
    ca: x509.Certificate,
    issuer: str,
    receipt_trust: ReceiptTrust,
) -> dict[str, Any]:
    checks = []

    def result(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    try:
        value = parts(token)
        protected = cbor2.loads(value[0])
        if (
            protected.get(1) != -7
            or protected.get(16) != 294
            or not isinstance(protected.get(13), CBORTag)
        ):
            raise ValueError("expected ES256 application/kb+cwt with kcwt")
        statement = cbor(protected[13])
        statement_value = parts(statement)
        statement_protected = cbor2.loads(statement_value[0])
        receipts = statement_value[1].get(SCITT_RECEIPTS, [])
        if (
            statement_protected.get(1) != -7
            or statement_protected.get(16) != 293
            or statement_protected.get(170) != -16
        ):
            raise ValueError("embedded statement algorithms/profile are unsupported")
        if len(receipts) != 1:
            raise ValueError("SCITT receipt is missing")
        receipt_algorithm = cbor2.loads(parts(receipt_bytes(receipts[0]))[0]).get(1)
        if receipt_algorithm not in {-7, -35}:
            raise ValueError("receipt algorithm/profile is unsupported")
        result(
            "COSE envelopes and algorithms",
            "pass",
            "KBT, SD-CWT, and receipt use the expected profiles",
        )
    except Exception as exc:
        result("COSE envelopes and algorithms", "fail", str(exc))
        for name in (
            "Issuer trust and signature",
            "SCITT receipt",
            "KBT proof and audience",
            "Disclosure consistency",
        ):
            result(name, "skipped", "Blocked by invalid envelope structure")
        result("SCITT Merkle inclusion", "unavailable", "Receipt was not inspected")
        return {"valid": False, "checks": checks, "report": None}

    payload = None
    receipt_info = None
    kbt_result = None
    report = None
    try:
        payload = verify_issuer(statement, ca, issuer)
        result(
            "Issuer trust and signature",
            "pass",
            "MSRC CA, did:x509 identity, schema, and issuer signature verified",
        )
    except Exception as exc:
        result("Issuer trust and signature", "fail", str(exc))
    try:
        receipt_info = verify_transparent_statement(statement, receipt_trust)
        result(
            "SCITT receipt",
            "pass",
            "Service signature and exact statement digest verified",
        )
    except Exception as exc:
        result("SCITT receipt", "fail", str(exc))
    try:
        if payload is None:
            raise ValueError("issuer payload is not trusted")
        leaf = x509.load_der_x509_certificate(statement_protected[33][0])
        verified_kbt = sd_cwt.kbt_verify(
            token,
            public_cose(leaf.public_key()),
            expected_aud=audience,
        )
        claims = verified_kbt.kbt_claims or {}
        if not isinstance(claims.get(6), int):
            raise ValueError("KBT claims are invalid")
        now = int(time.time())
        if claims[6] > now + 60 or claims[6] < now - 3600:
            raise ValueError("KBT iat is outside the verifier window")
        if 5 in claims and now < claims[5]:
            raise ValueError("KBT is not yet valid")
        if 4 in claims and now >= claims[4]:
            raise ValueError("KBT has expired")
        kbt_result = verified_kbt
        result(
            "KBT proof and audience",
            "pass",
            "cnf proof-of-possession, audience, and iat verified",
        )
    except Exception as exc:
        result("KBT proof and audience", "fail", str(exc))
    try:
        if kbt_result is None:
            raise ValueError("KBT is not trusted")
        presented = statement_value[1].get(SD_CLAIMS, [])
        selected = kbt_result.claims.disclosed
        if not set(selected).issubset(CONTENT_FIELDS):
            raise ValueError("disclosed fields are outside the report schema")
        report = describe_selected(payload, presented, selected=selected)
        report.update(
            {
                "subject": statement_protected.get(15, {}).get(2, ""),
                "txid": receipt_info["txid"] if receipt_info else None,
                "audience": audience,
            }
        )
        result(
            "Disclosure consistency",
            "pass",
            "All presented openings match reachable hashes and the report schema",
        )
    except Exception as exc:
        result("Disclosure consistency", "fail", str(exc))
    if not receipt_trust.merkle:
        result("SCITT Merkle inclusion", "unavailable", "The mock receipt has no Merkle proof")
    elif receipt_info is None:
        result("SCITT Merkle inclusion", "skipped", "Blocked by invalid SCITT receipt")
    else:
        result("SCITT Merkle inclusion", "pass", "CCF Merkle inclusion proof verified")
    return {
        "valid": all(check["status"] in {"pass", "unavailable"} for check in checks),
        "checks": checks,
        "report": report,
    }
