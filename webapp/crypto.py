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
    if leaf.subject != x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Web Statement Issuer")]
    ):
        raise ValueError("issuer certificate subject does not match did:x509")
    ca.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        ec.ECDSA(leaf.signature_hash_algorithm),
    )
    message = Sign1Message.decode(token)
    message.key = public_cose(leaf.public_key())
    if not message.verify_signature():
        raise ValueError("invalid statement signature")
    payload = cbor2.loads(message.payload)
    cwt = protected.get(15, {})
    if cwt.get(1) != issuer or payload.get(1) != issuer:
        raise ValueError("unexpected issuer")
    public_key_from_cnf(payload.get(8))
    if holder_key is not None and payload[8] != {1: public_cose_map(holder_key)}:
        raise ValueError("statement is bound to a different holder key")
    if set(payload) != {1, 6, 8, RCK} or len(payload[RCK]) != 9:
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
    openings = {
        hashlib.sha256(cbor(item)).digest(): cbor2.loads(item) for item in presented
    }

    def resolve(value: Any) -> Any:
        if isinstance(value, dict):
            hashes = value.get(RCK)
            if hashes is None:
                return {key: resolve(item) for key, item in value.items()}
            result = {}
            for digest in hashes:
                opening = openings.get(digest)
                if opening is None or len(opening) != 3:
                    raise ValueError("map disclosure is missing")
                _, item, key = opening
                if key in result:
                    raise ValueError("duplicate disclosed map key")
                result[key] = resolve(item)
            return result
        if isinstance(value, list):
            result = []
            for item in value:
                if isinstance(item, CBORTag) and item.tag == 60:
                    opening = openings.get(item.value)
                    if opening is None or len(opening) != 2:
                        raise ValueError("array disclosure is missing")
                    result.append(resolve(opening[1]))
                else:
                    result.append(resolve(item))
            return result
        return value

    result: dict[int, Any] = {}
    for digest in payload.get(RCK, []):
        if digest not in openings:
            raise ValueError("field disclosure is missing")
        _, value, field = openings[digest]
        result[field] = resolve(value)
    if set(result) != set(range(1000, 1009)):
        raise ValueError("disclosures do not match the report schema")
    if isinstance(result[1002], dict):
        chunks = result[1002]
        if sorted(chunks) != list(range(len(chunks))) or not all(
            isinstance(chunk, str) for chunk in chunks.values()
        ):
            raise ValueError("body chunks are invalid")
        result[1002] = "".join(chunks[index] for index in range(len(chunks)))
    return result


def resolve_selected(payload: dict[Any, Any], presented: list[bytes]) -> dict[int, Any]:
    openings = {}
    for encoded in presented:
        digest = hashlib.sha256(cbor(encoded)).digest()
        if digest in openings:
            raise ValueError("duplicate disclosure")
        openings[digest] = cbor2.loads(encoded)
    used = set()

    def resolve(value: Any) -> Any:
        if isinstance(value, dict) and RCK in value:
            result = {}
            for digest in value[RCK]:
                opening = openings.get(digest)
                if opening is not None:
                    used.add(digest)
                    _, item, key = opening
                    result[key] = resolve(item)
            return result
        if isinstance(value, list):
            result = []
            for item in value:
                if isinstance(item, CBORTag) and item.tag == 60:
                    opening = openings.get(item.value)
                    if opening is not None:
                        used.add(item.value)
                        result.append(resolve(opening[1]))
                else:
                    result.append(resolve(item))
            return result
        return value

    result = {}
    for digest in payload[RCK]:
        opening = openings.get(digest)
        if opening is not None:
            used.add(digest)
            _, value, field = opening
            result[field] = resolve(value)
    if used != set(openings):
        raise ValueError("unmatched disclosure")
    return result


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
    headers = dict(value[1])
    headers[SD_CLAIMS] = selected
    presented = CBORTag(18, [value[0], headers, value[2], value[3]])
    message = Sign1Message(
        phdr={Algorithm: Es256, 13: presented, 16: 294},
        uhdr={},
        payload=cbor({3: audience.strip(), 6: int(time.time())}),
    )
    message.key = private_cose(holder_key)
    return message.encode(tag=True)


def describe_selected(payload: dict[Any, Any], presented: list[bytes]) -> dict[str, Any]:
    selected = resolve_selected(payload, presented)
    names = {
        1001: "title",
        1003: "component",
        1004: "severity",
        1005: "fingerprint",
        1007: "patch",
        1008: "patch_date",
    }
    fields = {}
    for key, name in names.items():
        value = selected.get(key)
        fields[name] = None if value is None else (
            value.hex() if isinstance(value, bytes) else value
        )
    body = selected.get(1002)
    if isinstance(body, dict):
        openings = {
            hashlib.sha256(cbor(item)).digest(): cbor2.loads(item)
            for item in presented
        }
        count = 0
        for digest in payload[RCK]:
            opening = openings.get(digest)
            if opening is not None and len(opening) == 3 and opening[2] == 1002:
                count = len(opening[1].get(RCK, []))
                break
        body_view = {"known": True, "chunks": [body.get(index) for index in range(count)]}
    else:
        body_view = {"known": False, "chunks": []}
    return {
        "fields": fields,
        "body": body_view,
        "references": selected.get(1006),
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
    txid = None
    selected = None
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
        txid = receipt_info["txid"]
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
        message = Sign1Message.decode(token)
        message.key = public_cose(public_key_from_cnf(payload.get(8)))
        if not message.verify_signature():
            raise ValueError("signature does not match the cnf key")
        claims = cbor2.loads(value[2])
        if claims.get(3) != audience:
            raise ValueError("audience does not match")
        if 1 in claims or 2 in claims or not isinstance(claims.get(6), int):
            raise ValueError("KBT claims are invalid")
        now = int(time.time())
        if claims[6] > now + 60 or claims[6] < now - 3600:
            raise ValueError("KBT iat is outside the verifier window")
        if 5 in claims and now < claims[5]:
            raise ValueError("KBT is not yet valid")
        if 4 in claims and now >= claims[4]:
            raise ValueError("KBT has expired")
        result(
            "KBT proof and audience",
            "pass",
            "cnf proof-of-possession, audience, and iat verified",
        )
    except Exception as exc:
        result("KBT proof and audience", "fail", str(exc))
    try:
        if payload is None:
            raise ValueError("issuer payload is not trusted")
        presented = statement_value[1].get(SD_CLAIMS, [])
        selected = resolve_selected(payload, presented)
        if not set(selected).issubset(set(range(1000, 1009))):
            raise ValueError("disclosed fields are outside the report schema")
        result(
            "Disclosure consistency",
            "pass",
            "All presented openings match reachable hashes and the report schema",
        )
    except Exception as exc:
        result("Disclosure consistency", "fail", str(exc))
    if receipt_trust.merkle and "receipt_info" in locals():
        result("SCITT Merkle inclusion", "pass", "CCF Merkle inclusion proof verified")
    else:
        result("SCITT Merkle inclusion", "unavailable", "The mock receipt has no Merkle proof")
    report = None
    if payload is not None and selected is not None:
        report = describe_selected(payload, statement_value[1].get(SD_CLAIMS, []))
        report.update(
            {
                "subject": statement_protected.get(15, {}).get(2, ""),
                "txid": txid,
                "audience": audience,
            }
        )
    return {
        "valid": all(check["status"] in {"pass", "unavailable"} for check in checks),
        "checks": checks,
        "report": report,
    }