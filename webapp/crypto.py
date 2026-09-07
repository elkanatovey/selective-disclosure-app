from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import cbor2
from cbor2 import CBORTag
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pycose.algorithms import Es256
from pycose.headers import Algorithm
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

import sd_cwt

from .report import check_headers, check_payload, resolve_selected

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


def verify_statement(
    token: bytes | sd_cwt.ParsedToken,
    ca: x509.Certificate,
    issuer: str,
    holder_key: ec.EllipticCurvePublicKey | None = None,
) -> sd_cwt.VerifiedToken:
    parsed = token if isinstance(token, sd_cwt.ParsedToken) else sd_cwt.ParsedToken.decode(token)
    protected = parsed.protected
    check_headers(protected)
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
    verified = sd_cwt.verify(parsed, public_cose(leaf.public_key()))
    payload = verified.payload
    cwt = protected.get(15, {})
    if cwt.get(1) != issuer or payload.get(1) != issuer:
        raise ValueError("unexpected issuer")
    public_key_from_cnf(payload.get(8))
    if holder_key is not None and payload[8] != {1: public_cose_map(holder_key)}:
        raise ValueError("statement is bound to a different holder key")
    check_payload(payload)
    return verified


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
    statement: bytes | sd_cwt.ParsedToken,
    trust: ReceiptTrust,
) -> dict[str, Any]:
    if isinstance(statement, sd_cwt.ParsedToken):
        header, statement = statement.unprotected, statement.encoded
    else:
        header = parts(statement)[1]
    receipts = header.get(SCITT_RECEIPTS, [])
    if len(receipts) != 1:
        raise ValueError("SCITT receipt is missing")
    bare = with_uhdr(statement, {})
    txid = verify_standalone_receipt(receipt_bytes(receipts[0]), bare, trust)
    return {"txid": txid, "merkle": trust.merkle}


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
