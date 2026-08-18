from __future__ import annotations

import base64
import csv
import hashlib
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import cbor2
from cbor2 import CBORSimpleValue, CBORTag
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pycose.algorithms import Es256
from pycose.headers import Algorithm
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

ROOT = Path(__file__).parent
RCK = CBORSimpleValue(59)
SD_CLAIMS = 17
SCITT_RECEIPTS = 394


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
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
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


def parts(token: bytes) -> list[Any]:
    tagged = cbor2.loads(token)
    if not isinstance(tagged, CBORTag) or tagged.tag != 18:
        raise ValueError("expected tagged COSE Sign1")
    return list(tagged.value)


def with_uhdr(token: bytes, header: dict[Any, Any]) -> bytes:
    value = parts(token)
    value[1] = header
    return cbor(CBORTag(18, value))


class State:
    def __init__(self) -> None:
        self.governance_key = ec.generate_private_key(ec.SECP256R1())
        self.governance_cert = cert(
            "Mock SCITT Governance",
            self.governance_key.public_key(),
            self.governance_key,
        )
        root_hash = self.governance_cert.fingerprint(hashes.SHA256())
        self.issuer = f"did:x509:0:sha256:{b64(root_hash)}::subject:CN:Web Statement Issuer"
        self.msrc_key = ec.generate_private_key(ec.SECP256R1())
        self.scitt_key = ec.generate_private_key(ec.SECP256R1())
        self.inbox: list[dict[str, Any]] = []
        self.seqno = 0
        with (ROOT / "parties.csv").open(newline="") as handle:
            self.parties = list(csv.DictReader(handle))

    @property
    def msrc_cnf(self) -> dict[int, Any]:
        return {1: public_cose_map(self.msrc_key.public_key())}

    @property
    def msrc_kid(self) -> str:
        pem = self.msrc_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(pem).hexdigest()[:16]


state = State()
app = FastAPI(title="Bug Report Submission")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


class EndorseBody(BaseModel):
    public_jwk: dict[str, str]


class TokenBody(BaseModel):
    token: str


class DeliveryBody(BaseModel):
    statement: str


def verify_issuer(token: bytes) -> dict[Any, Any]:
    value = parts(token)
    protected = cbor2.loads(value[0])
    if protected.get(16) != 293 or protected.get(170) != -16:
        raise ValueError("not the expected SD-CWT profile")
    chain = protected.get(33)
    if not isinstance(chain, list) or len(chain) != 2:
        raise ValueError("missing issuer certificate chain")
    if chain[1] != state.governance_cert.public_bytes(serialization.Encoding.DER):
        raise ValueError("issuer is not endorsed by governance")
    leaf = x509.load_der_x509_certificate(chain[0])
    state.governance_cert.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
    )
    message = Sign1Message.decode(token)
    message.key = public_cose(leaf.public_key())
    if not message.verify_signature():
        raise ValueError("invalid statement signature")
    payload = cbor2.loads(message.payload)
    cwt = protected.get(15, {})
    if cwt.get(1) != state.issuer or payload.get(1) != state.issuer:
        raise ValueError("unexpected issuer")
    if payload.get(8) != state.msrc_cnf:
        raise ValueError("unexpected issuer or confirmation key")
    if set(payload) != {1, 6, 8, RCK} or len(payload[RCK]) != 9:
        raise ValueError("statement does not have the uniform report shape")
    return payload


def receipt(token: bytes, txid: str) -> bytes:
    message = Sign1Message(
        phdr={Algorithm: Es256, 4: hashlib.sha256(b"mock-scitt").digest()[:8]},
        uhdr={},
        payload=cbor(
            {1: "mock-scitt", 2: hashlib.sha256(token).digest(), 3: txid, 6: int(time.time())}
        ),
    )
    message.key = private_cose(state.scitt_key)
    return message.encode(tag=True)


def resolve_all(payload: dict[Any, Any], presented: list[bytes]) -> dict[int, Any]:
    openings = {hashlib.sha256(cbor(item)).digest(): cbor2.loads(item) for item in presented}
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


def verify_receipt(statement: bytes) -> str:
    value = parts(statement)
    receipts = value[1].get(SCITT_RECEIPTS, [])
    if len(receipts) != 1:
        raise ValueError("SCITT receipt is missing")
    encoded = cbor(receipts[0])
    message = Sign1Message.decode(encoded)
    message.key = public_cose(state.scitt_key.public_key())
    if not message.verify_signature():
        raise ValueError("invalid SCITT receipt")
    claims = cbor2.loads(message.payload)
    if claims.get(2) != hashlib.sha256(with_uhdr(statement, {})).digest():
        raise ValueError("receipt does not bind this statement")
    return claims[3]


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/state")
def get_state() -> dict[str, Any]:
    point = state.msrc_key.public_key().public_numbers()
    return {
        "parties": state.parties,
        "issuer": state.issuer,
        "msrcKid": state.msrc_kid,
        "msrcJwk": {"kty": "EC", "crv": "P-256", "x": b64(point.x.to_bytes(32, "big")), "y": b64(point.y.to_bytes(32, "big"))},
    }


@app.post("/mock/governance/endorse")
def endorse(body: EndorseBody) -> dict[str, Any]:
    try:
        jwk = body.public_jwk
        if "d" in jwk:
            raise ValueError("governance accepts public keys only")
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            raise ValueError("expected a P-256 public JWK")
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(unb64(jwk["x"]), "big"),
            int.from_bytes(unb64(jwk["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        leaf = cert("Web Statement Issuer", public_key, state.governance_key, state.governance_cert)
        return {
            "issuer": state.issuer,
            "serial": hex(leaf.serial_number)[2:14],
            "leaf": b64(leaf.public_bytes(serialization.Encoding.DER)),
            "root": b64(state.governance_cert.public_bytes(serialization.Encoding.DER)),
        }
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/mock/scitt")
def mock_scitt(body: TokenBody) -> dict[str, Any]:
    try:
        token = unb64(body.token)
        payload = verify_issuer(token)
        if parts(token)[1]:
            raise ValueError("SCITT only accepts the fully redacted envelope")
        state.seqno += 1
        txid = f"1.{state.seqno}"
        transparent = with_uhdr(token, {SCITT_RECEIPTS: [cbor2.loads(receipt(token, txid))]})
        return {"txid": txid, "transparent": b64(transparent), "bytes": len(transparent)}
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/mock/msrc")
def mock_msrc(body: DeliveryBody) -> dict[str, Any]:
    try:
        statement = unb64(body.statement)
        payload = verify_issuer(statement)
        txid = verify_receipt(statement)
        fields = resolve_all(payload, parts(statement)[1].get(SD_CLAIMS, []))
        item = {
            "txid": txid,
            "fields": len(fields),
            "digest": hashlib.sha256(statement).hexdigest()[:16],
        }
        state.inbox.insert(0, item)
        return item
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8090)