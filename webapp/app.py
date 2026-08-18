from __future__ import annotations

import base64
import csv
import hashlib
import os
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
REAL_SCITT_URL = os.getenv("SCITT_URL")
REAL_SCITT_CA = os.getenv("SCITT_CA")


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


class KbtBody(BaseModel):
    token: str
    audience: str


def real_scitt_config():
    if not REAL_SCITT_URL or not REAL_SCITT_CA:
        return None
    try:
        import ccf.cose
        import requests
    except ImportError as exc:
        raise RuntimeError("install the real-scitt optional dependencies") from exc
    ca = Path(REAL_SCITT_CA)
    key = x509.load_pem_x509_certificate(ca.read_bytes()).public_key()
    return requests, ccf.cose, ca, key


def receipt_bytes(receipt: Any) -> bytes:
    return receipt if isinstance(receipt, bytes) else cbor(receipt)


def registration_txid(receipt: bytes) -> str:
    value = parts(receipt)
    for encoded in value[1].get(396, {}).get(-1, []):
        evidence = cbor2.loads(encoded).get(1, [None, ""])[1]
        if isinstance(evidence, str) and evidence.startswith("ce:"):
            return evidence.split(":", 2)[1]
    raise ValueError("receipt has no registration transaction ID")


def verify_issuer(token: bytes) -> dict[Any, Any]:
    value = parts(token)
    protected = cbor2.loads(value[0])
    if protected.get(1) != -7 or protected.get(16) != 293 or protected.get(170) != -16:
        raise ValueError("not the expected SD-CWT profile")
    chain = protected.get(33)
    if not isinstance(chain, list) or len(chain) != 2:
        raise ValueError("missing issuer certificate chain")
    if chain[1] != state.governance_cert.public_bytes(serialization.Encoding.DER):
        raise ValueError("issuer is not endorsed by governance")
    leaf = x509.load_der_x509_certificate(chain[0])
    now = datetime.now(UTC)
    if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
        raise ValueError("issuer certificate is outside its validity period")
    if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("issuer leaf certificate must not be a CA")
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


def verify_receipt_details(statement: bytes) -> dict[str, Any]:
    value = parts(statement)
    receipts = value[1].get(SCITT_RECEIPTS, [])
    if len(receipts) != 1:
        raise ValueError("SCITT receipt is missing")
    encoded = receipt_bytes(receipts[0])
    receipt_protected = cbor2.loads(parts(encoded)[0])
    if receipt_protected.get(1) not in {-7, -35}:
        raise ValueError("unsupported receipt algorithm")
    if isinstance(receipts[0], bytes):
        config = real_scitt_config()
        if config is None:
            raise ValueError("real SCITT trust configuration is unavailable")
        _, cose, _, key = config
        cose.verify_receipt(encoded, key, hashlib.sha256(with_uhdr(statement, {})).digest())
        return {"txid": registration_txid(encoded), "merkle": True}
    message = Sign1Message.decode(encoded)
    message.key = public_cose(state.scitt_key.public_key())
    if not message.verify_signature():
        raise ValueError("invalid SCITT receipt")
    claims = cbor2.loads(message.payload)
    if claims.get(2) != hashlib.sha256(with_uhdr(statement, {})).digest():
        raise ValueError("receipt does not bind this statement")
    return {"txid": claims[3], "merkle": False}


def verify_receipt(statement: bytes) -> str:
    return verify_receipt_details(statement)["txid"]


def verify_kbt(token: bytes, audience: str) -> dict[str, Any]:
    value = parts(token)
    protected = cbor2.loads(value[0])
    if protected.get(1) != -7 or protected.get(16) != 294 or not isinstance(protected.get(13), CBORTag):
        raise ValueError("invalid key binding token")
    statement = cbor(protected[13])
    payload = verify_issuer(statement)
    txid = verify_receipt(statement)
    message = Sign1Message.decode(token)
    message.key = public_cose(state.msrc_key.public_key())
    if not message.verify_signature():
        raise ValueError("KBT signature does not match cnf")
    claims = cbor2.loads(value[2])
    if 1 in claims or 2 in claims or (6 not in claims and 7 not in claims):
        raise ValueError("invalid KBT claims")
    if claims.get(3) != audience:
        raise ValueError("KBT audience mismatch")
    selected = resolve_selected(payload, parts(statement)[1].get(SD_CLAIMS, []))
    return {"txid": txid, "fields": sorted(selected), "iat": claims.get(6)}


def describe_selected(payload: dict[Any, Any], presented: list[bytes]) -> dict[str, Any]:
    selected = resolve_selected(payload, presented)
    names = {1001: "title", 1003: "component", 1004: "severity", 1005: "fingerprint", 1007: "patch", 1008: "patch_date"}
    fields = {}
    for key, name in names.items():
        value = selected.get(key)
        fields[name] = None if value is None else (value.hex() if isinstance(value, bytes) else value)
    body = selected.get(1002)
    if isinstance(body, dict):
        openings = {hashlib.sha256(cbor(item)).digest(): cbor2.loads(item) for item in presented}
        count = 0
        for digest in payload[RCK]:
            opening = openings.get(digest)
            if opening is not None and len(opening) == 3 and opening[2] == 1002:
                count = len(opening[1].get(RCK, []))
                break
        body_view = {"known": True, "chunks": [body.get(index) for index in range(count)]}
    else:
        body_view = {"known": False, "chunks": []}
    return {"fields": fields, "body": body_view, "references": selected.get(1006)}


def verify_bundle(token: bytes, audience: str) -> dict[str, Any]:
    checks = []
    def result(name: str, status: str, detail: str):
        checks.append({"name": name, "status": status, "detail": detail})
    try:
        value = parts(token)
        protected = cbor2.loads(value[0])
        if protected.get(1) != -7 or protected.get(16) != 294 or not isinstance(protected.get(13), CBORTag):
            raise ValueError("expected ES256 application/kb+cwt with kcwt")
        statement = cbor(protected[13])
        statement_value = parts(statement)
        statement_protected = cbor2.loads(statement_value[0])
        receipt_value = statement_value[1].get(SCITT_RECEIPTS, [])
        if statement_protected.get(1) != -7 or statement_protected.get(16) != 293 or statement_protected.get(170) != -16:
            raise ValueError("embedded statement algorithms/profile are unsupported")
        if len(receipt_value) != 1 or cbor2.loads(parts(receipt_bytes(receipt_value[0]))[0]).get(1) not in {-7, -35}:
            raise ValueError("receipt algorithm/profile is unsupported")
        result("COSE envelopes and algorithms", "pass", "KBT, SD-CWT, and receipt use the expected ES256 profiles")
    except Exception as exc:
        result("COSE envelopes and algorithms", "fail", str(exc))
        for name in ("Issuer trust and signature", "SCITT receipt", "KBT proof and audience", "Disclosure consistency"):
            result(name, "skipped", "Blocked by invalid envelope structure")
        result("SCITT Merkle inclusion", "unavailable", "The mock receipt has no Merkle proof")
        return {"valid": False, "checks": checks, "report": None}
    payload = None
    txid = None
    selected = None
    try:
        payload = verify_issuer(statement)
        result("Issuer trust and signature", "pass", "Governance endorsement, did:x509 identity, schema, and issuer signature verified")
    except Exception as exc:
        result("Issuer trust and signature", "fail", str(exc))
    try:
        receipt_info = verify_receipt_details(statement)
        txid = receipt_info["txid"]
        result("SCITT receipt", "pass", "Service signature and exact statement digest verified")
    except Exception as exc:
        result("SCITT receipt", "fail", str(exc))
    try:
        message = Sign1Message.decode(token)
        message.key = public_cose(state.msrc_key.public_key())
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
        result("KBT proof and audience", "pass", "cnf proof-of-possession, audience, and iat verified")
    except Exception as exc:
        result("KBT proof and audience", "fail", str(exc))
    try:
        if payload is None:
            raise ValueError("issuer payload is not trusted")
        presented = statement_value[1].get(SD_CLAIMS, [])
        selected = resolve_selected(payload, presented)
        if not set(selected).issubset(set(range(1000, 1009))):
            raise ValueError("disclosed fields are outside the report schema")
        result("Disclosure consistency", "pass", "All presented openings match reachable hashes and the report schema")
    except Exception as exc:
        result("Disclosure consistency", "fail", str(exc))
    if "receipt_info" in locals() and receipt_info["merkle"]:
        result("SCITT Merkle inclusion", "pass", "CCF Merkle inclusion proof verified")
    else:
        result("SCITT Merkle inclusion", "unavailable", "The mock receipt has no Merkle proof")
    report = None
    if payload is not None and selected is not None:
        report = describe_selected(payload, statement_value[1].get(SD_CLAIMS, []))
        report.update({"subject": statement_protected.get(15, {}).get(2, ""), "txid": txid, "audience": audience})
    return {"valid": all(check["status"] in {"pass", "unavailable"} for check in checks), "checks": checks, "report": report}


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/msrc")
def msrc_home() -> FileResponse:
    return FileResponse(ROOT / "static" / "msrc.html")


@app.get("/verify")
def verifier_home() -> FileResponse:
    return FileResponse(ROOT / "static" / "verify.html")


@app.get("/api/state")
def get_state() -> dict[str, Any]:
    point = state.msrc_key.public_key().public_numbers()
    parties = [dict(party) for party in state.parties]
    if REAL_SCITT_URL and REAL_SCITT_CA:
        registry = next(party for party in parties if party["role"] == "registry")
        registry.update({"name": "Real SCITT", "path": "/scitt/register"})
    return {
        "parties": parties,
        "ledger": {"mode": "real" if REAL_SCITT_URL and REAL_SCITT_CA else "mock", "name": "Real SCITT" if REAL_SCITT_URL and REAL_SCITT_CA else "Mock SCITT"},
        "issuer": state.issuer,
        "msrcKid": state.msrc_kid,
        "msrcJwk": {"kty": "EC", "crv": "P-256", "x": b64(point.x.to_bytes(32, "big")), "y": b64(point.y.to_bytes(32, "big"))},
    }


@app.get("/mock/msrc/key")
def get_msrc_key() -> dict[str, str]:
    numbers = state.msrc_key.private_numbers()
    public = numbers.public_numbers
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64(public.x.to_bytes(32, "big")),
        "y": b64(public.y.to_bytes(32, "big")),
        "d": b64(numbers.private_value.to_bytes(32, "big")),
    }


@app.post("/mock/msrc/inspect")
def inspect_msrc(body: DeliveryBody) -> dict[str, Any]:
    try:
        statement = unb64(body.statement)
        payload = verify_issuer(statement)
        txid = verify_receipt(statement)
        resolve_all(payload, parts(statement)[1].get(SD_CLAIMS, []))
        protected = cbor2.loads(parts(statement)[0])
        return {"txid": txid, "subject": protected.get(15, {}).get(2, "")}
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/mock/verifier")
def mock_verifier(body: KbtBody) -> dict[str, Any]:
    try:
        return verify_kbt(unb64(body.token), body.audience)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/verify")
def verify_api(body: KbtBody) -> dict[str, Any]:
    try:
        return verify_bundle(unb64(body.token), body.audience)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


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


@app.post("/scitt/register")
def real_scitt(body: TokenBody) -> dict[str, Any]:
    try:
        config = real_scitt_config()
        if config is None:
            raise ValueError("real SCITT is not configured")
        requests, cose, ca, key = config
        token = unb64(body.token)
        response = requests.post(
            f"{REAL_SCITT_URL}/entries?waitForCommit=true",
            data=token,
            headers={"content-type": "application/cose"},
            verify=ca,
            timeout=30,
        )
        response.raise_for_status()
        txid = response.headers["x-ms-ccf-transaction-id"]
        digest = hashlib.sha256(token).digest()
        cose.verify_receipt(response.content, key, digest)
        transparent = None
        for _ in range(100):
            fetched = requests.get(
                f"{REAL_SCITT_URL}/entries/{txid}/statement", verify=ca, timeout=30
            )
            if fetched.status_code == 200:
                transparent = fetched.content
                break
            if fetched.status_code not in (202, 503):
                fetched.raise_for_status()
            time.sleep(0.1)
        if transparent is None:
            raise TimeoutError(f"historical transaction {txid} remained uncached")
        if with_uhdr(transparent, {}) != token:
            raise ValueError("SCITT returned different signed bytes")
        receipts = parts(transparent)[1].get(SCITT_RECEIPTS, [])
        if len(receipts) != 1:
            raise ValueError("transparent statement has no single receipt")
        cose.verify_receipt(receipt_bytes(receipts[0]), key, digest)
        return {"txid": txid, "transparent": b64(transparent), "bytes": len(transparent), "receiptVerified": True}
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