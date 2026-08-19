from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import cbor2
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .crypto import (
    SD_CLAIMS,
    ReceiptTrust,
    b64,
    cert,
    issuer_for_ca,
    parts,
    public_cose_map,
    public_jwk,
    public_key_from_jwk,
    resolve_all,
    resolve_selected,
    sign_kbt,
    unb64,
    verify_issuer,
    verify_transparent_statement,
)

ROOT = Path(__file__).parent
SCITT_URL = os.getenv("SCITT_URL", "http://127.0.0.1:8000")
SCITT_CA = os.getenv("SCITT_CA")
RECEIPT_VERIFIER_URL = os.getenv("RECEIPT_VERIFIER_URL")
RESEARCHER_ORIGIN = os.getenv("RESEARCHER_ORIGIN", "http://127.0.0.1:8090")


class State:
    def __init__(self) -> None:
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_cert = cert("MSRC Researcher CA", self.ca_key.public_key(), self.ca_key)
        self.issuer = issuer_for_ca(self.ca_cert)
        self.holder_key = ec.generate_private_key(ec.SECP256R1())
        self.inbox: list[dict[str, Any]] = []

    @property
    def holder_cnf(self) -> dict[int, Any]:
        return {1: public_cose_map(self.holder_key.public_key())}

    @property
    def holder_kid(self) -> str:
        encoded = self.holder_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(encoded).hexdigest()[:16]


class EndorseBody(BaseModel):
    public_jwk: dict[str, str]


class DisclosureBody(BaseModel):
    statement: str
    selected: list[str]
    audience: str


state = State()
app = FastAPI(title="MSRC Disclosure Service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[RESEARCHER_ORIGIN],
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


def receipt_trust() -> ReceiptTrust:
    if SCITT_CA:
        if not RECEIPT_VERIFIER_URL:
            raise RuntimeError("real SCITT receipt verifier is not configured")
        return ReceiptTrust(real_verifier_url=RECEIPT_VERIFIER_URL)
    response = requests.get(f"{SCITT_URL}/api/trust", timeout=5)
    response.raise_for_status()
    return ReceiptTrust(mock_key=public_key_from_jwk(response.json()["publicJwk"]))


def inspect_statement(statement: bytes, require_all: bool) -> dict[str, Any]:
    payload = verify_issuer(
        statement,
        state.ca_cert,
        state.issuer,
        state.holder_key.public_key(),
    )
    receipt = verify_transparent_statement(statement, receipt_trust())
    presented = parts(statement)[1].get(SD_CLAIMS, [])
    fields = resolve_all(payload, presented) if require_all else resolve_selected(payload, presented)
    protected = cbor2.loads(parts(statement)[0])
    return {
        "txid": receipt["txid"],
        "subject": protected.get(15, {}).get(2, ""),
        "fields": fields,
        "merkle": receipt["merkle"],
    }


async def cose_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").partition(";")[0]
    if content_type.lower() != "application/cose":
        raise HTTPException(415, "request body must be application/cose")
    value = await request.body()
    if not value:
        raise HTTPException(400, "COSE body is empty")
    return value


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "msrc.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"role": "msrc", "status": "ok"}


@app.get("/api/public")
def public_state() -> dict[str, Any]:
    return {
        "issuer": state.issuer,
        "ca": b64(state.ca_cert.public_bytes(serialization.Encoding.DER)),
        "msrcKid": state.holder_kid,
        "msrcJwk": public_jwk(state.holder_key.public_key()),
    }


@app.post("/issuer/endorse")
def endorse(body: EndorseBody) -> dict[str, str]:
    try:
        if "d" in body.public_jwk:
            raise ValueError("MSRC accepts public keys only")
        public_key = public_key_from_jwk(body.public_jwk)
        leaf = cert("Web Statement Issuer", public_key, state.ca_key, state.ca_cert)
        return {
            "issuer": state.issuer,
            "serial": hex(leaf.serial_number)[2:14],
            "leaf": b64(leaf.public_bytes(serialization.Encoding.DER)),
            "root": b64(state.ca_cert.public_bytes(serialization.Encoding.DER)),
        }
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/deliveries")
async def deliver(request: Request) -> dict[str, Any]:
    try:
        statement = await cose_body(request)
        inspected = inspect_statement(statement, require_all=True)
        item = {
            "txid": inspected["txid"],
            "subject": inspected["subject"],
            "fields": len(inspected["fields"]),
            "digest": hashlib.sha256(statement).hexdigest()[:16],
        }
        state.inbox.insert(0, item)
        return item
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/inspect")
async def inspect(request: Request) -> dict[str, Any]:
    try:
        inspected = inspect_statement(await cose_body(request), require_all=True)
        return {
            "txid": inspected["txid"],
            "subject": inspected["subject"],
            "receiptVerified": True,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/disclosures")
def disclose(body: DisclosureBody) -> Response:
    try:
        statement = unb64(body.statement)
        inspect_statement(statement, require_all=True)
        selected = [unb64(item) for item in body.selected]
        payload = verify_issuer(
            statement,
            state.ca_cert,
            state.issuer,
            state.holder_key.public_key(),
        )
        resolve_selected(payload, selected)
        token = sign_kbt(statement, selected, state.holder_key, body.audience)
        return Response(token, media_type="application/cose")
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc