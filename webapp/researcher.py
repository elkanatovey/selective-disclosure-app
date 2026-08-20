from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests
from cryptography import x509
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from .crypto import (
    ReceiptTrust,
    public_key_from_jwk,
    verify_standalone_receipt,
    verify_transparent_statement,
    with_uhdr,
)

ROOT = Path(__file__).parent
MSRC_URL = os.getenv("MSRC_URL", "http://127.0.0.1:8091")
SCITT_URL = os.getenv("SCITT_URL", "http://127.0.0.1:8000")
SCITT_CA = os.getenv("SCITT_CA")


class State:
    def __init__(self) -> None:
        self.entries: dict[str, bytes] = {}


state = State()
app = FastAPI(title="Researcher Submission")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


def scitt_verify() -> Path | bool:
    return Path(SCITT_CA) if SCITT_CA else True


def receipt_trust() -> ReceiptTrust:
    if SCITT_CA:
        ca = x509.load_pem_x509_certificate(Path(SCITT_CA).read_bytes())
        return ReceiptTrust(real_ca=ca)
    response = requests.get(f"{SCITT_URL}/api/trust", timeout=5)
    response.raise_for_status()
    return ReceiptTrust(mock_key=public_key_from_jwk(response.json()["publicJwk"]))


def msrc_public() -> dict[str, Any]:
    response = requests.get(f"{MSRC_URL}/api/public", timeout=5)
    response.raise_for_status()
    return response.json()


async def cose_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").partition(";")[0]
    if content_type.lower() != "application/cose":
        raise HTTPException(415, "SCITT entries require application/cose")
    value = await request.body()
    if not value:
        raise HTTPException(400, "SCITT entry is empty")
    return value


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"role": "researcher", "status": "ok"}


@app.get("/api/state")
def public_state() -> dict[str, Any]:
    try:
        public = msrc_public()
        real = bool(SCITT_CA)
        return {
            "parties": [
                {
                    "role": "issuer",
                    "name": "MSRC Researcher CA",
                    "path": f"{MSRC_URL}/issuer/endorse",
                },
                {
                    "role": "registry",
                    "name": "Microsoft Signing Transparency Ledger" if real else "Mock SCITT",
                    "path": "/entries",
                },
                {
                    "role": "holder",
                    "name": "MSRC",
                    "path": f"{MSRC_URL}/deliveries",
                },
            ],
            "ledger": {
                "mode": "real" if real else "mock",
                "name": "Microsoft Signing Transparency Ledger" if real else "Mock SCITT",
            },
            **public,
        }
    except Exception as exc:
        raise HTTPException(503, f"MSRC public configuration is unavailable: {exc}") from exc


@app.post("/entries")
async def register(
    request: Request,
    wait_for_commit: bool = Query(True, alias="waitForCommit"),
) -> Response:
    try:
        token = await cose_body(request)
        upstream = requests.post(
            f"{SCITT_URL}/entries",
            params={"waitForCommit": str(wait_for_commit).lower()},
            data=token,
            headers={"content-type": "application/cose"},
            verify=scitt_verify(),
            timeout=30,
        )
        if upstream.status_code != 201:
            raise HTTPException(upstream.status_code, upstream.text or upstream.reason)
        txid = upstream.headers.get("x-ms-ccf-transaction-id")
        if not txid:
            raise ValueError("SCITT response has no transaction ID")
        receipt_txid = verify_standalone_receipt(upstream.content, token, receipt_trust())
        if receipt_txid != txid:
            raise ValueError("SCITT receipt transaction ID does not match")
        state.entries[txid] = token
        return Response(
            upstream.content,
            status_code=201,
            media_type="application/cose",
            headers={
                "x-ms-ccf-transaction-id": txid,
                "x-receipt-verified": "true",
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/entries/{txid}/statement")
def statement(txid: str) -> Response:
    try:
        upstream = requests.get(
            f"{SCITT_URL}/entries/{txid}/statement",
            verify=scitt_verify(),
            timeout=30,
        )
        if upstream.status_code in (202, 503):
            return Response(status_code=upstream.status_code)
        if upstream.status_code != 200:
            raise HTTPException(upstream.status_code, upstream.text or upstream.reason)
        original = state.entries.get(txid)
        if original is None:
            raise ValueError("researcher has no matching submitted statement")
        if with_uhdr(upstream.content, {}) != original:
            raise ValueError("SCITT returned different signed bytes")
        receipt = verify_transparent_statement(upstream.content, receipt_trust())
        if receipt["txid"] != txid:
            raise ValueError("SCITT receipt transaction ID does not match")
        return Response(
            upstream.content,
            media_type="application/cose",
            headers={"x-receipt-verified": "true"},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc