from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests
from cryptography import x509
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .crypto import (
    ReceiptTrust,
    public_key_from_jwk,
    unb64,
    verify_bundle,
)

ROOT = Path(__file__).parent
MSRC_URL = os.getenv("MSRC_URL", "http://127.0.0.1:8091")
SCITT_URL = os.getenv("SCITT_URL", "http://127.0.0.1:8000")
SCITT_CA = os.getenv("SCITT_CA")

app = FastAPI(title="Disclosure Verifier")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


def msrc_public() -> dict[str, Any]:
    response = requests.get(f"{MSRC_URL}/api/public", timeout=5)
    response.raise_for_status()
    return response.json()


def receipt_trust() -> ReceiptTrust:
    if SCITT_CA:
        ca = x509.load_pem_x509_certificate(Path(SCITT_CA).read_bytes())
        return ReceiptTrust(real_ca=ca)
    response = requests.get(f"{SCITT_URL}/api/trust", timeout=5)
    response.raise_for_status()
    return ReceiptTrust(mock_key=public_key_from_jwk(response.json()["publicJwk"]))


async def cose_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").partition(";")[0]
    if content_type.lower() != "application/cose":
        raise HTTPException(415, "verification requires application/cose")
    value = await request.body()
    if not value:
        raise HTTPException(400, "KBT is empty")
    return value


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "verify.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"role": "verifier", "status": "ok"}


@app.post("/api/verify")
async def verify(request: Request, audience: str = Query(...)) -> dict[str, Any]:
    try:
        public = msrc_public()
        return verify_bundle(
            await cose_body(request),
            audience,
            x509.load_der_x509_certificate(unb64(public["ca"])),
            public["issuer"],
            receipt_trust(),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
