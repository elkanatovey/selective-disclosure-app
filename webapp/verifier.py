from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography import x509
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .crypto import unb64, verify_bundle
from .http import CoseBody, msrc_public, receipt_trust

ROOT = Path(__file__).parent
MSRC_URL = os.getenv("MSRC_URL", "http://127.0.0.1:8091")
SCITT_URL = os.getenv("SCITT_URL", "http://127.0.0.1:8000")
SCITT_CA = os.getenv("SCITT_CA")

app = FastAPI(title="Disclosure Verifier")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "verify.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"role": "verifier", "status": "ok"}


@app.post("/api/verify")
def verify(token: CoseBody, audience: str = Query(...)) -> dict[str, Any]:
    try:
        public = msrc_public(MSRC_URL)
        return verify_bundle(
            token,
            audience,
            x509.load_der_x509_certificate(unb64(public["ca"])),
            public["issuer"],
            receipt_trust(SCITT_URL, SCITT_CA),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc
