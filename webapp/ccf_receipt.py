from __future__ import annotations

import base64
import os
from pathlib import Path

import cbor2
import ccf.cose
from cryptography import x509
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

SCITT_CA = Path(os.environ["SCITT_CA"])
SERVICE_KEY = x509.load_pem_x509_certificate(SCITT_CA.read_bytes()).public_key()


class VerifyBody(BaseModel):
    receipt: str
    digest: str


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def registration_txid(receipt: bytes) -> str:
    value = cbor2.loads(receipt).value
    for encoded in value[1].get(396, {}).get(-1, []):
        evidence = cbor2.loads(encoded).get(1, [None, ""])[1]
        if isinstance(evidence, str) and evidence.startswith("ce:"):
            return evidence.split(":", 2)[1]
    raise ValueError("receipt has no registration transaction ID")


app = FastAPI(title="CCF Receipt Verifier")


@app.get("/health")
def health() -> dict[str, str]:
    return {"role": "ccf-receipt-verifier", "status": "ok"}


@app.post("/verify")
def verify(body: VerifyBody) -> dict[str, str]:
    try:
        receipt = unb64(body.receipt)
        ccf.cose.verify_receipt(receipt, SERVICE_KEY, unb64(body.digest))
        return {"txid": registration_txid(receipt)}
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc