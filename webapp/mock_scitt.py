from __future__ import annotations

import os
from typing import Any

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import Response

from .crypto import (
    SCITT_RECEIPTS,
    create_mock_receipt,
    parts,
    public_jwk,
    public_key_from_jwk,
    unb64,
    verify_issuer,
    with_uhdr,
)

MSRC_URL = os.getenv("MSRC_URL", "http://127.0.0.1:8091")


class State:
    def __init__(self) -> None:
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.entries: dict[str, bytes] = {}
        self.seqno = 0


state = State()
app = FastAPI(title="Mock SCITT")


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


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"role": "mock-scitt", "status": "ok"}


@app.get("/api/trust")
def trust() -> dict[str, Any]:
    return {"publicJwk": public_jwk(state.signing_key.public_key())}


@app.post("/entries")
async def register(
    request: Request,
    wait_for_commit: bool = Query(True, alias="waitForCommit"),
) -> Response:
    del wait_for_commit
    try:
        token = await cose_body(request)
        if parts(token)[1]:
            raise ValueError("SCITT only accepts the fully redacted envelope")
        public = msrc_public()
        verify_issuer(
            token,
            x509.load_der_x509_certificate(unb64(public["ca"])),
            public["issuer"],
            public_key_from_jwk(public["msrcJwk"]),
        )
        state.seqno += 1
        txid = f"1.{state.seqno}"
        receipt = create_mock_receipt(token, txid, state.signing_key)
        state.entries[txid] = with_uhdr(
            token,
            {SCITT_RECEIPTS: [cbor2.loads(receipt)]},
        )
        return Response(
            receipt,
            status_code=201,
            media_type="application/cose",
            headers={"x-ms-ccf-transaction-id": txid},
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/entries/{txid}/statement")
def statement(txid: str) -> Response:
    transparent = state.entries.get(txid)
    if transparent is None:
        raise HTTPException(404, "SCITT entry was not found")
    return Response(transparent, media_type="application/cose")
