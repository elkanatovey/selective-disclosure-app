from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from .crypto import (
    verify_standalone_receipt,
    verify_transparent_statement,
    with_uhdr,
)
from .http import CoseBody, RequestBody, msrc_public, receipt_trust

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


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"role": "researcher", "status": "ok"}


@app.get("/api/state")
def public_state() -> dict[str, Any]:
    try:
        public = msrc_public(MSRC_URL)
        mst = bool(SCITT_CA)
        return {
            "parties": [
                {
                    "role": "issuer",
                    "name": "MSRC Researcher CA",
                    "path": "/msrc/issuer/endorse",
                },
                {
                    "role": "registry",
                    "name": "Microsoft Signing Transparency" if mst else "Mock SCITT",
                    "path": "/entries",
                },
                {
                    "role": "holder",
                    "name": "MSRC",
                    "path": "/msrc/deliveries",
                },
            ],
            "ledger": {
                "mode": "mst" if mst else "mock",
                "name": "Microsoft Signing Transparency" if mst else "Mock SCITT",
            },
            **public,
        }
    except Exception as exc:
        raise HTTPException(503, f"MSRC public configuration is unavailable: {exc}") from exc


def proxy_response(upstream: requests.Response) -> Response:
    media_type = upstream.headers.get("content-type", "application/json").partition(";")[0]
    return Response(upstream.content, status_code=upstream.status_code, media_type=media_type)


@app.post("/msrc/issuer/endorse")
def endorse(body: RequestBody) -> Response:
    try:
        upstream = requests.post(
            f"{MSRC_URL}/issuer/endorse",
            data=body,
            headers={"content-type": "application/json"},
            timeout=5,
        )
        return proxy_response(upstream)
    except requests.RequestException as exc:
        raise HTTPException(502, f"MSRC endorsement is unavailable: {exc}") from exc


@app.post("/msrc/deliveries")
def deliver(body: RequestBody) -> Response:
    try:
        upstream = requests.post(
            f"{MSRC_URL}/deliveries",
            data=body,
            headers={"content-type": "application/cose"},
            timeout=30,
        )
        return proxy_response(upstream)
    except requests.RequestException as exc:
        raise HTTPException(502, f"MSRC delivery is unavailable: {exc}") from exc


@app.post("/entries")
def register(
    token: CoseBody,
    wait_for_commit: bool = Query(True, alias="waitForCommit"),
) -> Response:
    try:
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
        receipt_txid = verify_standalone_receipt(
            upstream.content, token, receipt_trust(SCITT_URL, SCITT_CA)
        )
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
        receipt = verify_transparent_statement(upstream.content, receipt_trust(SCITT_URL, SCITT_CA))
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
