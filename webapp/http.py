from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import requests
from cryptography import x509
from fastapi import Depends, HTTPException, Request

from .crypto import ReceiptTrust, public_key_from_jwk


def get_json(url: str) -> dict[str, Any]:
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return response.json()


def msrc_public(url: str) -> dict[str, Any]:
    return get_json(f"{url}/api/public")


def receipt_trust(url: str, ca_path: str | None) -> ReceiptTrust:
    if ca_path:
        return ReceiptTrust(real_ca=x509.load_pem_x509_certificate(Path(ca_path).read_bytes()))
    return ReceiptTrust(mock_key=public_key_from_jwk(get_json(f"{url}/api/trust")["publicJwk"]))


async def request_body(request: Request) -> bytes:
    return await request.body()


async def cose_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").partition(";")[0]
    if content_type.lower() != "application/cose":
        raise HTTPException(415, "request body must be application/cose")
    body = await request.body()
    if not body:
        raise HTTPException(400, "COSE body is empty")
    return body


RequestBody = Annotated[bytes, Depends(request_body)]
CoseBody = Annotated[bytes, Depends(cose_body)]
