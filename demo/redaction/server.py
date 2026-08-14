# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Operator tooling: redact a transparent statement before handing it on.

Load what ``GET /operator/statements/{txid}`` returns, choose which body chunks
to keep, and export a copy with the rest withheld. Single-process: one statement
is held in memory at a time.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sd_cwt import statement as st

from .statement_tool import Loaded, load, restrict, sample_statement, verify

HERE = Path(__file__).parent
MAX_UPLOAD_BYTES = 8 * 1024 * 1024

app = FastAPI(title="SD-CWT statement redaction")
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")

_loaded: Optional[Loaded] = None
_service_cert: Optional[bytes] = None


class SampleRequest(BaseModel):
    text: str


class RestrictRequest(BaseModel):
    keep: list[int] = []


async def _read(upload: Optional[UploadFile]) -> Optional[bytes]:
    if upload is None:
        return None
    raw = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large")
    return raw


_TYPED_FIELDS = {
    "title": str,
    "component": str,
    "severity": str,
    "patch": str,
    "patch_date": int,
    "references": list,
}


def _displayable(fields: dict) -> dict:
    """Absent content fields are random sentinels, not values (DESIGN section 9).
    A wrong type gives one away; `parent` and `fingerprint` are genuinely bstr,
    so theirs cannot be told apart and are shown as-is."""
    out = {}
    for name, v in fields.items():
        want = _TYPED_FIELDS.get(name)
        if want is not None and not isinstance(v, want):
            continue
        out[name] = v.hex() if isinstance(v, bytes) else str(v)
    return out


def _state() -> dict:
    out = verify(_loaded.token, _service_cert)
    return {
        "chunk_count": _loaded.total,
        "chunk_chars": st.BODY_CHUNK_CHARS,
        "chunks": _loaded.spans(),
        "fields": _displayable(_loaded.fields),
        "token_bytes": len(_loaded.token),
        "has_receipt": out.has_receipt,
        "receipt_ok": out.receipt_ok,
        "disclosures_ok": out.disclosures_ok,
        "error": out.error,
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.post("/api/load")
async def api_load(token: UploadFile, service_cert: Optional[UploadFile] = None):
    global _loaded, _service_cert
    raw = await _read(token)
    cert = await _read(service_cert)
    try:
        _loaded = load(raw)
    except Exception as exc:
        raise HTTPException(400, f"not a valid transparent statement: {exc}") from exc
    if cert is not None:
        _service_cert = cert
    return _state()


@app.post("/api/sample")
def api_sample(req: SampleRequest):
    global _loaded, _service_cert
    if not req.text:
        raise HTTPException(400, "text is empty")
    _loaded, _service_cert = load(sample_statement(req.text)), None
    return _state()


@app.post("/api/restrict")
def api_restrict(req: RestrictRequest):
    if _loaded is None:
        raise HTTPException(409, "no statement loaded")
    return Response(
        content=restrict(_loaded.token, req.keep),
        media_type="application/cose",
        headers={"Content-Disposition": 'attachment; filename="redacted.cose"'},
    )


@app.post("/api/verify")
async def api_verify(token: UploadFile, service_cert: Optional[UploadFile] = None):
    raw = await _read(token)
    cert = await _read(service_cert) or _service_cert
    out = verify(raw, cert)
    try:
        chunks = load(raw).spans()
    except Exception:
        chunks = []
    return {
        "valid": out.valid,
        "has_receipt": out.has_receipt,
        "receipt_ok": out.receipt_ok,
        "disclosures_ok": out.disclosures_ok,
        "chunk_count": out.chunk_count,
        "revealed_count": out.revealed,
        "chunks": chunks,
        "error": out.error,
    }
