# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""FastAPI front end for chunk-level redaction of a free-text SD-CWT claim.

Single-process demo: one issued document is held in memory, standing in for the
holder's custody of the disclosures. The issuer key is ephemeral, so a restart
invalidates any presentation exported before it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .chunking import CHUNK_CHARS
from .textfield import IssuedText, issue_text, new_key, reveal, verify_text

HERE = Path(__file__).parent
MAX_CHARS = 120_000
MAX_UPLOAD_BYTES = 8 * 1024 * 1024

app = FastAPI(title="SD-CWT text redaction")
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")

_key = new_key()
_issued: Optional[IssuedText] = None


class IssueRequest(BaseModel):
    text: str
    size: int = Field(default=CHUNK_CHARS, ge=1, le=4096)


class PresentRequest(BaseModel):
    reveal: list[int] = []
    include_field: bool = True


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "sample": (HERE / "sample.txt").read_text(encoding="utf-8"),
            "chunk_chars": CHUNK_CHARS,
            "max_chars": MAX_CHARS,
        },
    )


@app.post("/api/issue")
def api_issue(req: IssueRequest):
    if len(req.text) > MAX_CHARS:
        raise HTTPException(413, f"text exceeds {MAX_CHARS} characters")
    global _issued
    try:
        _issued = issue_text(req.text, _key, size=req.size)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        "chunk_count": _issued.chunk_count,
        "size": req.size,
        "token_bytes": len(_issued.token),
        "chunks": _issued.chunks,
    }


@app.post("/api/present")
def api_present(req: PresentRequest):
    if _issued is None:
        raise HTTPException(409, "no document has been issued yet")
    try:
        token = reveal(_issued, req.reveal, include_field=req.include_field)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return Response(
        content=token,
        media_type="application/cose",
        headers={"Content-Disposition": 'attachment; filename="presentation.cose"'},
    )


@app.post("/api/verify")
async def api_verify(token: UploadFile):
    raw = await token.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "token too large")
    out = verify_text(raw, _key)
    return {
        "signature_ok": out.signature_ok,
        "disclosures_ok": out.disclosures_ok,
        "field_revealed": out.field_revealed,
        "chunk_count": out.chunk_count,
        "revealed_count": len(out.revealed),
        "withheld_count": len(out.withheld),
        "spans": out.spans(),
        "error": out.error,
    }
