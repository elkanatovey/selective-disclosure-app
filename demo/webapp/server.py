# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""FastAPI backend for the interactive Selective Disclosure demo.

One server, four role windows. The browser talks JSON to this server; this
server is the real ledger client (mutual TLS + CBOR/COSE) and the offline
verifier. Blocking ledger calls run in a threadpool so the event loop that
drives the live WebSocket feed stays responsive.
"""

import asyncio
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sd_cwt import statement as st

from .events import EventBus
from .ledger_client import (
    DISCLOSABLE_FIELDS,
    SUBMIT_FIELDS,
    LedgerClient,
    LedgerError,
    load_clients,
    render_claims,
    report_from_form,
)

HERE = Path(__file__).parent
NODE_URL = os.environ.get("DEMO_URL", "https://127.0.0.1:8000")
COMMON_DIR = os.environ.get("DEMO_COMMON_DIR", "workspace/sandbox_common")

app = FastAPI(title="Selective Disclosure Report Ledger — Interactive Demo")
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")

bus = EventBus()
clients: dict[str, LedgerClient] = load_clients(NODE_URL, COMMON_DIR)

# Disclosure artifacts the Operator has released, so a researcher can pick one
# to verify offline. In-memory: a demo, restarted per run.
artifacts: dict[str, dict] = {}
_artifact_seq = 0


def _anon() -> LedgerClient:
    return clients["anonymous"]


def _verify(token: bytes):
    """Validate a token offline against the current endorsed issuer key."""
    key = _anon().issuer_key()
    return st.validate_statement(token, key)


# --- pages ------------------------------------------------------------------
ROLE_PAGES = {
    "index": "Selective Disclosure Ledger",
    "client": "Client",
    "operator": "Operator",
    "researcher": "Researcher",
    "member": "Member",
    "wall": "Live Ledger",
}


def _page(name: str):
    async def render(request: Request):
        return templates.TemplateResponse(
            request,
            f"{name}.html",
            {
                "request": request,
                "title": ROLE_PAGES[name],
                "node_url": NODE_URL,
                "submit_fields": SUBMIT_FIELDS,
                "disclosable_fields": DISCLOSABLE_FIELDS,
            },
        )

    return render


for _name in ROLE_PAGES:
    _route = "/" if _name == "index" else f"/{_name}"
    app.get(_route, name=_name)(_page(_name))


# --- API: health ------------------------------------------------------------
@app.get("/api/health")
async def health():
    try:
        version = await asyncio.to_thread(_anon().version)
    except Exception as e:  # node not up yet
        return JSONResponse({"node_up": False, "error": str(e)}, status_code=503)
    key_ready = True
    try:
        await asyncio.to_thread(_anon().issuer_key)
    except LedgerError:
        key_ready = False
    return {"node_up": True, "version": version, "signing_key_ready": key_ready}


# --- API: member ------------------------------------------------------------
@app.post("/api/member/signing-key")
async def signing_key(rotate: bool = False):
    try:
        result = await asyncio.to_thread(clients["member"].init_signing_key, rotate)
    except LedgerError as e:
        raise HTTPException(e.status, e.detail)
    await bus.publish("signing_key", rotate=rotate, **result)
    return result


# --- API: client ------------------------------------------------------------
@app.post("/api/client/reports")
async def submit_report(request: Request):
    form = dict(await request.form())
    try:
        report = report_from_form(form)
    except ValueError as e:
        raise HTTPException(400, f"bad field: {e}")
    if not report:
        raise HTTPException(400, "empty report")

    try:
        txid = await asyncio.to_thread(_anon().submit_report, report)
        redacted = await asyncio.to_thread(_anon().redacted_statement, txid)
        claims = await asyncio.to_thread(_verify, redacted)
    except LedgerError as e:
        raise HTTPException(e.status, e.detail)

    # Prove submitted plaintext is absent from the token bytes on the wire.
    leaked = [
        name
        for name, value in report.items()
        if isinstance(value, str) and value.encode() in redacted
    ]
    rendered = render_claims(claims)
    payload = {
        "txid": txid,
        "token_bytes": len(redacted),
        "leaked_fields": leaked,
        "public_view": rendered.fields,
    }
    await bus.publish("report", txid=txid, parent=None)
    return payload


# --- API: operator ----------------------------------------------------------
@app.get("/api/ledger")
async def ledger():
    """Drain the Operator's statement stream to the current watermark."""
    out: list[str] = []
    frm = 1
    try:
        while True:
            page = await asyncio.to_thread(clients["operator"].list_statements, frm)
            out.extend(page.get("statements", []))
            if page["to"] >= page["watermark"]:
                break
            frm = page["to"] + 1
    except LedgerError as e:
        raise HTTPException(e.status, e.detail)
    return {"statements": out}


@app.get("/api/operator/full/{txid}")
async def operator_full(txid: str):
    try:
        token = await asyncio.to_thread(clients["operator"].full_statement, txid)
        claims = await asyncio.to_thread(_verify, token)
    except LedgerError as e:
        raise HTTPException(e.status, e.detail)
    # Show that an anonymous caller is refused on the same endpoint.
    anon_status = await asyncio.to_thread(
        _anon().status, f"/operator/statements/{txid}"
    )
    return {
        "txid": txid,
        "fields": render_claims(claims).fields,
        "anon_status": anon_status,
    }


@app.post("/api/operator/disclose/{txid}")
async def operator_disclose(txid: str, request: Request):
    body = await request.json()
    fields = body.get("fields", [])
    if not fields:
        raise HTTPException(400, "choose at least one field to disclose")
    try:
        token = await asyncio.to_thread(clients["operator"].disclose, txid, fields)
        claims = await asyncio.to_thread(_verify, token)
    except LedgerError as e:
        raise HTTPException(e.status, e.detail)

    global _artifact_seq
    _artifact_seq += 1
    artifact_id = f"disc-{_artifact_seq}"
    rendered = render_claims(claims)
    artifacts[artifact_id] = {
        "id": artifact_id,
        "txid": txid,
        "requested": fields,
        "revealed": [f["name"] for f in rendered.fields],
        "bytes": token,
    }
    await bus.publish(
        "disclosure",
        artifact_id=artifact_id,
        txid=txid,
        revealed=artifacts[artifact_id]["revealed"],
    )
    return {
        "artifact_id": artifact_id,
        "txid": txid,
        "revealed": rendered.fields,
    }


# --- API: operator follow-up (duplicate-proof) ------------------------------
@app.post("/api/operator/followup/{parent_txid}")
async def operator_followup(parent_txid: str, request: Request):
    form = dict(await request.form())
    try:
        report = report_from_form(form)
    except ValueError as e:
        raise HTTPException(400, f"bad field: {e}")
    if not report:
        raise HTTPException(400, "empty follow-up")
    try:
        txid = await asyncio.to_thread(
            clients["operator"].submit_report, report, parent_txid
        )
    except LedgerError as e:
        raise HTTPException(e.status, e.detail)
    await bus.publish("report", txid=txid, parent=parent_txid)
    return {"txid": txid, "parent": parent_txid}


# --- API: researcher --------------------------------------------------------
@app.get("/api/artifacts")
async def list_artifacts():
    return {
        "artifacts": [
            {k: a[k] for k in ("id", "txid", "revealed")} for a in artifacts.values()
        ]
    }


@app.post("/api/researcher/verify")
async def researcher_verify(request: Request):
    body = await request.json()
    artifact_id = body.get("artifact_id")
    art = artifacts.get(artifact_id)
    if art is None:
        raise HTTPException(404, "unknown artifact")
    try:
        claims = await asyncio.to_thread(_verify, art["bytes"])
    except LedgerError as e:
        raise HTTPException(e.status, e.detail)
    except Exception as e:
        return {"verified": False, "error": str(e)}
    hidden = sorted(set(DISCLOSABLE_FIELDS) - set(art["revealed"]))
    return {
        "verified": True,
        "txid": art["txid"],
        "revealed": render_claims(claims).fields,
        "hidden": hidden,
    }


# --- WebSocket: live events -------------------------------------------------
@app.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept()
    q = bus.subscribe()

    async def watch_disconnect():
        # The client never sends; this wakes only when the socket closes.
        try:
            while True:
                await sock.receive()
        except Exception:
            pass

    closed = asyncio.ensure_future(watch_disconnect())
    try:
        while True:
            nxt = asyncio.ensure_future(q.get())
            done, _ = await asyncio.wait(
                {nxt, closed}, return_when=asyncio.FIRST_COMPLETED
            )
            if closed in done:
                nxt.cancel()
                break
            await sock.send_json(nxt.result())
    finally:
        closed.cancel()
        bus.unsubscribe(q)
