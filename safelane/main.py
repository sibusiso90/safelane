"""SafeLane AI Gateway - FastAPI app."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .service import Gateway, GatewayError

ROOT = Path(__file__).resolve().parent.parent
gateway = Gateway(os.getenv("SAFELANE_REGISTER", ROOT / "config" / "register.yaml"),
                  os.getenv("SAFELANE_AUDIT_DB", "safelane_audit.db"))

# Demo controls (the audit tamper simulation) are off unless SAFELANE_DEMO=1: they let
# anyone who can reach the API edit the audit log, so they must never run in production.
DEMO = os.getenv("SAFELANE_DEMO") == "1"

app = FastAPI(title="SafeLane AI Gateway", version="0.1.0")


class AskIn(BaseModel):
    user: str = Field(min_length=1)
    tool_id: str
    prompt: str = Field(min_length=1, max_length=20000)
    data_class: str = "internal"


class ReviewIn(BaseModel):
    reviewer: str = Field(min_length=1)
    action: str  # approve | reject
    note: str = ""


def _call(fn, *args):
    try:
        return fn(*args)
    except GatewayError as e:
        raise HTTPException(e.status, e.detail) from e


@app.get("/")
def ui():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/tools")
def tools():
    return {**gateway.tools(), "demo": DEMO}


@app.post("/api/ask")
def ask(body: AskIn):
    return _call(gateway.ask, body.user, body.tool_id, body.prompt, body.data_class)


@app.get("/api/reviews")
def reviews():
    return gateway.list_reviews()


@app.post("/api/reviews/{rid}")
def review(rid: str, body: ReviewIn):
    return _call(gateway.decide, rid, body.reviewer, body.action, body.note)


@app.get("/api/audit")
def audit_log(limit: int = 100):
    return gateway.audit.entries(limit)


@app.get("/api/audit/verify")
def audit_verify():
    return gateway.audit.verify()


@app.post("/api/audit/tamper")
def audit_tamper():
    if not DEMO:
        raise HTTPException(404, "Not found")
    return gateway.audit.simulate_tamper()


@app.post("/api/audit/restore")
def audit_restore():
    if not DEMO:
        raise HTTPException(404, "Not found")
    return gateway.audit.restore()


@app.get("/api/stats")
def stats():
    return gateway.audit.summary()
