"""SafeLane AI Gateway - FastAPI app."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .accounts import Account
from .policy import CLASS_ORDER
from .service import Gateway, GatewayError

ROOT = Path(__file__).resolve().parent.parent
gateway = Gateway(os.getenv("SAFELANE_REGISTER", ROOT / "config" / "register.yaml"),
                  os.getenv("SAFELANE_AUDIT_DB", "safelane_audit.db"),
                  os.getenv("SAFELANE_ACCOUNTS", ROOT / "config" / "accounts.yaml"))

# Demo controls (the audit tamper simulation) are off unless SAFELANE_DEMO=1: they let
# an admin edit the audit log, so they must never run in production.
DEMO = os.getenv("SAFELANE_DEMO") == "1"

app = FastAPI(title="SafeLane AI Gateway", version="0.2.0")
bearer = HTTPBearer(auto_error=False)

DataClass = Literal[tuple(CLASS_ORDER)]  # type: ignore[valid-type]


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AskIn(BaseModel):
    tool_id: str = Field(min_length=1, max_length=100)
    prompt: str = Field(min_length=1, max_length=20000)
    data_class: DataClass = "internal"


class ReviewIn(BaseModel):
    action: Literal["approve", "reject"]
    note: str = Field(default="", max_length=1000)


def _call(fn, *args):
    try:
        return fn(*args)
    except GatewayError as e:
        raise HTTPException(e.status, e.detail) from e


def _token(cred: HTTPAuthorizationCredentials | None) -> str | None:
    return cred.credentials if cred else None


def current(cred: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> Account:
    return _call(gateway.session, _token(cred))


Me = Annotated[Account, Depends(current)]


@app.get("/")
def ui():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/tools")
def tools():
    return {**gateway.tools(), "demo": DEMO, "demo_accounts": gateway.demo_accounts(),
            "demo_password": gateway.accounts.demo_password if gateway.accounts else None}


@app.post("/api/login")
def login(body: LoginIn):
    return _call(gateway.login, body.username, body.password)


@app.post("/api/logout")
def logout(cred: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
    return gateway.logout(_token(cred))


@app.get("/api/me")
def me(acct: Me):
    return acct.view()


@app.post("/api/ask")
def ask(body: AskIn, acct: Me):
    return _call(gateway.ask, acct, body.tool_id, body.prompt, body.data_class)


@app.get("/api/reviews")
def reviews(acct: Me):
    return _call(gateway.list_reviews, acct)


@app.post("/api/reviews/{rid}")
def review(rid: str, body: ReviewIn, acct: Me):
    return _call(gateway.decide, rid, acct, body.action, body.note)


@app.get("/api/audit")
def audit_log(acct: Me, limit: Annotated[int, Query(ge=1, le=500)] = 100):
    return _call(gateway.audit_entries, acct, limit)


@app.get("/api/audit/verify")
def audit_verify(acct: Me):
    return _call(gateway.audit_verify, acct)


@app.post("/api/audit/tamper")
def audit_tamper(acct: Me):
    if not DEMO:
        raise HTTPException(404, "Not found")
    return _call(gateway.simulate_tamper, acct)


@app.post("/api/audit/restore")
def audit_restore(acct: Me):
    if not DEMO:
        raise HTTPException(404, "Not found")
    return _call(gateway.restore, acct)


@app.get("/api/stats")
def stats(acct: Me):
    return _call(gateway.stats, acct)
