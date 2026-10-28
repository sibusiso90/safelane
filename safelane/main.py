"""SafeLane AI Gateway - FastAPI app."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import llm
from .audit import AuditLog
from .policy import CLASS_ORDER, Decision, PolicyEngine, Register, check_output

ROOT = Path(__file__).resolve().parent.parent
register = Register(os.getenv("SAFELANE_REGISTER", ROOT / "config" / "register.yaml"))
engine = PolicyEngine(register)
audit = AuditLog(os.getenv("SAFELANE_AUDIT_DB", "safelane_audit.db"))

# Pending human reviews. Kept in memory on purpose: the real values behind the
# placeholders never touch disk. (A production version would use an encrypted store.)
REVIEWS: dict[str, dict] = {}

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


def _log_request(user: str, d: Decision, review_id: str | None = None) -> None:
    audit.append("request", {
        "user": user, "tool": d.tool_id, "tier": d.tier, "rule": d.rule, "reason": d.reason,
        "detected": sorted(d.redaction.kinds), "original_class": d.original_class,
        "prompt_redacted": d.redaction.redacted, "flags": d.flags, "review_id": review_id,
    })


def _complete(d: Decision) -> dict:
    raw = llm.ask(d.outbound_prompt, d.tool_id)
    warnings = check_output(raw, d, engine.redactor)
    return {"answer": d.redaction.rehydrate(raw), "output_warnings": warnings}


def _decision_view(d: Decision) -> dict:
    return {
        "tier": d.tier, "rule": d.rule, "reason": d.reason, "flags": d.flags,
        "detected": sorted(d.redaction.kinds), "sent_to_model": d.outbound_prompt,
        "alternatives": [{"id": t, "name": register.get(t)["name"]} for t in d.alternatives],
    }


@app.get("/")
def ui():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/tools")
def tools():
    return {"organisation": register.organisation, "tools": list(register.tools.values()), "data_classes": CLASS_ORDER}


@app.post("/api/ask")
def ask(body: AskIn):
    if body.data_class not in CLASS_ORDER:
        raise HTTPException(422, f"data_class must be one of {CLASS_ORDER}")
    d = engine.evaluate(body.prompt, body.tool_id, body.data_class)
    out = _decision_view(d)
    if d.tier == "BLOCKED":
        _log_request(body.user, d)
        return out
    if d.tier == "HIGH":
        rid = uuid.uuid4().hex[:8]
        REVIEWS[rid] = {"id": rid, "user": body.user, "decision": d, "status": "pending"}
        _log_request(body.user, d, rid)
        return {**out, "review_id": rid, "status": "Held for human review"}
    _log_request(body.user, d)
    result = _complete(d)
    audit.append("response", {"user": body.user, "tool": d.tool_id, "output_warnings": result["output_warnings"]})
    return {**out, **result}


@app.get("/api/reviews")
def reviews():
    # Reviewers see the REDACTED prompt only - they judge risk without seeing the personal data.
    return [{"id": r["id"], "user": r["user"], "status": r["status"], "tool": r["decision"].tool_id,
             "rule": r["decision"].rule, "reason": r["decision"].reason,
             "detected": sorted(r["decision"].redaction.kinds), "prompt_redacted": r["decision"].redaction.redacted,
             **({"answer": r["answer"], "output_warnings": r["output_warnings"]} if "answer" in r else {})}
            for r in REVIEWS.values()]


@app.post("/api/reviews/{rid}")
def review(rid: str, body: ReviewIn):
    r = REVIEWS.get(rid)
    if not r:
        raise HTTPException(404, "No such review")
    if r["status"] != "pending":
        raise HTTPException(409, "Already decided")
    if body.reviewer.strip().lower() == r["user"].strip().lower():
        raise HTTPException(403, "Segregation of duties: you cannot approve your own request")
    if body.action not in ("approve", "reject"):
        raise HTTPException(422, "action must be approve or reject")
    d: Decision = r["decision"]
    r["status"] = "approved" if body.action == "approve" else "rejected"
    audit.append("review", {"review_id": rid, "reviewer": body.reviewer, "action": body.action,
                            "note": body.note, "requester": r["user"]})
    if body.action == "approve":
        result = _complete(d)
        r.update(result)
        audit.append("response", {"user": r["user"], "tool": d.tool_id, "review_id": rid,
                                  "output_warnings": result["output_warnings"]})
        return {"status": "approved", **result}
    return {"status": "rejected"}


@app.get("/api/audit")
def audit_log(limit: int = 100):
    return audit.entries(limit)


@app.get("/api/audit/verify")
def audit_verify():
    return audit.verify()


@app.get("/api/stats")
def stats():
    return audit.summary()
