"""Gateway logic, independent of any web framework.

`main.py` exposes this over FastAPI; the GitHub Pages build runs the same class in the
browser with Pyodide. Errors are raised as `GatewayError(status, detail)` so each host
can turn them into its own HTTP response.
"""
from __future__ import annotations

import uuid

from . import llm
from .audit import AuditLog
from .policy import CLASS_ORDER, Decision, PolicyEngine, Register, check_output


class GatewayError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class Gateway:
    def __init__(self, register_path, audit_path: str = "safelane_audit.db"):
        self.register = Register(register_path)
        self.engine = PolicyEngine(self.register)
        self.audit = AuditLog(audit_path)
        # Pending human reviews. Kept in memory on purpose: the real values behind the
        # placeholders never touch disk. (A production version would use an encrypted store.)
        self.reviews: dict[str, dict] = {}

    def _log_request(self, user: str, d: Decision, review_id: str | None = None) -> None:
        self.audit.append("request", {
            "user": user, "tool": d.tool_id, "tier": d.tier, "rule": d.rule, "reason": d.reason,
            "detected": sorted(d.redaction.kinds), "original_class": d.original_class,
            "prompt_redacted": d.redaction.redacted, "flags": d.flags, "review_id": review_id,
        })

    def _complete(self, d: Decision) -> dict:
        raw = llm.ask(d.outbound_prompt, d.tool_id)
        warnings = check_output(raw, d, self.engine.redactor)
        return {"answer": d.redaction.rehydrate(raw), "output_warnings": warnings}

    def _decision_view(self, d: Decision) -> dict:
        return {
            "tier": d.tier, "rule": d.rule, "reason": d.reason, "flags": d.flags,
            "detected": sorted(d.redaction.kinds), "sent_to_model": d.outbound_prompt,
            "alternatives": [{"id": t, "name": self.register.get(t)["name"]} for t in d.alternatives],
        }

    def tools(self) -> dict:
        return {"organisation": self.register.organisation, "tools": list(self.register.tools.values()),
                "data_classes": CLASS_ORDER}

    def ask(self, user: str, tool_id: str, prompt: str, data_class: str = "internal") -> dict:
        if data_class not in CLASS_ORDER:
            raise GatewayError(422, f"data_class must be one of {CLASS_ORDER}")
        d = self.engine.evaluate(prompt, tool_id, data_class)
        out = self._decision_view(d)
        if d.tier == "BLOCKED":
            self._log_request(user, d)
            return out
        if d.tier == "HIGH":
            rid = uuid.uuid4().hex[:8]
            self.reviews[rid] = {"id": rid, "user": user, "decision": d, "status": "pending"}
            self._log_request(user, d, rid)
            return {**out, "review_id": rid, "status": "Held for human review"}
        self._log_request(user, d)
        result = self._complete(d)
        self.audit.append("response", {"user": user, "tool": d.tool_id, "output_warnings": result["output_warnings"]})
        return {**out, **result}

    def list_reviews(self) -> list[dict]:
        # Reviewers see the REDACTED prompt only - they judge risk without seeing the personal data.
        return [{"id": r["id"], "user": r["user"], "status": r["status"], "tool": r["decision"].tool_id,
                 "rule": r["decision"].rule, "reason": r["decision"].reason,
                 "detected": sorted(r["decision"].redaction.kinds), "prompt_redacted": r["decision"].redaction.redacted,
                 **({"answer": r["answer"], "output_warnings": r["output_warnings"]} if "answer" in r else {})}
                for r in self.reviews.values()]

    def decide(self, rid: str, reviewer: str, action: str, note: str = "") -> dict:
        r = self.reviews.get(rid)
        if not r:
            raise GatewayError(404, "No such review")
        if r["status"] != "pending":
            raise GatewayError(409, "Already decided")
        if reviewer.strip().lower() == r["user"].strip().lower():
            raise GatewayError(403, "Segregation of duties: you cannot approve your own request")
        if action not in ("approve", "reject"):
            raise GatewayError(422, "action must be approve or reject")
        d: Decision = r["decision"]
        r["status"] = "approved" if action == "approve" else "rejected"
        self.audit.append("review", {"review_id": rid, "reviewer": reviewer, "action": action,
                                     "note": note, "requester": r["user"]})
        if action == "approve":
            result = self._complete(d)
            r.update(result)
            self.audit.append("response", {"user": r["user"], "tool": d.tool_id, "review_id": rid,
                                           "output_warnings": result["output_warnings"]})
            return {"status": "approved", **result}
        return {"status": "rejected"}
