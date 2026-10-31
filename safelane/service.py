"""Gateway logic, independent of any web framework.

`main.py` exposes this over FastAPI; the GitHub Pages build runs the same class in the
browser with Pyodide. Errors are raised as `GatewayError(status, detail)` so each host
can turn them into its own HTTP response.

Every call that does something takes the signed-in `Account`, so who asked and who
approved come from the session, never from a name typed into a form.
"""
from __future__ import annotations

import threading
import uuid

from . import llm
from .accounts import Account, Accounts, AuthError
from .audit import AuditLog
from .policy import CLASS_ORDER, Decision, PolicyEngine, Register, check_output


class GatewayError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class Gateway:
    def __init__(self, register_path, audit_path: str = "safelane_audit.db", accounts_path=None,
                 audit_key: str | bytes | None = None):
        self.register = Register(register_path)
        self.engine = PolicyEngine(self.register)
        self.audit = AuditLog(audit_path, audit_key)
        self.accounts = Accounts(accounts_path) if accounts_path else None
        # Pending human reviews. Kept in memory on purpose: the real values behind the
        # placeholders never touch disk. (A production version would use an encrypted store.)
        self.reviews: dict[str, dict] = {}
        self._lock = threading.Lock()

    # ---------- sign-in ----------
    def login(self, username: str, password: str) -> dict:
        try:
            token, acct = self._accounts().login(username, password)
        except AuthError as e:
            if e.status == 401:
                self.audit.append("login_failed", {"user": username.strip().lower()[:64]})
            raise GatewayError(e.status, e.detail) from e
        self.audit.append("login", {"user": acct.username, "role": acct.role})
        return {"token": token, "account": acct.view()}

    def session(self, token: str | None) -> Account:
        try:
            return self._accounts().session(token)
        except AuthError as e:
            raise GatewayError(e.status, e.detail) from e

    def logout(self, token: str | None) -> dict:
        self._accounts().logout(token)
        return {"ok": True}

    def demo_accounts(self) -> list[dict]:
        """The sign-in page lists these, with the shared demo password, only when the
        accounts file sets one."""
        a = self._accounts()
        return a.directory() if a.demo_password else []

    def _accounts(self) -> Accounts:
        if not self.accounts:
            raise GatewayError(503, "Sign-in is not configured.")
        return self.accounts

    @staticmethod
    def _require(acct: Account, permission: str) -> None:
        if not acct.can(permission):
            raise GatewayError(403, f"Your role ({acct.role}) cannot do this.")

    # ---------- asking ----------
    def _log_request(self, user: str, d: Decision, review_id: str | None = None) -> None:
        self.audit.append("request", {
            "user": user, "tool": d.tool_id, "tier": d.tier, "rule": d.rule, "reason": d.reason,
            "detected": sorted(d.redaction.kinds), "original_class": d.original_class,
            "prompt_redacted": d.redaction.redacted, "flags": d.flags, "review_id": review_id,
        })

    def _complete(self, user: str, d: Decision, review_id: str | None = None) -> dict:
        """Call the model. On failure, log it and raise a 502; the caller decides what to undo."""
        try:
            raw = llm.ask(d.outbound_prompt, d.tool_id)
        except Exception as e:  # network, HTTP or malformed reply: the user gets a clear message
            self.audit.append("response", {"user": user, "tool": d.tool_id, "review_id": review_id,
                                           "error": f"Model call failed: {type(e).__name__}"})
            raise GatewayError(502, "The AI model could not be reached. Nothing was answered; try again.") from e
        warnings = check_output(raw, d, self.engine.redactor)
        self.audit.append("response", {"user": user, "tool": d.tool_id, "review_id": review_id,
                                       "output_warnings": warnings})
        return {"answer_raw": raw, "answer": d.redaction.rehydrate(raw), "output_warnings": warnings}

    def _decision_view(self, d: Decision) -> dict:
        return {
            "tier": d.tier, "rule": d.rule, "reason": d.reason, "flags": d.flags,
            "detected": sorted(d.redaction.kinds), "sent_to_model": d.outbound_prompt,
            "alternatives": [{"id": t, "name": self.register.get(t)["name"]} for t in d.alternatives],
        }

    def tools(self) -> dict:
        return {"organisation": self.register.organisation, "tools": list(self.register.tools.values()),
                "data_classes": CLASS_ORDER}

    def ask(self, acct: Account, tool_id: str, prompt: str, data_class: str = "internal") -> dict:
        self._require(acct, "ask")
        if data_class not in CLASS_ORDER:
            raise GatewayError(422, f"data_class must be one of {CLASS_ORDER}")
        d = self.engine.evaluate(prompt, tool_id, data_class)
        out = self._decision_view(d)
        if d.tier == "BLOCKED":
            self._log_request(acct.username, d)
            return out
        if d.tier == "HIGH":
            rid = uuid.uuid4().hex[:8]
            with self._lock:
                self.reviews[rid] = {"id": rid, "user": acct.username, "decision": d, "status": "pending"}
            self._log_request(acct.username, d, rid)
            return {**out, "review_id": rid, "status": "Held for human review"}
        self._log_request(acct.username, d)
        result = self._complete(acct.username, d)
        return {**out, "answer": result["answer"], "output_warnings": result["output_warnings"]}

    # ---------- human review ----------
    def list_reviews(self, acct: Account) -> list[dict]:
        """Reviewers and auditors see every held request; staff see their own.
        Only the requester gets the answer with the real values restored; everyone else
        sees the placeholders, so reviewing never exposes the personal data."""
        if not (acct.can("view_reviews") or acct.can("ask")):
            raise GatewayError(403, f"Your role ({acct.role}) cannot do this.")
        out = []
        for r in list(self.reviews.values()):
            mine = r["user"] == acct.username
            if not (mine or acct.can("view_reviews")):
                continue
            d: Decision = r["decision"]
            item = {"id": r["id"], "user": r["user"], "status": r["status"], "tool": d.tool_id, "rule": d.rule,
                    "reason": d.reason, "detected": sorted(d.redaction.kinds), "prompt_redacted": d.redaction.redacted,
                    "mine": mine, "can_decide": acct.can("review") and not mine and r["status"] == "pending",
                    "reviewer": r.get("reviewer")}
            if "answer" in r:
                item |= {"answer": r["answer"] if mine else r["answer_raw"], "output_warnings": r["output_warnings"],
                         "answer_restored": mine}
            out.append(item)
        return out

    def decide(self, rid: str, acct: Account, action: str, note: str = "") -> dict:
        self._require(acct, "review")
        if action not in ("approve", "reject"):
            raise GatewayError(422, "action must be approve or reject")
        with self._lock:  # check-and-claim in one step, so two reviewers cannot both release it
            r = self.reviews.get(rid)
            if not r:
                raise GatewayError(404, "No such review")
            if r["user"] == acct.username:
                raise GatewayError(403, "Segregation of duties: you cannot approve your own request")
            if r["status"] != "pending":
                raise GatewayError(409, "Already decided")
            r["status"] = "sending" if action == "approve" else "rejected"
            r["reviewer"] = acct.username
        self.audit.append("review", {"review_id": rid, "reviewer": acct.username, "action": action,
                                     "note": note, "requester": r["user"]})
        if action == "reject":
            return {"status": "rejected"}
        d: Decision = r["decision"]
        try:
            result = self._complete(r["user"], d, rid)
        except GatewayError:
            with self._lock:  # nothing was released: put it back in the queue so it can be retried
                r["status"], r["reviewer"] = "pending", None
            raise
        with self._lock:
            r.update(result, status="approved")
        # The reviewer gets the placeholder version; the requester sees the restored answer.
        return {"status": "approved", "answer": result["answer_raw"], "output_warnings": result["output_warnings"]}

    # ---------- audit ----------
    def audit_entries(self, acct: Account, limit: int = 100) -> list[dict]:
        self._require(acct, "audit")
        return self.audit.entries(min(max(limit, 1), 500))

    def audit_verify(self, acct: Account) -> dict:
        self._require(acct, "audit")
        return self.audit.verify()

    def stats(self, acct: Account) -> dict:
        self._require(acct, "audit")
        return self.audit.summary()

    def simulate_tamper(self, acct: Account) -> dict:
        self._require(acct, "demo_controls")
        return self.audit.simulate_tamper()

    def restore(self, acct: Account) -> dict:
        self._require(acct, "demo_controls")
        return self.audit.restore()
