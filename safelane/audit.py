"""Tamper-evident audit log (SQLite, hash-chained).

Each entry stores the hash of the previous entry. Editing or deleting any past row
breaks the chain, which `verify()` detects. The log stores the *redacted* prompt and
the detection types - never the raw sensitive values - so the audit trail itself does
not become a new data-leak risk.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str = "safelane_audit.db"):
        self._lock = threading.Lock()
        self._tampered: dict | None = None  # original row kept by simulate_tamper()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, event TEXT NOT NULL, payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL, hash TEXT NOT NULL)"""
        )
        self.db.commit()

    @staticmethod
    def _hash(ts: str, event: str, payload: str, prev: str) -> str:
        return hashlib.sha256(f"{ts}|{event}|{payload}|{prev}".encode()).hexdigest()

    def append(self, event: str, payload: dict) -> int:
        with self._lock:
            row = self.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            body = json.dumps(payload, sort_keys=True)
            h = self._hash(ts, event, body, prev)
            cur = self.db.execute(
                "INSERT INTO audit (ts, event, payload, prev_hash, hash) VALUES (?,?,?,?,?)",
                (ts, event, body, prev, h),
            )
            self.db.commit()
            return cur.lastrowid

    def entries(self, limit: int = 200) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, ts, event, payload, hash FROM audit ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"id": r[0], "ts": r[1], "event": r[2], **json.loads(r[3]), "hash": r[4][:12]} for r in rows]

    def verify(self) -> dict:
        prev = GENESIS
        n = 0
        for id_, ts, event, payload, prev_hash, h in self.db.execute(
            "SELECT id, ts, event, payload, prev_hash, hash FROM audit ORDER BY id"
        ):
            n += 1
            if prev_hash != prev or self._hash(ts, event, payload, prev_hash) != h:
                return {"ok": False, "entries_checked": n, "broken_at_id": id_}
            prev = h
        return {"ok": True, "entries_checked": n}

    def simulate_tamper(self) -> dict:
        """Demo only: rewrite one stored entry the way an insider with database access
        might, without recomputing its hash. Prefers covering up the latest HIGH or
        BLOCKED request by marking it LOW. `restore()` puts the original back."""
        with self._lock:
            if self._tampered:
                return self._tampered["info"]
            rows = self.db.execute("SELECT id, event, payload FROM audit ORDER BY id DESC").fetchall()
            if not rows:
                return {"ok": False, "detail": "The log is empty. Send a request first."}
            requests = [r for r in rows if r[1] == "request"]
            risky = [r for r in requests if json.loads(r[2]).get("tier") in ("HIGH", "BLOCKED")]
            id_, event, body = (risky or requests or rows)[0]
            p = json.loads(body)
            if event == "request":
                change = {"field": "tier", "from": p["tier"], "to": "LOW"}
            else:
                change = {"field": "user", "from": p.get("user", ""), "to": "someone-else"}
            p[change["field"]] = change["to"]
            self.db.execute("UPDATE audit SET payload = ? WHERE id = ?", (json.dumps(p, sort_keys=True), id_))
            self.db.commit()
            info = {"ok": True, "id": id_, **change}
            self._tampered = {"id": id_, "payload": body, "info": info}
            return info

    def restore(self) -> dict:
        with self._lock:
            if not self._tampered:
                return {"ok": False, "detail": "Nothing to restore."}
            t, self._tampered = self._tampered, None
            self.db.execute("UPDATE audit SET payload = ? WHERE id = ?", (t["payload"], t["id"]))
            self.db.commit()
            return {"ok": True, "id": t["id"]}

    def summary(self) -> dict:
        rows = self.db.execute("SELECT event, payload FROM audit").fetchall()
        tiers: dict[str, int] = {}
        kinds: dict[str, int] = {}
        for event, payload in rows:
            if event != "request":
                continue
            p = json.loads(payload)
            tiers[p["tier"]] = tiers.get(p["tier"], 0) + 1
            for k in p.get("detected", []):
                kinds[k] = kinds.get(k, 0) + 1
        return {"requests_by_tier": tiers, "detections_by_type": kinds}
