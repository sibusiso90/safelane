"""Tamper-evident audit log (SQLite, keyed hash chain).

Each entry stores an HMAC-SHA256 of its contents and of the previous entry's MAC, so
editing or deleting any past row breaks the chain. Because the MAC needs a key that is
not in the database, someone who can write to the database cannot rewrite an entry and
then recompute the chain after it. A signed "head" record (the last entry's id and MAC)
is kept outside the table, so deleting the newest entries is caught too.

Where the key lives decides what this protects against. The demo keeps it in a file
next to the database (or in memory); a real deployment would hold it in a secret store
the database administrators cannot read, and copy the head to write-once storage.

The log stores the *redacted* prompt and the detection types - never the raw sensitive
values - so the audit trail itself does not become a new data-leak risk.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
SCHEME = "hmac-sha256-v2"


def _load_key(path: str, key: str | bytes | None) -> bytes:
    if key is None:
        key = os.getenv("SAFELANE_AUDIT_KEY")
    if key:
        return key.encode() if isinstance(key, str) else key
    if path == ":memory:":
        return secrets.token_bytes(32)
    # Demo fallback: a random key in a file beside the database, readable by its owner only.
    key_file = Path(f"{path}.key")
    if not key_file.exists():
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    return bytes.fromhex(key_file.read_text().strip())


class AuditLog:
    def __init__(self, path: str = "safelane_audit.db", key: str | bytes | None = None):
        self._lock = threading.Lock()
        self._tampered: dict | None = None  # original row kept by simulate_tamper()
        self._key = _load_key(path, key)
        self._head_file = None if path == ":memory:" else Path(f"{path}.head")
        self._head: dict | None = None
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        scheme = self.db.execute("SELECT v FROM meta WHERE k = 'scheme'").fetchone()
        if scheme is None:
            # A log from before keyed hashes cannot be verified with a key; keep it aside, start fresh.
            exists = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'").fetchone()
            if exists:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                self.db.execute(f"ALTER TABLE audit RENAME TO audit_legacy_{stamp}")
            self.db.execute("INSERT INTO meta (k, v) VALUES ('scheme', ?)", (SCHEME,))
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, event TEXT NOT NULL, payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL, hash TEXT NOT NULL)"""
        )
        self.db.commit()
        if self._head_file and self._head_file.exists():
            self._head = json.loads(self._head_file.read_text())

    def _hash(self, ts: str, event: str, payload: str, prev: str) -> str:
        msg = json.dumps([ts, event, payload, prev]).encode()  # unambiguous field boundaries
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def _head_mac(self, id_: int, h: str) -> str:
        return hmac.new(self._key, f"head|{id_}|{h}".encode(), hashlib.sha256).hexdigest()

    def _write_head(self, id_: int, h: str) -> None:
        self._head = {"id": id_, "hash": h, "mac": self._head_mac(id_, h)}
        if self._head_file:
            tmp = self._head_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._head))
            tmp.replace(self._head_file)

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
            self._write_head(cur.lastrowid, h)
            return cur.lastrowid

    def entries(self, limit: int = 200) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, ts, event, payload, hash FROM audit ORDER BY id DESC LIMIT ?", (max(1, limit),)
        ).fetchall()
        return [{"id": r[0], "ts": r[1], "event": r[2], **json.loads(r[3]), "hash": r[4][:12]} for r in rows]

    def verify(self) -> dict:
        prev = GENESIS
        n = 0
        last_id = None
        with self._lock:
            rows = self.db.execute("SELECT id, ts, event, payload, prev_hash, hash FROM audit ORDER BY id").fetchall()
            head = self._head
        for id_, ts, event, payload, prev_hash, h in rows:
            n += 1
            if prev_hash != prev or not hmac.compare_digest(self._hash(ts, event, payload, prev_hash), h):
                return {"ok": False, "entries_checked": n, "broken_at_id": id_,
                        "detail": f"Entry {id_} was changed or removed after it was written."}
            prev, last_id = h, id_
        if head is None:
            if n:
                return {"ok": False, "entries_checked": n, "broken_at_id": None,
                        "detail": "The signed head record is missing, so deleted recent entries cannot be ruled out."}
            return {"ok": True, "entries_checked": 0}
        if not hmac.compare_digest(head.get("mac", ""), self._head_mac(head["id"], head["hash"])):
            return {"ok": False, "entries_checked": n, "broken_at_id": None, "detail": "The head record was forged."}
        if last_id != head["id"] or prev != head["hash"]:
            return {"ok": False, "entries_checked": n, "broken_at_id": head["id"],
                    "detail": f"The log should end at entry {head['id']}; the most recent entries were deleted."}
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
