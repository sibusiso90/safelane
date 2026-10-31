"""Sign-in, sessions and roles.

Accounts come from a YAML file of salted PBKDF2 password hashes (`config/accounts.yaml`
holds the demo accounts). A real deployment would sign people in through the company's
identity provider instead; the rest of the gateway only needs an `Account` with a role.

Roles keep duties apart, so nobody holds every power:
  staff     - ask the AI and see their own held requests
  reviewer  - also approve or reject other people's held requests (never their own)
  auditor   - read the audit log and every review, verify the chain; cannot ask or approve
  admin     - runs the gateway: audit log, reviews (read only) and, in demo mode only,
              the tampering simulation; cannot ask or approve
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

ROLES = {
    "staff": {"ask"},
    "reviewer": {"ask", "review", "view_reviews"},
    "auditor": {"audit", "view_reviews"},
    "admin": {"audit", "view_reviews", "demo_controls"},
}
SESSION_TTL = 8 * 3600
# Failed sign-ins are counted per (username, client) pair, so a stranger guessing at an
# account cannot lock its owner out from elsewhere; per client across all usernames, so one
# client cannot spray guesses over many accounts; and per account across all clients, with a
# higher limit, so many clients together cannot guess without end. Locking an owner out that
# way takes at least MAX_ACCOUNT_FAILURES / MAX_FAILURES separate clients.
MAX_FAILURES, MAX_CLIENT_FAILURES, MAX_ACCOUNT_FAILURES, LOCKOUT_WINDOW = 5, 20, 50, 15 * 60
ITERATIONS = 600_000


def _pbkdf2_sha256(password: bytes, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256 (RFC 8018) for one 32-byte block. Pyodide's Python has no
    OpenSSL, so `hashlib.pbkdf2_hmac` is missing in the browser build; this gives the
    same result using plain SHA-256."""
    key = hashlib.sha256(password).digest() if len(password) > 64 else password
    key = key.ljust(64, b"\0")
    inner, outer = hashlib.sha256(bytes(b ^ 0x36 for b in key)), hashlib.sha256(bytes(b ^ 0x5C for b in key))

    def prf(msg: bytes) -> bytes:
        i, o = inner.copy(), outer.copy()
        i.update(msg)
        o.update(i.digest())
        return o.digest()

    u = prf(salt + b"\0\0\0\1")
    acc = int.from_bytes(u, "big")
    for _ in range(iterations - 1):
        u = prf(u)
        acc ^= int.from_bytes(u, "big")
    return acc.to_bytes(32, "big")


def hash_password(password: str, salt: str | None = None, iterations: int = ITERATIONS) -> str:
    salt = salt or secrets.token_hex(16)
    derive = getattr(hashlib, "pbkdf2_hmac", None)
    dk = (derive("sha256", password.encode(), bytes.fromhex(salt), iterations) if derive
          else _pbkdf2_sha256(password.encode(), bytes.fromhex(salt), iterations))
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, _ = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    return hmac.compare_digest(hash_password(password, salt, int(iterations)), stored)


_dummy: str | None = None


def _dummy_hash() -> str:
    """Checked when the username is unknown, so a wrong username takes as long as a wrong
    password. Made on first use, so starting the gateway stays fast."""
    global _dummy
    if _dummy is None:
        _dummy = hash_password(secrets.token_hex(8))
    return _dummy


@dataclass(frozen=True)
class Account:
    username: str
    name: str
    role: str
    department: str = ""

    def can(self, permission: str) -> bool:
        return permission in ROLES.get(self.role, set())

    def view(self) -> dict:
        return {"username": self.username, "name": self.name, "role": self.role, "department": self.department,
                "permissions": sorted(ROLES.get(self.role, set()))}


class AuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def client_key(client: str) -> str:
    """IPv6 clients are counted by /64 network: one attacker usually holds a whole /64."""
    try:
        ip = ipaddress.ip_address(client)
    except ValueError:
        return client
    return str(ipaddress.ip_network(f"{ip}/64", strict=False)) if ip.version == 6 else str(ip)


class Accounts:
    def __init__(self, path: str | Path):
        data = yaml.safe_load(Path(path).read_text()) or {}
        self.demo_password = data.get("demo_password")  # shown on the sign-in page; demo builds only
        self._users: dict[str, tuple[Account, str]] = {}
        for u in data.get("accounts", []):
            if u["role"] not in ROLES:
                raise ValueError(f"Unknown role {u['role']!r} for {u['username']!r}")
            acct = Account(u["username"].lower(), u["name"], u["role"], u.get("department", ""))
            self._users[acct.username] = (acct, u["password_hash"])
        self._sessions: dict[str, tuple[Account, float]] = {}
        self._failures: dict[tuple, list[float]] = {}
        self._lock = threading.Lock()

    def exists(self, username: str) -> bool:
        return username.strip().lower() in self._users

    def directory(self) -> list[dict]:
        return [a.view() for a, _ in self._users.values()]

    def login(self, username: str, password: str, client: str = "local") -> tuple[str, Account]:
        key, client = username.strip().lower(), client_key(client)
        now = time.time()
        buckets = [((key, client), MAX_FAILURES), (("*", client), MAX_CLIENT_FAILURES),
                   ((key, "*"), MAX_ACCOUNT_FAILURES)]
        with self._lock:
            # Count the attempt before the slow hash, so parallel guesses cannot all slip
            # under the limit; a successful sign-in clears the count for that account.
            recent = {b: [t for t in self._failures.get(b, []) if now - t < LOCKOUT_WINDOW] for b, _ in buckets}
            if any(len(recent[b]) >= limit for b, limit in buckets):
                self._failures.update(recent)
                raise AuthError(429, "Too many failed sign-ins. Try again in 15 minutes.")
            for b, _ in buckets:
                self._failures[b] = recent[b] + [now]
        acct, stored = self._users.get(key) or (None, _dummy_hash())
        if not check_password(password, stored) or acct is None:
            raise AuthError(401, "Wrong username or password.")
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._failures.pop((key, client), None)
            for b in (("*", client), (key, "*")):
                if self._failures.get(b):
                    self._failures[b].pop()  # this attempt was not a failure
            self._sessions = {t: s for t, s in self._sessions.items() if s[1] > now}  # drop expired
            self._sessions[token] = (acct, now + SESSION_TTL)
        return token, acct

    def session(self, token: str | None) -> Account:
        with self._lock:
            s = self._sessions.get(token or "")
            if not s or s[1] < time.time():
                self._sessions.pop(token or "", None)
                raise AuthError(401, "Please sign in.")
            return s[0]

    def logout(self, token: str | None) -> None:
        with self._lock:
            self._sessions.pop(token or "", None)
