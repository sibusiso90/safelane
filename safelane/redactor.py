"""Detect and redact sensitive data in prompts before they leave the organisation.

Design choices:
- Deterministic, rule-based detectors (regex + checksums + context). They are
  explainable, testable and run offline. An ML/NER detector can be added behind the
  same interface later; free-text person names are a known gap.
- Every detection is replaced by a typed placeholder ([EMAIL_1]) and the mapping is
  kept in memory for the request only, so the answer can be "rehydrated" for the
  user without the external model ever seeing the real values.

v2 changes (after the adversarial test, see eval/README.md):
  formatted/spaced numbers, +27 (0) and (011) phones, obfuscated e-mails ("at"/"dot"),
  JWTs, bearer tokens, "password is X", bank-name account numbers, codename aliases,
  context suppression for reference/serial/order numbers, test-card allow-list,
  and a minimum-strength check so "token: placeholder" is not treated as a secret.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def sa_id_ok(raw: str) -> bool:
    """South African ID: YYMMDD SSSS C A Z, 13 digits, Luhn checksum, valid date."""
    num = _digits(raw)
    if len(num) != 13:
        return False
    mm, dd = int(num[2:4]), int(num[4:6])
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return False
    if num[10] not in "01":  # citizenship digit
        return False
    return luhn_ok(num)


TEST_CARDS = {"4111111111111111", "4242424242424242", "5555555555554444", "4000056655665556", "378282246310005"}


def card_ok(raw: str) -> bool:
    n = _digits(raw)
    return 13 <= len(n) <= 19 and luhn_ok(n) and n not in TEST_CARDS


def strong_secret(raw: str) -> bool:
    """A value after 'password:' / 'token=' only counts if it looks like a real secret."""
    v = raw.strip("'\";,")
    return len(v) >= 6 and bool(re.search(r"[\d\W_]", v)) and v.lower() not in {"placeholder", "redacted", "xxxxxx", "changeme"}


# Words that, just before a number, mean it is a business reference - not personal data.
REFERENCE_CONTEXT = re.compile(
    r"(?i)\b(?:ref(?:erence)?|order|invoice|inv|ticket|case|serial|meter|po|purchase order|tracking|tender|policy no|job)\b[\s#:.\-]*(?:no\.?|number|#)?[\s#:.\-]*$"
)

BANKS = r"(?:FNB|ABSA|Absa|Nedbank|Capitec|Standard Bank|TymeBank|Investec|African Bank|Discovery Bank|Bank)"

# (kind, pattern, validator, suppress_if_reference_context)
_DETECTORS: list[tuple[str, re.Pattern, Callable[[str], bool] | None, bool]] = [
    ("SECRET", re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[bp]-[A-Za-z0-9\-]{10,})\b"), None, False),
    ("SECRET", re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"), None, False),  # JWT
    ("SECRET", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.=]{16,})"), None, False),
    ("SECRET", re.compile(r"(?i)\b(?:password|passwd|pwd|passcode|api[_ ]?key|access[_ ]?key|token|secret)\s*(?:[:=]|\bis\b)\s*([^\s;,'\"]{4,})"), strong_secret, False),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None, False),
    ("EMAIL", re.compile(r"(?i)\b[a-z0-9._%+\-]+(?:\s+dot\s+[a-z0-9_\-]+)*\s*(?:\[at\]|\(at\)|\s+at\s+)\s*[a-z0-9\-]+"
                         r"(?:\s*(?:\[dot\]|\(dot\)|\s+dot\s+|\.)\s*[a-z0-9\-]+)*\s*(?:\[dot\]|\(dot\)|\s+dot\s+|\.)\s*[a-z]{2,}\b"), None, False),
    ("SA_ID", re.compile(r"(?<![\d\-])\d(?:[ \-]?\d){12}(?![\d\-])"), sa_id_ok, True),
    ("CARD", re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)"), card_ok, True),
    ("BANK_ACCOUNT", re.compile(rf"(?i)\b(?:acc(?:ount)?(?:\s*(?:no|number|#))?\.?|{BANKS}(?:\s+acc(?:ount)?)?(?:\s*(?:no|number|#))?\.?)\s*[:#]?\s*(\d{{8,12}})\b"), None, False),
    ("PHONE", re.compile(r"(?<![\d+])(?:\+27[\s\-]?(?:\(0\)[\s\-]?)?|\(0|0)(?:[1-8]\d)\)?[\s\-]?\d{3}[\s\-]?\d{4}(?!\d)"), None, True),
]


@dataclass
class Detection:
    kind: str
    value: str
    start: int
    end: int


@dataclass
class RedactionResult:
    original: str
    redacted: str
    detections: list[Detection] = field(default_factory=list)
    mapping: dict[str, str] = field(default_factory=dict)  # placeholder -> real value

    @property
    def kinds(self) -> set[str]:
        return {d.kind for d in self.detections}

    def rehydrate(self, text: str) -> str:
        for ph, real in self.mapping.items():
            text = text.replace(ph, real)
        return text


def _term_pattern(term: str) -> str:
    # "Acme board pack" also matches "Acme board-pack"; "Delta-9" matches "Delta 9"
    parts = re.split(r"[\s\-]+", term.strip())
    return r"[\s\-]?".join(re.escape(p) for p in parts)


class Redactor:
    def __init__(self, sensitive_terms: list | None = None):
        """sensitive_terms: strings (case-insensitive) or {term:, aliases: [...]}.
        Aliases are matched case-sensitively, so the codename 'Kestrel' is caught
        but the bird 'kestrel' is not."""
        full, aliases = [], []
        for t in sensitive_terms or []:
            if isinstance(t, dict):
                full.append(t["term"])
                aliases.extend(t.get("aliases", []))
            elif str(t).strip():
                full.append(str(t))
        by_len = lambda xs: sorted(xs, key=len, reverse=True)
        self._term_re = re.compile(r"(?i)\b(" + "|".join(_term_pattern(t) for t in by_len(full)) + r")\b") if full else None
        self._alias_re = re.compile(r"\b(" + "|".join(_term_pattern(t) for t in by_len(aliases)) + r")\b") if aliases else None

    def detect(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        taken: list[tuple[int, int]] = []

        def free(s: int, e: int) -> bool:
            return all(e <= a or s >= b for a, b in taken)

        def add(kind, s, e):
            found.append(Detection(kind, text[s:e], s, e))
            taken.append((s, e))

        for kind, pat, check, ref_ctx in _DETECTORS:
            for m in pat.finditer(text):
                s, e = (m.start(1), m.end(1)) if m.lastindex else (m.start(), m.end())
                val = text[s:e]
                if check and not check(val):
                    continue
                if ref_ctx and REFERENCE_CONTEXT.search(text[max(0, s - 30):s]):
                    continue
                if free(s, e):
                    add(kind, s, e)
        for rx in (self._term_re, self._alias_re):
            if rx:
                for m in rx.finditer(text):
                    if free(m.start(), m.end()):
                        add("INTERNAL_TERM", m.start(), m.end())
        return sorted(found, key=lambda d: d.start)

    def redact(self, text: str) -> RedactionResult:
        dets = self.detect(text)
        counters: dict[str, int] = {}
        seen: dict[str, str] = {}  # same value -> same placeholder
        mapping: dict[str, str] = {}
        out, pos = [], 0
        for d in dets:
            key = f"{d.kind}:{d.value.lower()}"
            if key not in seen:
                counters[d.kind] = counters.get(d.kind, 0) + 1
                seen[key] = f"[{d.kind}_{counters[d.kind]}]"
                mapping[seen[key]] = d.value
            out.append(text[pos:d.start])
            out.append(seen[key])
            pos = d.end
        out.append(text[pos:])
        return RedactionResult(text, "".join(out), dets, mapping)
