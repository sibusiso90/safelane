"""Detect and redact sensitive data in prompts before they leave the organisation.

Design choices:
- Deterministic, rule-based detectors (regex + checksums + context). They are
  explainable, testable and run offline. An ML/NER detector can be added behind the
  same interface later. Names with nothing around them that marks a person
  ("tell sibongile") are still a known gap.
- Every detection is replaced by a typed placeholder ([EMAIL_1]) and the mapping is
  kept in memory for the request only, so the answer can be "rehydrated" for the
  user without the external model ever seeing the real values.

v2 changes (after the adversarial test, see eval/README.md):
  formatted/spaced numbers, +27 (0) and (011) phones, obfuscated e-mails ("at"/"dot"),
  JWTs, bearer tokens, "password is X", bank-name account numbers, codename aliases,
  context suppression for reference/serial/order numbers, test-card allow-list,
  and a minimum-strength check so "token: placeholder" is not treated as a secret.

v3 changes (scored on eval/heldout_v3.jsonl, which was written and committed first):
  person names from titles, greetings, sign-offs, addressing words, initials and
  "Firstname Surname from/said ..." patterns; "pass:" labels; and unlabelled
  "user / password" pairs when the password is long and mixes character classes.

v4 changes (scored on eval/heldout_v4.jsonl, which was written and committed first):
  every detector runs on a normalised view of the prompt: invisible characters
  (zero-width space, soft hyphen, word joiner ...) are removed, look-alike digits
  (fullwidth ０-９) become ASCII, and runs of spoken digits ("eight zero zero ...",
  "double five", Afrikaans "agt nul") become numbers. An offset map points each
  detection back at the original characters, so redaction replaces exactly those.
  The detectors also still run on the raw text, and the results are merged, so
  normalising can only add detections: a removed character cannot glue a number to
  its neighbour, and spoken digits cannot swallow a phone number written beside them.
"""
from __future__ import annotations

import re
import unicodedata
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
    return "".join(str(int(d)) for d in re.findall(r"\d", s))  # fullwidth and other digits as ASCII


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


def complex_secret(raw: str) -> bool:
    """For a password with no label: at least 8 characters and 3 of the 4 character classes."""
    v = raw.rstrip(".")
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w]"))
    return len(v) >= 8 and classes >= 3


# --- Person names (v3) ---
# No list of first names: names are found from the way people are written about. A
# title ("Ms Fourie"), a greeting or sign-off ("Dear ...", "Regards, ..."), a word that
# addresses someone ("tell", "for", "technician"), an initial ("J. Smith"), or two
# capitalised words followed by something a person does ("... from procurement asked").
_CAP = r"[A-Z][a-z]+(?:[\-'][A-Z][a-z]+)?"
_PARTICLE = r"(?:van der|van den|van|von|de la|de|du|le|da|dos)"
_NAME = rf"(?:{_PARTICLE}\s+)?{_CAP}(?:\s+(?:{_PARTICLE}\s+)?{_CAP}){{0,2}}"
TITLES = r"(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Adv|Sir|Madam|Mnr|Mev)"
NAME_CUES = (
    r"(?:Dear|Hi|Hello|Hey|Sawubona|Dumela|Molo|Regards,?|Thanks,?|Thank you,?|Sincerely,?|Attn:?|Cc:?|"
    r"I,|I am|I'm|my name is|named|called|to|for|from|with|by|tell|ask|call|phone|email|e-mail|e-mailed|emailed|"
    r"remind|contact|thank|congratulate|invite|promote|hire|dismiss|"
    r"colleague|manager|supervisor|technician|engineer|employee|candidate|applicant|customer|client|intern|"
    r"attendees? (?:were|was|are|is)|met with|spoke to|signed by|approved by)"
)
_TITLE_RE = re.compile(rf"\b{TITLES}\.?\s+({_NAME})")
_CUE_RE = re.compile(rf"(?:(?<=\s)|^|(?<=[\"'(]))(?i:{NAME_CUES}),?\s+({_NAME})")
_INITIAL_RE = re.compile(r"(?<![\w.])([A-Z]\.\s?(?:[A-Z]\.\s?)?" + _CAP + r")")
_PAIR_RE = re.compile(rf"\b({_CAP}\s+(?:{_PARTICLE}\s+)?{_CAP})(?=\s+(?:from|at|in|of|said|says|asked|asks|wants|will|has|is|was|"
                      r"joined|reported|called|e-?mailed)\b|,|'s\b)")
# Capitalised words that start a sentence, name a time, or belong to places and organisations.
NOT_NAMES = {
    "The", "A", "An", "This", "That", "These", "Those", "Our", "My", "Your", "His", "Her", "Their", "Its", "All", "Every",
    "Each", "Some", "Any", "No", "Please", "Can", "Could", "Would", "Will", "Should", "Write", "Draft", "Summarise",
    "Summarize", "Explain", "Make", "Create", "Translate", "Rewrite", "Rephrase", "Check", "Use", "Send", "Forward",
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December",
    "Project", "Team", "Department", "Board", "Exco", "Acme", "Customer", "Care", "Support", "Sales", "Finance",
    "Procurement", "Operations", "Head", "Office", "Depot", "Region", "Committee", "Act", "Policy", "Microsoft", "Google",
    "Teams", "Meet", "Zoom", "Outlook", "Excel", "Word", "Eskom", "Municipality", "Council", "Bank", "Street", "Road",
    "Drive", "Avenue", "Station", "Substation", "Health", "Safety", "South", "Africa", "African", "Gauteng", "Limpopo",
    "Mpumalanga", "Natal", "Cape", "Free", "State", "North", "West", "East", "Northern", "Eastern", "Western", "Southern",
    "Johannesburg", "Pretoria", "Tshwane", "Durban", "Ethekwini", "Town", "Gqeberha", "Port", "Elizabeth", "London",
    "Bloemfontein", "Polokwane", "Mbombela", "Nelspruit", "Kimberley", "Mahikeng", "Pietermaritzburg", "Soweto",
    "Mthatha", "Rustenburg", "George", "Sandton", "Centurion", "Midrand", "AI", "IT", "HR",
    "Mr", "Mrs", "Ms", "Miss", "Mx", "Dr", "Prof", "Adv", "Sir", "Madam", "Mnr", "Mev",
}
# A capitalised name followed by one of these is a place or organisation ("Mandela Drive").
PLACE_NEXT = re.compile(r"\s+(?:Drive|Street|St|Road|Rd|Avenue|Ave|Square|Park|Hospital|School|University|College|"
                        r"Bank|Holdings|Group|Ltd|Inc|Act|Committee|Municipality|Depot|depot|office|branch|region|station|plant)\b")


def _trim_name(text: str, s: int, e: int) -> tuple[int, int] | None:
    """Drop non-name words from either end of a candidate; None if nothing name-like is left."""
    words = [(m.start() + s, m.end() + s) for m in re.finditer(r"\S+", text[s:e])]
    while words and text[words[0][0]:words[0][1]] in NOT_NAMES:
        words.pop(0)
    while words and text[words[-1][0]:words[-1][1]] in NOT_NAMES:
        words.pop()
    if not words or any(text[a:b] in NOT_NAMES for a, b in words):
        return None
    s, e = words[0][0], words[-1][1]
    if PLACE_NEXT.match(text, e):
        return None
    return s, e


# --- Unregistered project names (v3.1) ---
# "Project SK" or "Project Blue Sky" that is not on the register may still be a codename,
# so it is redacted and the user is asked to confirm it is public. Ordinary phrases
# ("project manager", "Project Plan") are not names.
PROJECT_WORDS = {"manager", "management", "managers", "plan", "plans", "planning", "team", "teams", "lead", "leader",
                 "office", "status", "update", "updates", "report", "reports", "scope", "charter", "schedule", "budget",
                 "board", "meeting", "sponsor", "owner", "phase", "kickoff", "kick-off", "timeline", "risk", "risks",
                 "proposal", "brief", "summary", "review", "closeout", "close-out", "the", "a", "an", "and", "or", "to"}
_PROJECT_TOKEN = r"(?:[A-Z][\w\-]*|[\w\-]*\d[\w\-]*)"
_PROJECT_RE = re.compile(rf"\b(?i:project)\s+({_PROJECT_TOKEN}(?:\s+{_PROJECT_TOKEN})?)")


def _project_span(text: str, m: re.Match) -> tuple[int, int] | None:
    words = [(w.start() + m.start(1), w.end() + m.start(1)) for w in re.finditer(r"\S+", m.group(1))]
    while words and text[words[-1][0]:words[-1][1]].lower() in PROJECT_WORDS:
        words.pop()
    if not words or text[words[0][0]:words[0][1]].lower() in PROJECT_WORDS:
        return None
    return m.start(), words[-1][1]


# --- Normalisation (v4) ---
# Spoken digits in English and Afrikaans. A run only becomes a number when it has at
# least 3 spoken digits and 7 digits in all, so "one two buckle my shoe" stays text.
DIGIT_WORDS = {w: str(i) for i, w in enumerate("zero one two three four five six seven eight nine".split())}
DIGIT_WORDS |= {w: str(i) for i, w in enumerate("nul een twee drie vier vyf ses sewe agt nege".split())}
DIGIT_WORDS |= {"oh": "0", "nought": "0"}
REPEAT_WORDS = {"double": 2, "triple": 3, "dubbel": 2}
_TOKEN = r"(?:\b(?:" + "|".join(sorted(DIGIT_WORDS | REPEAT_WORDS, key=len, reverse=True)) + r")\b|\d+)"
_NUM_TOKEN = re.compile(rf"(?i){_TOKEN}")
_NUM_RUN = re.compile(rf"(?i){_TOKEN}(?:[\s,\-]+{_TOKEN})+")


def _spoken_digits(run: re.Match) -> list[tuple[str, int, int]] | None:
    """Digits in a run of tokens, each with the span it came from; None if it is not a spoken number."""
    out, spoken, repeat = [], 0, None
    for t in _NUM_TOKEN.finditer(run.group()):
        s, e, word = run.start() + t.start(), run.start() + t.end(), t.group().lower()
        if word in REPEAT_WORDS:
            repeat = (REPEAT_WORDS[word], s)
            continue
        if word.isdigit():
            out += [(ch, s + i, s + i + 1) for i, ch in enumerate(word)]
        else:
            n, s = (repeat[0], repeat[1]) if repeat else (1, s)
            out += [(DIGIT_WORDS[word], s, e)] * n
            spoken += 1
        repeat = None
    return out if spoken >= 3 and len(out) >= 7 else None


def normalise(text: str, spoken: bool = True, hidden: str = "") -> tuple[str, list[tuple[int, int]]]:
    """A cleaned-up view of `text`, and for each of its characters the span it came from in `text`.
    Hidden characters are dropped, or replaced by `hidden` (e.g. a space)."""
    chars: list[str] = []
    spans: list[tuple[int, int]] = []
    for i, ch in enumerate(text):
        if unicodedata.category(ch) == "Cf":  # zero-width, soft hyphen, word joiner, BOM ...
            chars += hidden
            spans += [(i, i + 1)] * len(hidden)
            continue
        if not ch.isascii() and (n := unicodedata.normalize("NFKC", ch)).isascii():
            ch = n  # fullwidth digits and letters, non-breaking space
        chars += ch
        spans += [(i, i + 1)] * len(ch)
    flat = "".join(chars)
    if not spoken:
        return flat, spans
    out: list[str] = []
    out_spans: list[tuple[int, int]] = []
    pos = 0
    for m in _NUM_RUN.finditer(flat):
        digits = _spoken_digits(m)
        if digits is None:
            continue
        out.append(flat[pos:m.start()])
        out_spans += spans[pos:m.start()]
        for d, s, e in digits:
            out.append(d)
            out_spans.append((spans[s][0], spans[e - 1][1]))
        pos = m.end()
    out.append(flat[pos:])
    out_spans += spans[pos:]
    return "".join(out), out_spans


def hidden_in_words(text: str) -> bool:
    """A hidden character between two letters or digits: rare in normal writing, common in evasion."""
    return any(unicodedata.category(ch) == "Cf" and 0 < i < len(text) - 1
               and text[i - 1].isalnum() and text[i + 1].isalnum() for i, ch in enumerate(text))


# When detections from different views overlap, the merged span keeps the first of these kinds.
KIND_PRIORITY = ["SECRET", "INTERNAL_TERM", "PROJECT", "SA_ID", "CARD", "BANK_ACCOUNT", "EMAIL", "PHONE", "NAME"]

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
    ("SECRET", re.compile(r"(?i)\bpass\s*[:=]\s*([^\s;,'\"]{4,})"), strong_secret, False),
    # v3: unlabelled "user / password" or "user:password" pairs, kept only if the password looks real
    ("SECRET", re.compile(r"(?i)\b(?!https?\b|ftp\b)[a-z][\w.\-]{1,30}\s*[/:]\s*(?!/)([^\s;,'\"]{8,})"), complex_secret, False),
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
        views = [(text, [(i, i + 1) for i in range(len(text))]), normalise(text, spoken=False), normalise(text)]
        for view, spans in views:
            for kind, s, e in self._detect_view(view):
                a, b = spans[s][0], spans[e - 1][1]
                # Overlapping detections from different views merge into one span covering all of
                # them, labelled with the most sensitive kind: merging may only redact more.
                overlap = [d for d in found if a < d.end and b > d.start]
                if overlap:
                    a, b = min([a] + [d.start for d in overlap]), max([b] + [d.end for d in overlap])
                    kind = min([kind] + [d.kind for d in overlap], key=KIND_PRIORITY.index)
                    found = [d for d in found if d not in overlap]
                found.append(Detection(kind, text[a:b], a, b))
        return sorted(found, key=lambda d: d.start)

    def _detect_view(self, view: str) -> list[tuple[str, int, int]]:
        found: list[tuple[str, int, int]] = []

        def free(s: int, e: int) -> bool:
            return all(e <= a or s >= b for _, a, b in found)

        def add(kind, s, e):
            found.append((kind, s, e))

        for kind, pat, check, ref_ctx in _DETECTORS:
            for m in pat.finditer(view):
                s, e = (m.start(1), m.end(1)) if m.lastindex else (m.start(), m.end())
                val = view[s:e]
                if check and not check(val):
                    continue
                if ref_ctx and REFERENCE_CONTEXT.search(view[max(0, s - 30):s]):
                    continue
                if free(s, e):
                    add(kind, s, e)
        for rx in (self._term_re, self._alias_re):
            if rx:
                for m in rx.finditer(view):
                    if free(m.start(), m.end()):
                        add("INTERNAL_TERM", m.start(), m.end())
        for m in _PROJECT_RE.finditer(view):
            span = _project_span(view, m)
            if span and free(*span):
                add("PROJECT", *span)
        for rx in (_TITLE_RE, _CUE_RE, _INITIAL_RE, _PAIR_RE):
            for m in rx.finditer(view):
                span = _trim_name(view, m.start(1), m.end(1))
                if span and free(*span):
                    add("NAME", *span)
        return found

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
