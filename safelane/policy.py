"""Risk-tiered policy engine.

Turns (user, tool, prompt) into one of four decisions:
  LOW      -> send as-is
  MEDIUM   -> send the redacted prompt automatically
  HIGH     -> hold for a human reviewer before anything is sent
  BLOCKED  -> refuse, explain why, and point to an approved alternative

Rules are evaluated in a fixed order and every decision records which rule fired,
so a reviewer (or auditor) can see *why* - not just *what*.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .redactor import Redactor, RedactionResult

CLASS_ORDER = ["public", "internal", "personal", "confidential", "secret"]

# What each detection implies about the original prompt's sensitivity
KIND_TO_CLASS = {
    "EMAIL": "personal",
    "PHONE": "personal",
    "SA_ID": "personal",
    "BANK_ACCOUNT": "personal",
    "CARD": "personal",
    "NAME": "personal",
    "INTERNAL_TERM": "confidential",
    "SECRET": "secret",
}

# Tasks where an AI answer could drive a consequential decision about a person or money.
# v2: a decision cue AND a person/money object must both appear, so "how should we hire
# better graduates?" (a general question) is not held, but "should we hire Sipho?" is.
# A few isiZulu / Afrikaans cues are included because staff do not only write in English.
STRONG_IMPACT = re.compile(
    r"(?i)\b(disciplinary (?:hearing|action)|performance rating|retrench\w*|dismiss\w*|terminate\w*|"
    r"credit (?:decision|score)|medical (?:advice|diagnosis)|legal opinion)\b"
)
DECISION_CUE = re.compile(
    r"(?i)((?<!how )\bshould (?:we|i)\b|\bwho (?:should|gets)\b|\bwhich\b.{0,40}\bshould\b|\bdecide (?:whether|if)\b|"
    r"\bdecide\b|\byes or no\b|\bor not\b|\brank\b|\bshortlist\b|\brecommend whether\b|\btell me who\b|"
    r"\bnoma cha\b|\bkufanele\b|\bof nie\b|\bmoet ons\b)"
)
DECISION_OBJECT = re.compile(
    r"(?i)\b(applicants?|candidates?|cvs?|employees?|staff|contract|job offer|role|hire|hiring|fire|promot\w*|"
    r"loan|claim|credit|payment|pay out|reject|drop|qash\w*|siqashe|xosh\w*|aanstel\w*|afdank\w*)\b"
)


def high_impact(prompt: str) -> bool:
    if STRONG_IMPACT.search(prompt):
        return True
    return bool(DECISION_CUE.search(prompt) and DECISION_OBJECT.search(prompt))


# Misuse / prompt-injection / control-evasion indicators.
MISUSE = re.compile(
    r"(?i)((?:ignore|disregard|forget)\b.{0,25}\b(?:instructions|rules|guidelines)|"
    r"(?:disable|turn off|switch off|remove)\s+(?:the\s+)?(?:logging|audit\w*|redaction|filter\w*|guardrails?)|"
    r"(?:logging|audit\w*|redaction)\b.{0,20}\b(?:is |are )?(?:turned |switched )?off|"
    r"bypass (?:the )?(?:filter|gateway|policy|dlp|redaction)|exfiltrat\w+|jailbreak|developer mode|\bDAN\b|"
    r"unrestricted (?:assistant|mode|ai)|pretend (?:you are|to be) (?:the )?(?:admin|system)|"
    r"(?:reveal|print|show|output)\b.{0,20}\b(?:system prompt|redaction mapping|mapping table|other users)|"
    r"what other users (?:asked|typed|sent))"
)


@dataclass
class Decision:
    tier: str
    rule: str
    reason: str
    tool_id: str
    original_class: str
    redaction: RedactionResult
    alternatives: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    @property
    def outbound_prompt(self) -> str | None:
        if self.tier == "BLOCKED":
            return None
        return self.redaction.original if self.tier == "LOW" else self.redaction.redacted


def _max_class(classes) -> str:
    idx = max((CLASS_ORDER.index(c) for c in classes), default=CLASS_ORDER.index("internal"))
    return CLASS_ORDER[idx]


class Register:
    def __init__(self, path: str | Path):
        data = yaml.safe_load(Path(path).read_text())
        self.organisation = data.get("organisation", "")
        self.tools = {t["id"]: t for t in data["tools"]}
        self.sensitive_terms = data.get("sensitive_terms", [])

    def get(self, tool_id: str) -> dict:
        # Default deny: anything not on the register is treated as not approved.
        return self.tools.get(tool_id, {
            "id": tool_id, "name": tool_id, "status": "not_approved",
            "hosting": "unknown", "max_data_class": "public", "underlying_model_vendor": "unknown",
        })

    def approved_for(self, data_class: str) -> list[str]:
        need = CLASS_ORDER.index(data_class)
        return [t["id"] for t in self.tools.values()
                if t["status"] == "approved" and CLASS_ORDER.index(t["max_data_class"]) >= need]


class PolicyEngine:
    def __init__(self, register: Register):
        self.register = register
        self.redactor = Redactor(register.sensitive_terms)

    def evaluate(self, prompt: str, tool_id: str, declared_class: str = "internal") -> Decision:
        tool = self.register.get(tool_id)
        red = self.redactor.redact(prompt)
        original_class = _max_class([declared_class] + [KIND_TO_CLASS[k] for k in red.kinds])
        # After redaction, the detected values are gone; what remains is the user's declared class.
        residual_class = declared_class
        flags: list[str] = []
        if tool.get("hosting") == "offshore" and "personal" in {KIND_TO_CLASS[k] for k in red.kinds}:
            flags.append("POPIA s72: personal information would cross the border - redaction enforced")

        def d(tier, rule, reason, alts=None):
            return Decision(tier, rule, reason, tool_id, original_class, red, alts or [], flags)

        status = tool["status"]
        if status in ("not_approved", "prohibited"):
            return d("BLOCKED", "R1_REGISTER",
                     f"'{tool['name']}' is {status.replace('_', ' ')} on the AI Tools Register.",
                     self.register.approved_for(residual_class))

        if MISUSE.search(prompt):
            flags.append("Security event: control-evasion or prompt-injection pattern")
            return d("BLOCKED", "R2_MISUSE", "Prompt matches a misuse / prompt-injection pattern.")

        if "SECRET" in red.kinds and tool.get("hosting") != "on_prem":
            flags.append("Credential exposure attempt: rotate the credential if it was real")
            return d("BLOCKED", "R3_SECRET",
                     "Credentials or keys must never be sent to an external AI service.",
                     [t for t in self.register.approved_for("secret") if self.register.get(t)["hosting"] == "on_prem"]
                     or self.register.approved_for("confidential"))

        if high_impact(prompt):
            return d("HIGH", "R4_HIGH_IMPACT",
                     "Task could drive a consequential decision about a person or money; a human must review.")

        if CLASS_ORDER.index(residual_class) > CLASS_ORDER.index(tool["max_data_class"]):
            if status == "restricted":
                return d("HIGH", "R5_CLASS_RESTRICTED",
                         f"{residual_class.title()} data on a restricted tool needs reviewer approval.",
                         self.register.approved_for(residual_class))
            return d("BLOCKED", "R5_CLASS",
                     f"{residual_class.title()} data exceeds what '{tool['name']}' is approved for.",
                     self.register.approved_for(residual_class))

        if status == "restricted" and red.detections:
            return d("HIGH", "R6_RESTRICTED_SENSITIVE",
                     "Sensitive data detected on a restricted tool; reviewer approval required.",
                     self.register.approved_for(original_class))

        if red.detections:
            kinds = ", ".join(sorted(red.kinds))
            return d("MEDIUM", "R7_REDACT", f"Redacted before sending: {kinds}.")

        return d("LOW", "R8_CLEAN", "No sensitive data detected.")


def check_output(answer: str, decision: Decision, redactor: Redactor) -> list[str]:
    """Checks on what comes BACK from the model (the brief asks how outputs are checked)."""
    warnings = []
    # `answer` is the raw model output, before placeholders are swapped back, so any
    # sensitive value in it did not come from the user's (redacted) prompt.
    leaked = redactor.detect(answer)
    if leaked:
        warnings.append("Answer contains sensitive-looking data the user did not send: " + ", ".join(sorted({d.kind for d in leaked})))
    unknown_ph = set(re.findall(r"\[[A-Z_]+_\d+\]", answer)) - set(decision.redaction.mapping)
    if unknown_ph:
        warnings.append("Answer references placeholders that were never issued (possible fabrication).")
    if decision.rule == "R4_HIGH_IMPACT":
        warnings.append("Draft only: a named person must make and own this decision.")
    if re.search(r"https?://", answer):
        warnings.append("Answer contains links: verify sources before relying on them.")
    return warnings
