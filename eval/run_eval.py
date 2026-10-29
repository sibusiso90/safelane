"""Evaluate SafeLane on the synthetic labelled set.

Reports:
  1. Detection precision / recall per entity type (value-level matching)
  2. Decision accuracy (gateway tier vs expected tier) with a confusion table
  3. Leakage: sensitive values that would reach an EXTERNAL model
       - baseline (policy + training only: nothing stops the paste)
       - with SafeLane
Writes eval/results.json and prints a markdown summary.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from safelane.policy import PolicyEngine, Register  # noqa: E402

TIERS = ["LOW", "MEDIUM", "HIGH", "BLOCKED"]
reg = Register(ROOT / "config" / "register.yaml")
eng = PolicyEngine(reg)
DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "eval" / "prompts.jsonl"
rows = [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]

norm = lambda s: "".join(ch for ch in s.lower() if ch.isalnum())
tp, fp, fn = Counter(), Counter(), Counter()
confusion = defaultdict(Counter)
errors = []
base_leak = gw_leak = total_sensitive = 0

for r in rows:
    d = eng.evaluate(r["prompt"], r["tool_id"])
    found = {(x.kind, norm(x.value)) for x in d.redaction.detections}
    truth = {(k, norm(v)) for k, v in r["entities"] if k != "NAME"}
    for k, v in truth:
        (tp if (k, v) in found else fn)[k] += 1
    for k, v in found:
        if (k, v) not in truth:
            fp[k] += 1
    for k, v in r["entities"]:
        if k == "NAME":
            fn["NAME (not in scope)"] += 0 if norm(v) in {fv for _, fv in found} else 1
    confusion[r["expected_tier"]][d.tier] += 1
    if d.tier != r["expected_tier"]:
        errors.append({"category": r["category"], "expected": r["expected_tier"], "got": d.tier,
                       "rule": d.rule, "prompt": r["prompt"]})
    # Leakage to external (non on-prem) tools
    tool = reg.get(r["tool_id"])
    if tool.get("hosting") != "on_prem":
        sens = [v for k, v in r["entities"] if k != "NAME"]
        total_sensitive += len(sens)
        base_leak += len(sens)  # baseline: nothing technical stops the paste
        sent = d.outbound_prompt or ""
        gw_leak += sum(1 for v in sens if norm(v) in norm(sent))

types = sorted(set(tp) | set(fn) | set(fp))
det = {}
for k in types:
    p = tp[k] / (tp[k] + fp[k]) if tp[k] + fp[k] else None
    rc = tp[k] / (tp[k] + fn[k]) if tp[k] + fn[k] else None
    det[k] = {"tp": tp[k], "fp": fp[k], "fn": fn[k], "precision": p, "recall": rc}
all_tp, all_fp, all_fn = (sum(c[k] for k in types if not k.startswith("NAME")) for c in (tp, fp, fn))
correct = sum(confusion[t][t] for t in TIERS)
res = {
    "prompts": len(rows),
    "detection": det,
    "detection_overall": {"precision": all_tp / (all_tp + all_fp) if all_tp + all_fp else None,
                          "recall": all_tp / (all_tp + all_fn) if all_tp + all_fn else None},
    "decision_accuracy": correct / len(rows),
    "confusion": {t: dict(confusion[t]) for t in TIERS},
    "leakage": {"sensitive_values_bound_for_external_models": total_sensitive,
                "baseline_leaked": base_leak, "gateway_leaked": gw_leak},
    "names_missed": fn["NAME (not in scope)"],
    "errors": errors,
}
(ROOT / "eval" / f"results_{DATA.stem}.json").write_text(json.dumps(res, indent=2))

pct = lambda x: "n/a" if x is None else f"{x*100:.1f}%"
print(f"## SafeLane evaluation: {DATA.name} ({len(rows)} synthetic prompts)\n")
print("| Entity type | TP | FP | FN | Precision | Recall |\n|---|---|---|---|---|---|")
for k, v in det.items():
    print(f"| {k} | {v['tp']} | {v['fp']} | {v['fn']} | {pct(v['precision'])} | {pct(v['recall'])} |")
print(f"\n**Overall detection (in-scope types):** precision {pct(res['detection_overall']['precision'])}, "
      f"recall {pct(res['detection_overall']['recall'])}")
print(f"**Decision accuracy:** {pct(res['decision_accuracy'])} ({correct}/{len(rows)})\n")
print("| Expected \\ Got | " + " | ".join(TIERS) + " |\n|---|" + "---|" * len(TIERS))
for t in TIERS:
    print(f"| {t} | " + " | ".join(str(confusion[t][g]) for g in TIERS) + " |")
L = res["leakage"]
print(f"\n**Leakage to external models:** baseline {L['baseline_leaked']}/{L['sensitive_values_bound_for_external_models']} "
      f"sensitive values; with SafeLane {L['gateway_leaked']}/{L['sensitive_values_bound_for_external_models']}")
if res["names_missed"]:
    print(f"**Known gap:** {res['names_missed']} free-text person names not detected (no NER yet)")
if errors:
    print(f"\n{len(errors)} decision errors, e.g.:")
    for e in errors:
        print(f"- [{e['category']}] expected {e['expected']}, got {e['got']} ({e['rule']}): {e['prompt'][:90]}")
