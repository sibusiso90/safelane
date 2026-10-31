"""Fail if any evaluation set scores below its recorded result.

Run after `run_eval.py` on each set (CI does both). The floors are the published
numbers in eval/README.md, so a change that makes any set worse fails the build.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# set: (minimum decision accuracy, maximum sensitive values reaching an external model)
FLOORS = {
    "prompts": (1.0, 0),
    "adversarial": (1.0, 0),
    "heldout": (1.0, 0),
    "heldout_v3": (1.0, 0),
    "heldout_v4": (1.0, 0),
    "heldout_v5": (32 / 37, 15),
}

failed = False
for name, (min_acc, max_leak) in FLOORS.items():
    res = json.loads((ROOT / f"results_{name}.json").read_text())
    acc, leak = res["decision_accuracy"], res["leakage"]["gateway_leaked"]
    ok = acc >= min_acc - 1e-9 and leak <= max_leak
    failed |= not ok
    print(f"{'ok  ' if ok else 'FAIL'} {name}: decisions {acc:.1%} (min {min_acc:.1%}), leaked {leak} (max {max_leak})")
sys.exit(1 if failed else 0)
