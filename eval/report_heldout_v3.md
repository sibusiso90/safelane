## SafeLane evaluation: heldout_v3.jsonl (30 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| EMAIL | 2 | 0 | 0 | 100.0% | 100.0% |
| NAME | 15 | 0 | 1 | 100.0% | 93.8% |
| PHONE | 1 | 0 | 0 | 100.0% | 100.0% |
| SECRET | 3 | 0 | 0 | 100.0% | 100.0% |

**Overall detection:** precision 100.0%, recall 95.5%
**Decision accuracy:** 96.7% (29/30)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 10 | 0 | 0 | 0 |
| MEDIUM | 1 | 14 | 0 | 0 |
| HIGH | 0 | 0 | 2 | 0 |
| BLOCKED | 0 | 0 | 0 | 3 |

**Leakage to external models:** baseline 20/20 sensitive values; with SafeLane 1/20

1 decision errors, e.g.:
- [name] expected MEDIUM, got LOW (R8_CLEAN): Make this sound more professional: tell sibongile the site visit moved to thursday
