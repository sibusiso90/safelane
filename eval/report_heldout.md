## SafeLane evaluation: heldout.jsonl (20 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| BANK_ACCOUNT | 1 | 0 | 0 | 100.0% | 100.0% |
| EMAIL | 2 | 0 | 0 | 100.0% | 100.0% |
| INTERNAL_TERM | 1 | 1 | 1 | 50.0% | 50.0% |
| PHONE | 1 | 0 | 0 | 100.0% | 100.0% |
| SA_ID | 1 | 0 | 0 | 100.0% | 100.0% |
| SECRET | 3 | 0 | 0 | 100.0% | 100.0% |

**Overall detection:** precision 90.0%, recall 90.0%
**Decision accuracy:** 100.0% (20/20)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 5 | 0 | 0 | 0 |
| MEDIUM | 0 | 7 | 0 | 0 |
| HIGH | 0 | 0 | 3 | 0 |
| BLOCKED | 0 | 0 | 0 | 5 |

**Leakage to external models:** baseline 10/10 sensitive values; with SafeLane 0/10
