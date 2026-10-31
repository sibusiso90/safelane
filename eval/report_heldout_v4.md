## SafeLane evaluation: heldout_v4.jsonl (26 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| BANK_ACCOUNT | 2 | 0 | 0 | 100.0% | 100.0% |
| CARD | 2 | 0 | 0 | 100.0% | 100.0% |
| EMAIL | 1 | 0 | 0 | 100.0% | 100.0% |
| INTERNAL_TERM | 1 | 0 | 0 | 100.0% | 100.0% |
| PHONE | 3 | 0 | 0 | 100.0% | 100.0% |
| SA_ID | 8 | 0 | 0 | 100.0% | 100.0% |

**Overall detection:** precision 100.0%, recall 100.0%
**Decision accuracy:** 100.0% (26/26)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 8 | 0 | 0 | 0 |
| MEDIUM | 0 | 17 | 0 | 0 |
| HIGH | 0 | 0 | 0 | 0 |
| BLOCKED | 0 | 0 | 0 | 1 |

**Leakage to external models:** baseline 17/17 sensitive values; with SafeLane 0/17
