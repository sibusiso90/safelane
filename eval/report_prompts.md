## SafeLane evaluation: prompts.jsonl (180 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| BANK_ACCOUNT | 20 | 0 | 0 | 100.0% | 100.0% |
| CARD | 10 | 0 | 0 | 100.0% | 100.0% |
| EMAIL | 35 | 0 | 0 | 100.0% | 100.0% |
| INTERNAL_TERM | 15 | 0 | 0 | 100.0% | 100.0% |
| NAME | 55 | 0 | 15 | 100.0% | 78.6% |
| PHONE | 25 | 0 | 0 | 100.0% | 100.0% |
| SA_ID | 20 | 0 | 0 | 100.0% | 100.0% |
| SECRET | 15 | 0 | 0 | 100.0% | 100.0% |

**Overall detection:** precision 100.0%, recall 92.9%
**Decision accuracy:** 100.0% (180/180)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 50 | 0 | 0 | 0 |
| MEDIUM | 0 | 70 | 0 | 0 |
| HIGH | 0 | 0 | 25 | 0 |
| BLOCKED | 0 | 0 | 0 | 35 |

**Leakage to external models:** baseline 195/195 sensitive values; with SafeLane 0/195
