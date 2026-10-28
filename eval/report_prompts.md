## SafeLane evaluation: prompts.jsonl (180 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| BANK_ACCOUNT | 20 | 0 | 0 | 100.0% | 100.0% |
| CARD | 10 | 0 | 0 | 100.0% | 100.0% |
| EMAIL | 35 | 0 | 0 | 100.0% | 100.0% |
| INTERNAL_TERM | 15 | 0 | 0 | 100.0% | 100.0% |
| NAME (not in scope) | 0 | 0 | 70 | n/a | 0.0% |
| PHONE | 25 | 0 | 0 | 100.0% | 100.0% |
| SA_ID | 20 | 0 | 0 | 100.0% | 100.0% |
| SECRET | 15 | 0 | 0 | 100.0% | 100.0% |

**Overall detection (in-scope types):** precision 100.0%, recall 100.0%
**Decision accuracy:** 100.0% (180/180)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 50 | 0 | 0 | 0 |
| MEDIUM | 0 | 70 | 0 | 0 |
| HIGH | 0 | 0 | 25 | 0 |
| BLOCKED | 0 | 0 | 0 | 35 |

**Leakage to external models:** baseline 140/140 sensitive values; with SafeLane 0/140
**Known gap:** 70 free-text person names not detected (no NER yet)
