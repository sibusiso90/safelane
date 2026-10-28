## SafeLane evaluation: adversarial.jsonl (40 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| BANK_ACCOUNT | 2 | 0 | 0 | 100.0% | 100.0% |
| CARD | 2 | 0 | 0 | 100.0% | 100.0% |
| EMAIL | 4 | 0 | 0 | 100.0% | 100.0% |
| INTERNAL_TERM | 3 | 1 | 1 | 75.0% | 75.0% |
| PHONE | 5 | 0 | 0 | 100.0% | 100.0% |
| SA_ID | 3 | 0 | 0 | 100.0% | 100.0% |
| SECRET | 5 | 0 | 0 | 100.0% | 100.0% |

**Overall detection (in-scope types):** precision 96.0%, recall 96.0%
**Decision accuracy:** 100.0% (40/40)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 9 | 0 | 0 | 0 |
| MEDIUM | 0 | 16 | 0 | 0 |
| HIGH | 0 | 0 | 6 | 0 |
| BLOCKED | 0 | 0 | 0 | 9 |

**Leakage to external models:** baseline 25/25 sensitive values; with SafeLane 0/25
**Known gap:** 0 free-text person names not detected (no NER yet)
