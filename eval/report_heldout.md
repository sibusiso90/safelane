## SafeLane evaluation: heldout.jsonl (20 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| BANK_ACCOUNT | 1 | 0 | 0 | 100.0% | 100.0% |
| EMAIL | 2 | 0 | 0 | 100.0% | 100.0% |
| INTERNAL_TERM | 1 | 1 | 1 | 50.0% | 50.0% |
| PHONE | 1 | 0 | 0 | 100.0% | 100.0% |
| SA_ID | 1 | 0 | 0 | 100.0% | 100.0% |
| SECRET | 2 | 0 | 1 | 100.0% | 66.7% |

**Overall detection (in-scope types):** precision 88.9%, recall 80.0%
**Decision accuracy:** 95.0% (19/20)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 5 | 0 | 0 | 0 |
| MEDIUM | 0 | 7 | 0 | 0 |
| HIGH | 0 | 0 | 3 | 0 |
| BLOCKED | 1 | 0 | 0 | 4 |

**Leakage to external models:** baseline 10/10 sensitive values; with SafeLane 1/10
**Known gap:** 0 free-text person names not detected (no NER yet)

1 decision errors, e.g.:
- [secret] expected BLOCKED, got LOW (R8_CLEAN): Login for the SCADA historian is admin / P@ssw0rd2026, write the handover note.
