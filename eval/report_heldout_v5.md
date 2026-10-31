## SafeLane evaluation: heldout_v5.jsonl (37 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| EMAIL | 5 | 1 | 1 | 83.3% | 83.3% |
| NAME | 14 | 3 | 16 | 82.4% | 46.7% |

**Overall detection:** precision 82.6%, recall 52.8%
**Decision accuracy:** 86.5% (32/37)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 13 | 1 | 0 | 0 |
| MEDIUM | 4 | 19 | 0 | 0 |
| HIGH | 0 | 0 | 0 | 0 |
| BLOCKED | 0 | 0 | 0 | 0 |

**Leakage to external models:** baseline 36/36 sensitive values; with SafeLane 15/36

5 decision errors, e.g.:
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): pls draft a thank you msg for nomvula, she covered the call centre all weekend
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): email rajesh naidoo the minutes from this morning and say sorry for the delay
- [single_name] expected MEDIUM, got LOW (R8_CLEAN): Translate into isiZulu: Zanele will collect the keys from reception tomorrow.
- [name_list] expected MEDIUM, got LOW (R8_CLEAN): Summarise the roster: Morning shift – Palesa, Gert. Afternoon shift – Themba, Shireen.
- [hard_negative] expected LOW, got MEDIUM (R7_REDACT): Translate into Afrikaans: The Durban and Polokwane depots will close early on Heritage Day
