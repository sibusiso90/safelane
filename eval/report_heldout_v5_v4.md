## SafeLane evaluation: heldout_v5.jsonl (37 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| EMAIL | 5 | 3 | 1 | 62.5% | 83.3% |
| NAME | 5 | 1 | 25 | 83.3% | 16.7% |

**Overall detection:** precision 71.4%, recall 27.8%
**Decision accuracy:** 56.8% (21/37)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 11 | 3 | 0 | 0 |
| MEDIUM | 13 | 10 | 0 | 0 |
| HIGH | 0 | 0 | 0 | 0 |
| BLOCKED | 0 | 0 | 0 | 0 |

**Leakage to external models:** baseline 36/36 sensitive values; with SafeLane 25/36

16 decision errors, e.g.:
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): tell sibongile the site visit moved to thursday and ask her to bring the meter readings
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): cc johan on the outage summary and make the tone a bit friendlier
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): can you write a short note to remind lerato that the safety training starts at 9
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): pls draft a thank you msg for nomvula, she covered the call centre all weekend
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): invite pieter van wyk and keabetswe to the planning session, keep it short
- [lowercase_name] expected MEDIUM, got LOW (R8_CLEAN): email rajesh naidoo the minutes from this morning and say sorry for the delay
- [single_name] expected MEDIUM, got LOW (R8_CLEAN): Thabo finished the meter audit early. Write a short shout-out for the team newsletter.
- [single_name] expected MEDIUM, got LOW (R8_CLEAN): Sipho's leave starts Monday, so draft a handover note for the Pretoria depot.
- [single_name] expected MEDIUM, got LOW (R8_CLEAN): Translate into isiZulu: Zanele will collect the keys from reception tomorrow.
- [single_name] expected MEDIUM, got LOW (R8_CLEAN): Summarise this for the depot noticeboard: Kagiso says the new pumps are louder than expect
- [name_list] expected MEDIUM, got LOW (R8_CLEAN): Ayanda, Pieter and Fatima will attend the water-quality workshop. Draft the joining instru
- [name_list] expected MEDIUM, got LOW (R8_CLEAN): please put tumi, marike and yusuf on the cc line and draft a one-paragraph update on the p
- [name_list] expected MEDIUM, got LOW (R8_CLEAN): Summarise the roster: Morning shift – Palesa, Gert. Afternoon shift – Themba, Shireen.
- [hard_negative] expected LOW, got MEDIUM (R7_REDACT): The full outage details are at acme-utilities.co.za/outages — summarise them in two senten
- [hard_negative] expected LOW, got MEDIUM (R7_REDACT): Translate into Afrikaans: The Durban and Polokwane depots will close early on Heritage Day
- [hard_negative] expected LOW, got MEDIUM (R7_REDACT): Customers can pay at any Pick n Pay or at www.acme-utilities.co.za. Write that as a short 
