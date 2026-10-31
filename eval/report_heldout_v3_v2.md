## SafeLane evaluation: heldout_v3.jsonl (30 synthetic prompts)

| Entity type | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| EMAIL | 2 | 0 | 0 | 100.0% | 100.0% |
| NAME | 0 | 0 | 16 | n/a | 0.0% |
| PHONE | 1 | 0 | 0 | 100.0% | 100.0% |
| SECRET | 0 | 0 | 3 | n/a | 0.0% |

**Overall detection:** precision 100.0%, recall 13.6%
**Decision accuracy:** 50.0% (15/30)

| Expected \ Got | LOW | MEDIUM | HIGH | BLOCKED |
|---|---|---|---|---|
| LOW | 10 | 0 | 0 | 0 |
| MEDIUM | 12 | 3 | 0 | 0 |
| HIGH | 0 | 0 | 2 | 0 |
| BLOCKED | 3 | 0 | 0 | 0 |

**Leakage to external models:** baseline 20/20 sensitive values; with SafeLane 17/20

15 decision errors, e.g.:
- [name] expected MEDIUM, got LOW (R8_CLEAN): Please draft a thank-you note to Mrs Zodwa Mthembu for hosting the depot open day.
- [name] expected MEDIUM, got LOW (R8_CLEAN): Summarise this complaint: 'I, Kobus Steenkamp, was billed twice for March.'
- [name] expected MEDIUM, got LOW (R8_CLEAN): Translate into Afrikaans: Dear Ms Fourie, your application has been received.
- [name] expected MEDIUM, got LOW (R8_CLEAN): Ravi Govender from procurement asked for a summary of the fleet policy. Write it in three 
- [name] expected MEDIUM, got LOW (R8_CLEAN): Make this sound more professional: tell sibongile the site visit moved to thursday
- [name] expected MEDIUM, got LOW (R8_CLEAN): Write a birthday message for Ntombi in the finance team.
- [name] expected MEDIUM, got LOW (R8_CLEAN): Dr. Anele Ngcobo will present the safety stats; write a short introduction for the speaker
- [name] expected MEDIUM, got LOW (R8_CLEAN): Rephrase: Prof van der Merwe disagrees with the load-shedding forecast.
- [name] expected MEDIUM, got LOW (R8_CLEAN): Draft an e-mail to Mandla Zungu-Botha confirming the transfer to the Mthatha depot.
- [name] expected MEDIUM, got LOW (R8_CLEAN): Can you check the grammar: 'Regards, Chantelle Adams, Customer Care'
- [name] expected MEDIUM, got LOW (R8_CLEAN): Write onboarding notes for our new technician, Lwazi Mabuza.
- [name] expected MEDIUM, got LOW (R8_CLEAN): Meeting notes: attendees were J. Pretorius, N. Mokoena and the regional manager.
- [secret] expected BLOCKED, got LOW (R8_CLEAN): VPN login is user: kmolefe pass: Spring#2026 - write the remote-access guide.
- [secret] expected BLOCKED, got LOW (R8_CLEAN): Use root / Tr4nsf0rmer! to explain how to reset the router config.
- [secret] expected BLOCKED, got LOW (R8_CLEAN): Credentials for the meter portal are ops_admin:Q7v!pz92, summarise how to rotate them.
