# Evaluation

All prompts are synthetic. Every name, ID number, card, account, key and codename was generated or invented. None is real.

## Three test sets, three purposes

| Set | Size | How it was made | What it shows |
|---|---|---|---|
| `prompts.jsonl` | 180 | Generated from templates (`generate_dataset.py`, fixed seed) | The rules work on the formats they were written for. This is a regression set, **not** evidence of real-world accuracy. |
| `adversarial.jsonl` | 40 | Hand-written to break v1: odd formats, obfuscation, other languages, hard negatives | Where v1 failed. v2 was then improved **using this set**, so it is no longer a blind test. |
| `heldout.jsonl` | 20 | Hand-written **before** the v2 changes and not used for tuning | A blind test of v2. v3 was built after its result was published, so for v3 it is no longer blind. |
| `heldout_v3.jsonl` | 30 | Hand-written and committed (`b4734cf`) **before** any v3 code, and scored against v2 at that point | A blind test of v3: person names, unlabelled credentials and hard negatives (places, weekdays, a street named after a person, `admin/admin`). |

Run: `python eval/run_eval.py eval/<set>.jsonl` (writes `results_<set>.json`; the `report_<set>.md` files are saved outputs).

## Results

| Set | Version | Detection precision | Detection recall | Decision accuracy | Sensitive values reaching an external model* |
|---|---|---|---|---|---|
| Templated (180) | v2 | 100% | 100% | 100% | 0 / 140 |
| Adversarial (40) | v1 | 70.0% | 56.0% | 52.5% | 9 / 25 |
| Adversarial (40) | v2 (tuned on it) | 96.0% | 96.0% | 100% | 0 / 25 |
| Held-out (20) | v1 | 80.0% | 40.0% | 45.0% | 5 / 10 |
| **Held-out (20)** | **v2** | **88.9%** | **80.0%** | **95.0%** | **1 / 10** |
| Held-out 2 (30) | v2 | 100% | 13.6% | 50.0% | 17 / 20 |
| **Held-out 2 (30)** | **v3** | **100%** | **95.5%** | **96.7%** | **1 / 20** |

From v3 on, person names count towards detection and leakage. Re-running the older sets with v3 (names now counted): templated 100% / 92.9%, 100% decisions, 0 / 195 leaked; adversarial 88.9% / 96.0%, 100%, 0 / 25; held-out 1 90.0% / 90.0%, 100%, 0 / 10 (not blind for v3). On the adversarial set, one of the "false positives" is a real name (*Kagiso Khumalo*) that the set never labelled, because names were out of scope when it was written. The labels were left as they are.

\*Baseline (policy + training only, with no technical control) is every value, because nothing stops the paste.

Policy check latency: about 0.07 ms per prompt for v2 on a 2-vCPU cloud sandbox (4,800 evaluations), and about 0.05 ms for v3 on an Apple-silicon laptop (5,400 evaluations). The gateway adds effectively no delay compared with the model call.

## What v2 changed (from the adversarial failures)
Spaced and hyphenated numbers; `+27 (0)` and `(011)` phone formats; obfuscated e-mails (`name at domain dot com`, `[at]`); JWTs, bearer tokens and `password is X`; account numbers after a bank name; case-sensitive codename aliases (catches *Kestrel* the project but not *kestrel* the bird); ignoring numbers labelled as invoice, order, serial or reference; an allow-list of public test card numbers; a minimum-strength check for "secrets"; high-impact detection that needs a decision cue *and* a person/money object (so general HR questions pass); and a few isiZulu and Afrikaans decision cues.

Two adversarial labels were corrected after v1, and only to set where a secret starts and ends (the password inside a connection string; the token after `Bearer`). No decision label changed.

## What v3 changed
Person names, found from the words around them rather than from a list of first names: titles (*Ms Fourie*, *Prof van der Merwe*), greetings and sign-offs (*Dear …*, *Regards, …*), addressing words (*tell*, *for*, *to*, *technician*), initials (*J. Pretorius*), and two capitalised words followed by something a person does (*… from procurement asked*, *…'s*). Words that name places, days, months and organisations are excluded, and so is a name followed by *Drive*, *Act*, *depot* and the like. For credentials: `pass:` labels, and `user / password` or `user:password` pairs when the password has at least 8 characters and 3 of the 4 character classes.

The held-out 2 miss is `tell sibongile …`: a name in lower case. Catching it needs a name list or an NER model, and a hand-made name list would have been written by someone who had already seen the test set.

## Found by manual testing after v3 (v3.1)
*"can we fire the person based on the notes"* was sent straight to an approved model as LOW: the high-impact rule (R4) only knew phrasings like *"should we …"*. v3.1 also treats *can / could / may / must / do we* followed directly by a decision verb (*fire, dismiss, reject, approve, let … go, hire* a person) as high impact, without catching everyday questions like *"can we summarise the staff newsletter?"* or *"can we fire up the generator?"*. This came from hands-on testing, not from a blind test set, so no held-out number is claimed for it. Every set scores the same as before, and the cases are now unit tests.

## Honest limits
- **v2 held-out miss, fixed in v3:** `admin / P@ssw0rd2026`, a username/password pair with no "password" label. It was deliberately not patched before v2 was reported. v3's credential-pair rule catches it, and its effect was measured on held-out 2, not on the set that exposed it.
- **Names are found from context only.** A name with no cue, in lower case, or in a bare list (*Sipho, Thandi and Mike will attend*) is missed, and company or famous names that look like people (*Grant Thornton from audit*) are redacted when they need not be. 15 of the 70 names in the templated set are still missed. The next step is an on-prem NER model (e.g. a small multilingual model) behind the same interface.
- **Small, self-written test sets.** The same person wrote the rules and the tests. Held-out 2 was committed before the v3 code, but its author still knew what v3 would try to catch. A real pilot needs red-teaming by people who did not write the rules, and a sample of real (consented, redacted) prompts.
- **Detection will never be perfect.** That is why the design routes most work to the on-prem model by default: a missed value there stays inside the organisation.
