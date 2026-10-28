# Evaluation

All prompts are synthetic. Every name, ID number, card, account, key and codename was generated or invented. None is real.

## Three test sets, three purposes

| Set | Size | How it was made | What it shows |
|---|---|---|---|
| `prompts.jsonl` | 180 | Generated from templates (`generate_dataset.py`, fixed seed) | The rules work on the formats they were written for. This is a regression set, **not** evidence of real-world accuracy. |
| `adversarial.jsonl` | 40 | Hand-written to break v1: odd formats, obfuscation, other languages, hard negatives | Where v1 failed. v2 was then improved **using this set**, so it is no longer a blind test. |
| `heldout.jsonl` | 20 | Hand-written **before** the v2 changes and not used for tuning | The fairest estimate we have of how v2 handles prompts it was not tuned on. |

Run: `python eval/run_eval.py eval/<set>.jsonl` (writes `results_<set>.json`; the `report_<set>.md` files are saved outputs).

## Results

| Set | Version | Detection precision | Detection recall | Decision accuracy | Sensitive values reaching an external model* |
|---|---|---|---|---|---|
| Templated (180) | v2 | 100% | 100% | 100% | 0 / 140 |
| Adversarial (40) | v1 | 70.0% | 56.0% | 52.5% | 9 / 25 |
| Adversarial (40) | v2 (tuned on it) | 96.0% | 96.0% | 100% | 0 / 25 |
| Held-out (20) | v1 | 80.0% | 40.0% | 45.0% | 5 / 10 |
| **Held-out (20)** | **v2** | **88.9%** | **80.0%** | **95.0%** | **1 / 10** |

\*Baseline (policy + training only, with no technical control) is every value, i.e. 140/140, 25/25 and 10/10, because nothing stops the paste.

Policy check latency: about 0.07 ms per prompt on a 2-vCPU cloud sandbox (4,800 evaluations). The gateway adds effectively no delay compared with the model call.

## What v2 changed (from the adversarial failures)
Spaced and hyphenated numbers; `+27 (0)` and `(011)` phone formats; obfuscated e-mails (`name at domain dot com`, `[at]`); JWTs, bearer tokens and `password is X`; account numbers after a bank name; case-sensitive codename aliases (catches *Kestrel* the project but not *kestrel* the bird); ignoring numbers labelled as invoice, order, serial or reference; an allow-list of public test card numbers; a minimum-strength check for "secrets"; high-impact detection that needs a decision cue *and* a person/money object (so general HR questions pass); and a few isiZulu and Afrikaans decision cues.

Two adversarial labels were corrected after v1, and only to set where a secret starts and ends (the password inside a connection string; the token after `Bearer`). No decision label changed.

## Honest limits
- **Held-out miss:** `admin / P@ssw0rd2026`, a username/password pair with no "password" label, got through. In a utility (SCADA historian) that is the worst kind of miss. The fix is a credential-pair detector plus entropy scoring. It was deliberately **not** added before reporting, so the held-out number stays honest.
- **Names are not detected.** That's 70 free-text names in the templated set. Names alone are lower risk than IDs or accounts, but combined with context they identify people. The next step is an on-prem NER model (e.g. a small multilingual model) behind the same interface.
- **Small, self-written test sets.** The same person wrote the rules and the tests. A real pilot needs red-teaming by people who did not write the rules, and a sample of real (consented, redacted) prompts.
- **Detection will never be perfect.** That is why the design routes most work to the on-prem model by default: a missed value there stays inside the organisation.
