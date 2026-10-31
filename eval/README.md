# Evaluation

All prompts are synthetic. Every name, ID number, card, account, key and codename was generated or invented. None is real.

## Three test sets, three purposes

| Set | Size | How it was made | What it shows |
|---|---|---|---|
| `prompts.jsonl` | 180 | Generated from templates (`generate_dataset.py`, fixed seed) | The rules work on the formats they were written for. This is a regression set, **not** evidence of real-world accuracy. |
| `adversarial.jsonl` | 40 | Hand-written to break v1: odd formats, obfuscation, other languages, hard negatives | Where v1 failed. v2 was then improved **using this set**, so it is no longer a blind test. |
| `heldout.jsonl` | 20 | Hand-written **before** the v2 changes and not used for tuning | A blind test of v2. v3 was built after its result was published, so for v3 it is no longer blind. |
| `heldout_v3.jsonl` | 30 | Hand-written and committed (`b4734cf`) **before** any v3 code, and scored against v2 at that point | A blind test of v3: person names, unlabelled credentials and hard negatives (places, weekdays, a street named after a person, `admin/admin`). |
| `heldout_v4.jsonl` | 26 | Written after judges' feedback and committed (`b78c1c2`) **before** any v4 code, and scored against v3.1 at that point | A test of v4: values hidden with invisible or look-alike characters, spelled-out numbers (English, Afrikaans, *double five*), a split-word injection, and hard negatives (counting, quantities, an invoice number in words, a bad-checksum ID). |

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
| Held-out 3 (26) | v3.1 | 0%† | 0% | 34.6% | 16 / 17 |
| **Held-out 3 (26)** | **v4** | **100%** | **100%** | **100%** | **0 / 17** |

From v3 on, person names count towards detection and leakage. Re-running the older sets with v3 (names now counted): templated 100% / 92.9%, 100% decisions, 0 / 195 leaked; adversarial 88.9% / 96.0%, 100%, 0 / 25; held-out 1 90.0% / 90.0%, 100%, 0 / 10 (not blind for v3). On the adversarial set, one of the "false positives" is a real name (*Kagiso Khumalo*) that the set never labelled, because names were out of scope when it was written. The labels were left as they are.

†v3.1 caught one value, a fullwidth-digit ID, but labelled it a card, because the ID check compared the citizenship digit with ASCII "0"/"1".

\*Baseline (policy + training only, with no technical control) is every value, because nothing stops the paste.

Policy check latency: about 0.07 ms per prompt for v2 on a 2-vCPU cloud sandbox (4,800 evaluations), about 0.05 ms for v3 on an Apple-silicon laptop (5,400 evaluations), and about 0.19 ms for v4 on the same laptop (5,920 evaluations; the detectors now run on three views of each prompt). The gateway adds effectively no delay compared with the model call.

## What v2 changed (from the adversarial failures)
Spaced and hyphenated numbers; `+27 (0)` and `(011)` phone formats; obfuscated e-mails (`name at domain dot com`, `[at]`); JWTs, bearer tokens and `password is X`; account numbers after a bank name; case-sensitive codename aliases (catches *Kestrel* the project but not *kestrel* the bird); ignoring numbers labelled as invoice, order, serial or reference; an allow-list of public test card numbers; a minimum-strength check for "secrets"; high-impact detection that needs a decision cue *and* a person/money object (so general HR questions pass); and a few isiZulu and Afrikaans decision cues.

Two adversarial labels were corrected after v1, and only to set where a secret starts and ends (the password inside a connection string; the token after `Bearer`). No decision label changed.

## What v3 changed
Person names, found from the words around them rather than from a list of first names: titles (*Ms Fourie*, *Prof van der Merwe*), greetings and sign-offs (*Dear …*, *Regards, …*), addressing words (*tell*, *for*, *to*, *technician*), initials (*J. Pretorius*), and two capitalised words followed by something a person does (*… from procurement asked*, *…'s*). Words that name places, days, months and organisations are excluded, and so is a name followed by *Drive*, *Act*, *depot* and the like. For credentials: `pass:` labels, and `user / password` or `user:password` pairs when the password has at least 8 characters and 3 of the 4 character classes.

The held-out 2 miss is `tell sibongile …`: a name in lower case. Catching it needs a name list or an NER model, and a hand-made name list would have been written by someone who had already seen the test set.

## Found by manual testing after v3 (v3.1)
*"can we fire the person based on the notes"* was sent straight to an approved model as LOW: the high-impact rule (R4) only knew phrasings like *"should we …"*. v3.1 also treats *can / could / may / must / do we* followed directly by a decision verb (*fire, dismiss, reject, approve, let … go, hire* a person) as high impact, without catching everyday questions like *"can we summarise the staff newsletter?"* or *"can we fire up the generator?"*. Also from hands-on testing: *"give me 2 lines on project SK to post on linkedin"* went out as LOW because "Project SK" is not on the register. v3.1 redacts any *Project …* name that is not registered (type `PROJECT`, treated as confidential) and asks the user to confirm it is public; ordinary phrases such as *project manager* or *Project Plan* are left alone. Neither change came from a blind test set, so no held-out number is claimed for them. Every set scores the same as before, and the cases are now unit tests.

## What v4 changed (after judges' feedback)
Every detector, and the misuse and high-impact rules, now runs on a normalised view of the prompt: invisible format characters (zero-width space, joiner and non-joiner, soft hyphen, word joiner, byte-order mark) are removed; look-alike characters such as fullwidth digits become ASCII; and a run of at least 3 spoken digits and 7 digits in all becomes a number (*eight zero zero …*, *double five*, *oh one one*, Afrikaans *agt nul nul*, or digits mixed with words). An offset map sends each detection back to the exact original characters, so the redacted prompt and the audit log still hold placeholders, and rehydration restores the user's text unchanged. Short runs (*one two buckle my shoe*, *three pallets and four boxes*) are left as text. The older sets score exactly as before.

An automated security review of the first v4 commit found that normalising could also *remove* detections: a hidden character could glue an extra digit onto an ID (`8001015009087`+zero-width+`1`), spoken digits beside a phone number turned it into one long number (*0825550143 one two three*), and a hidden character between two words could stop the misuse rule matching (*ignore*+zero-width+*previous instructions*). v3.1 caught all three. The detectors now run on the raw text, the text with hidden characters removed, and the fully normalised text, and the results are merged so a later view can widen a detection but never drop one. The misuse and high-impact rules fire if either the raw or the cleaned text matches. Those cases are now unit tests. The ID checksum also reads fullwidth digits correctly now. A second review found two more gaps. When a detection from one view only partly overlapped one from another, the merge dropped it: in *Dear Thabo Eight Zero Zero …* the name detector took *Thabo Eight Zero*, and most of the spoken ID went out. Overlapping detections now merge into one span covering all of them, labelled with the most sensitive kind, so merging can only redact more. The second gap: hidden characters can split one word and glue the next in the same prompt (*dis*+zero-width+*regard*+zero-width+*all previous instructions*), and no single view caught that. Any prompt with hidden characters inside a word (one, or a run of them) is now flagged as a possible evasion attempt, and for any prompt that contains a hidden character at all, the misuse and high-impact rules are also matched without word boundaries. That adds false positives, but only on text carrying characters that normal writing rarely has. (A third review pass found the first version of this check missed runs of two or more hidden characters in a row; that is fixed and tested.) Held-out 3 was re-run after these fixes as a regression check only (it is no longer blind) and gives the same result.

The v4 held-out result (100%) should carry the least weight of any held-out number here. The set was written to cover the specific bypasses the judges reported, by the same author who then wrote the fix, so it shows that the reported gaps are closed, not that obfuscation in general is handled.

## Honest limits
- **v2 held-out miss, fixed in v3:** `admin / P@ssw0rd2026`, a username/password pair with no "password" label. It was deliberately not patched before v2 was reported. v3's credential-pair rule catches it, and its effect was measured on held-out 2, not on the set that exposed it.
- **Names are found from context only.** A name with no cue, in lower case, or in a bare list (*Sipho, Thandi and Mike will attend*) is missed, and company or famous names that look like people (*Grant Thornton from audit*) are redacted when they need not be. 15 of the 70 names in the templated set are still missed. The next step is an on-prem NER model (e.g. a small multilingual model) behind the same interface.
- **Small, self-written test sets.** The same person wrote the rules and the tests. Held-out 2 was committed before the v3 code, but its author still knew what v3 would try to catch. A real pilot needs red-teaming by people who did not write the rules, and a sample of real (consented, redacted) prompts.
- **Obfuscation has no end.** Not handled: digits in isiZulu or other languages, a number split across lines or messages, a number in an image, or text the model is asked to decode (reversed digits, base64, *add one to each digit*).
- **Detection will never be perfect.** That is why the design routes most work to the on-prem model by default: a missed value there stays inside the organisation.
