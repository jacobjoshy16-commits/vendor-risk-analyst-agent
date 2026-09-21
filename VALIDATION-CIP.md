# Validation — NERC CIP module

The question this document answers is not "did it find something." It is
**"would it have stayed quiet if there were nothing to find."** A detector that
only ever fires is unfalsifiable, and an auditor who cannot see a negative
control has no reason to believe a positive one.

Run it:

```bash
python3 -m unittest tests.test_cip -v      # 32 tests
python3 -m unittest discover -s tests -t . # 441 tests, whole repo
```

---

## 1. Is the cryptography real?

This is the first thing to establish, because if verification is a stored field
then nothing else in the module means anything.

| Assertion | Test |
| --- | --- |
| A valid signature verifies | `test_a_valid_signature_verifies` |
| **Flipping one bit anywhere in the image breaks the signature** | `test_flipping_one_byte_breaks_the_signature` |
| Another vendor's key does not verify | `test_another_vendors_key_does_not_verify` |
| A malformed signature returns False rather than crashing the run | `test_malformed_signature_returns_false_rather_than_raising` |
| Fingerprints are stable and key-specific | `test_fingerprint_is_stable_and_key_specific` |

The bit-flip test is the load-bearing one. It XORs a single bit at three
offsets in an 8 KB image and requires verification to fail each time. No
implementation that reads a boolean out of YAML can pass it.

Verified independently:

```
$ python3 -c "...sign a blob, flip one byte, re-verify..."
valid sig  : True
tampered   : False
garbage    : False
wrong key  : False
```

---

## 2. Does it distinguish CIP-010 R1.6.1 from R1.6.2?

The two parts ask different questions and the module must not collapse them.

| Scenario | R1.6.1 source | R1.6.2 integrity | Test |
| --- | :---: | :---: | --- |
| Correct package, trusted key | pass | pass | `test_clean_package_passes_both_parts` |
| **Hash matches, signature invalid** | **fail** | **fail** | `test_matching_hash_does_not_rescue_a_bad_signature` |
| Valid signature, revoked key | **fail** | pass | `test_revoked_key_fails_source_identity_despite_valid_signature` |
| Signed by an unregistered key | **fail** | **fail** | `test_unknown_signer_is_not_trusted` |
| Vendor publishes no key, hash only | n/a | pass *(marked weak)* | `test_hash_only_vendor_is_marked_as_the_weaker_check` |
| Artifact missing from disk | n/a | n/a *(gap)* | `test_missing_artifact_is_unevaluable_not_passing` |

Row 3 is worth reading twice. A revoked key still produces mathematically valid
signatures. The signature proves the bytes are unmodified since signing
(R1.6.2), and it does not establish a trusted source (R1.6.1). Collapsing the
two into one boolean would report this package as fine.

Row 6 matters for a different reason: a missing binary is recorded as
unevaluable, never as a pass. An unevaluable critical that reads as clean is
how a control goes quiet for a year.

---

## 3. The negative control

Fifteen firmware packages ship in the sandbox estate. One is compromised.

```
test_exactly_one_package_fails_verification
    asserts the failing set == ["SPS-421-4.7.2"], exactly
```

Fourteen correctly-signed packages must produce **nothing**. If this test ever
reports two failures, the detector is generating false positives and no number
it prints is trustworthy. CI enforces the same thing at the scenario level by
counting `FIRMWARE VERIFICATION FAILED` lines and requiring exactly one.

Observed on the full estate:

```
15 distinct packages cryptographically verified in 0.21s
FIRMWARE VERIFICATION FAILED  SPS-421-4.7.2
  ... 1 failing, 14 silent
```

---

## 4. Does CIP-002 scoping actually suppress out-of-scope assets?

CIP-013 and CIP-010 R1.6 obligations in this pack attach to high and medium
impact BES Cyber Systems. The generated estate is deliberately realistic: 26
high, 116 medium, 1,158 low out of 1,300 substations.

```
test_low_impact_assets_are_scoped_out_not_passed
    CIP-01 in_population        7,464 firmware deployments
    CIP-01 applicable           1,724 (high + medium impact only)
    CIP-01 not applicable       5,740 (low impact)
```

A run that ignored applicability would raise roughly four times as many
findings, ~77% of them wrong. Low-impact assets are reported **not applicable**,
never **passing** — the distinction is the difference between a defensible
denominator and a padded one.

---

## 5. Can a subject be silently dropped?

```
test_coverage_accounts_for_every_applicable_subject
    for every control: applicable == passed + failed + gapped
```

This is the accounting identity that makes the evidence pack's denominators
mean something. A subject that passed `applies_when` must land in exactly one
outcome bucket. If a future control introduces a path that evaluates nothing
and records nothing, this fails.

---

## 6. Claim discipline

The evidence pack is an audit artifact, and two failure modes would make it a
liability rather than an asset.

| Rule | Test |
| --- | --- |
| The pack never asserts compliance | `test_pack_never_claims_compliance` |
| The pack always declares the data synthetic | `test_pack_declares_the_data_is_synthetic` |
| The pack warns while citations are unverified | `test_pack_warns_while_citations_are_unverified` |
| Every requirement reports a denominator | `test_every_requirement_reports_a_denominator` |
| Firmware exceptions carry the computed hash and the verification performed | `test_firmware_exceptions_carry_the_computed_hash_as_evidence` |
| Exceptions collapse to root causes | `test_exceptions_are_grouped_to_one_root_cause` |

The compliance test greps both renderings for "is compliant", "fully
compliant", "compliance achieved" and similar. Compliance is a determination a
Regional Entity makes; a tool that claims it is selling something it cannot
back.

---

## 7. Control set integrity

| Rule | Test |
| --- | --- |
| Every control cites NERC with a pinned standard, version, requirement and part | `test_every_control_cites_nerc_with_a_pinned_requirement` |
| Every citation carries a human verification checkpoint | `test_every_citation_carries_a_human_verification_checkpoint` |
| **No control cites NIST 800-53 or SOC 2** | `test_no_control_cites_nist_or_soc2` |
| Every control has remediation and a known severity | `test_every_control_has_remediation_and_a_known_severity` |
| CIP-013 controls are scoped to high/medium impact | `test_cip013_controls_are_scoped_to_high_and_medium_impact` |

The single-framework test is deliberate. A utility is audited against NERC;
carrying three frameworks to say one thing makes the file longer without making
it more defensible.

---

## 8. Determinism

```
test_run_is_deterministic
    same seed + same date -> identical finding ids
```

CI additionally regenerates the entire fixture set and fails if a single
committed byte changes. An audit artifact that moves between runs cannot be
reconciled against the one filed last quarter.

---

## 9. The agent reads; the code decides

The extractor lets a model read vendor contracts. Everything below tests the
boundary that keeps a model reading from becoming a control failure.

```bash
python3 -m unittest tests.test_cip_onboarding -v   # 31 tests
```

### 9.1 Quote verification

| Assertion | Test |
| --- | --- |
| A verbatim quote verifies | `test_a_verbatim_quote_verifies` |
| Reflowed whitespace still verifies | `test_reflowed_whitespace_still_verifies` |
| **A plausible paraphrase does not verify** | `test_a_paraphrase_does_not_verify` |
| An invented clause does not verify | `test_an_invented_clause_does_not_verify` |
| A short fragment cannot evidence anything | `test_a_short_fragment_cannot_verify` |

The paraphrase test is the important one. The model is asked to quote verbatim;
asking is not a control. A model that summarises puts its own prose into a
finding's evidence block under the vendor's name.

The fragment test guards the other direction: `"Supplier shall"` appears in
every contract ever written, so a quote under 40 normalised characters is
refused regardless of whether it matches.

### 9.2 The two adjudication rules

| Rule | Behaviour | Test |
| --- | --- | --- |
| **Absence cannot be evidenced** | Model says "not present" → gap, never a failure | `test_absence_never_becomes_a_failure` |
| Verified presence below critical | Applied to the register, drives findings | `test_verified_presence_below_critical_is_applied` |
| **Critical ceiling** | Verified quote on a critical field → withheld for ratification | `test_critical_field_is_withheld_even_when_verified` |
| Unverifiable quote | Withheld regardless of confidence | `test_unverifiable_quote_is_withheld` |
| The ceiling tracks the control set | Re-rating a control in YAML moves it | `test_the_ceiling_is_read_from_the_control_set` |

The last one matters more than it looks. The ceiling is derived from
`cip_controls.yaml` at call time rather than hardcoded, so a control lowered
from critical to high becomes something extraction may decide — and a control
raised to critical stops being. The policy lives in one place.

### 9.3 End to end: a vendor arrives as documents

`tests/test_cip_onboarding.py::EndToEndOnboarding` runs the real sequence
against the real sandbox documents and asserts every step.

```
1. documents read              2 (msa-excerpt.txt, security-questionnaire.txt)
2. clauses examined            8
   quotes offered              7, all located in the source
3. applied to register         6
   withheld with a reason      2
4. signing key registered      kestrel-grid-2026, fingerprint confirmed OOB
5. releases verified           2  (SHA-256 then Ed25519)
   accepted                    KG-RTU-100-2.4.0
   rejected                    KG-RTU-100-2.4.1   hash MATCH, signature INVALID
6. exceptions                  2 critical, 6 information gaps
```

The assertions that carry weight are the refusals:

- `test_the_absent_clause_was_not_invented` — R1.2.3 is genuinely missing from
  the documents, and questionnaire answer A9 is written to look like it
  addresses the obligation while committing the vendor to nothing. The
  extractor does not claim it.
- `test_the_absent_clause_became_a_gap_not_a_failure` — CIP-10 must appear in
  gaps and must NOT appear in findings.
- `test_the_critical_clause_was_withheld_from_the_register` — the R1.2.5 quote
  verified, and the field still did not reach the register.
- `test_withheld_claims_were_queued_for_a_human` — with a stated reason per
  item, so ratifying is a decision rather than a re-investigation.
- `test_the_clean_release_produced_no_finding` — the negative control for the
  onboarding path.
- `test_verification_order_is_hash_then_signature` — the evidence log must read
  in the order the work was done, or it is not a record of what happened.

### 9.4 The extractor is not trusted to be friendly

| Assertion | Test |
| --- | --- |
| A furniture supply contract yields zero applied claims | `test_a_document_with_no_clauses_yields_no_applied_claims` |
| An unreadable PDF is reported, not silently skipped | `test_an_unreadable_document_is_reported_not_skipped` |

The second matters because silently skipping a document means assessing a
vendor on a partial document set while reporting full coverage.

### 9.5 The offline extractor is held to the same rules

Without a local model the extractor falls back to a keyword heuristic. It is
**not** exempt from verification: it must return a real verbatim sentence from
the document, and that sentence goes through `verify_quote` like any model
output. A heuristic that could bypass the check would leave the entire safety
boundary untested in CI, which is the one place it must hold.

---

## What this does NOT validate

Stated plainly, because a validation document that only lists successes is
marketing.

- **28 of 34 citations are still unverified.** The six CIP-010 controls the
  demo exercises were checked on 2026-09-21 and are correct: NERC lists
  CIP-010-4 as mandatory and subject to enforcement, with CIP-010-5 subject to
  future enforcement. Everything else — CIP-013-2, CIP-004-7, CIP-005-7,
  CIP-003-9 and their part numbers — was written from knowledge and still
  carries `citation_verified: false`. The artifacts print a banner. **Verify
  the rest before presenting to a compliance audience.**
- **The verified ones expire.** CIP-010-5 takes effect 2028-04-01 under FERC
  Order No. 919, and the software integrity requirement moves from R1 Part 1.6
  to R1 Part 1.3. `citation_status()` re-checks this every run and
  `tests/test_cip.py::CitationShelfLife` pins the transition, but somebody has
  to act on the warning when it fires.
- **CIP-003-9 may itself be superseded.** NERC Project 2023-04 has been
  developing CIP-003-A / CIP-003-11. The Section 6 controls cite
  "Attachment 1 Section 6" without asserting sub-part numbers for that reason.
- **The impact ratings are a plausible distribution, not a categorisation.**
  Real CIP-002 categorisation runs Attachment 1 criteria against each BES Cyber
  System. `_impact_for` approximates the *shape* of a utility's estate; it is
  not a categorisation method and the code says so.
- **Ed25519 is not what relay vendors actually use.** Real firmware signing is
  usually RSA or ECDSA under an X.509 chain, with certificate path validation
  and revocation checking this module does not implement. The trust model here
  is a flat registry of pinned keys.
- **The estate is synthetic.** No part of this has been run against real vendor
  firmware, a real key registry, or a real asset database. The pipeline and the
  control mapping are validated; the integration with any real system is not.
- **No live OT integration exists.** There is no connector to a configuration
  management database, a patch management system, or a substation gateway.
  Deployments are generated, not observed.
- **The extraction has only been run against the offline heuristic.** The
  sandbox contract documents are clean, well-structured prose written for this
  demo. A real master services agreement is 90 pages of cross-referenced
  exhibits and amendments, and the heuristic would do badly on it. The
  *adjudication* is validated; the *extraction quality* on messy real contracts
  is not. Run it against Ollama and real documents before relying on it.
- **Quote verification does not validate interpretation.** It proves the text
  exists in the document. It cannot tell whether a clause was struck by a later
  amendment, scoped to a different product line, or is a definition rather than
  an obligation. That is precisely why criticals are withheld — but it also
  means an applied `high` finding rests on the model having read scope
  correctly.
- **CIP-004 findings come from generated data.** The PRA and training ages that
  drive CIP-20 and CIP-21 are synthetic distributions, not records. Those
  controls are exercised, but they have never seen a real access roster.
