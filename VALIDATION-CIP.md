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

## What this does NOT validate

Stated plainly, because a validation document that only lists successes is
marketing.

- **The citations themselves are unverified.** All 25 controls carry
  `citation_verified: false`. The standard revision numbers (CIP-013-2,
  CIP-004-7, CIP-005-7, CIP-010-4) and part numbers in this repo were written
  from knowledge, not checked against the enforceable standards on nerc.com. The
  tests assert the checkpoint *exists*; a human has to do the checking. Until
  then every artifact prints a warning. **Do not present this to a compliance
  audience without doing that pass first.**
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
- **CIP-004 findings come from generated data.** The PRA and training ages that
  drive CIP-20 and CIP-21 are synthetic distributions, not records. Those
  controls are exercised, but they have never seen a real access roster.
