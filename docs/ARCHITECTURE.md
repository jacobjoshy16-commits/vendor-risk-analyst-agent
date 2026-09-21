# Technical breakdown — NERC CIP substation supply-chain monitor

**This document has two jobs.** The first is to explain exactly how the system
works, end to end. The second is to mark **every design decision and who made
it**, because a lot of them were made by Claude during implementation rather
than by the project owner, and the owner needs to be able to find and reverse
them.

Markers used throughout:

| Marker | Meaning |
| --- | --- |
| **[OWNER]** | You decided this explicitly. Not changed without asking. |
| **[CLAUDE]** | Claude decided this while implementing. **Overridable — your call.** |
| **[INHERITED]** | Pre-existing behaviour of the repo this module was built on. |

If you disagree with anything marked **[CLAUDE]**, it changes. That is the point
of the marker. The decisions most worth your attention are collected in
[§8 Decision register](#8-decision-register), with the five highest-impact ones
listed first.

---

## 1. What the system does, in one paragraph

It answers two questions for an electric utility. **"Can I trust this firmware
before it goes on a protective relay?"** — answered by real SHA-256 and real
Ed25519 signature verification against a registry of pinned vendor keys.
**"Does my procurement process address what CIP-013 requires?"** — answered by a
language model reading the vendor's actual contract, with code verifying every
quote it produces before any of it affects a control. Both answers are scored
against a NERC control set in YAML, and the output is an audit evidence pack
organised by requirement with a denominator on every row.

---

## 2. The pipeline

There are two entry paths. They converge on the same evaluator.

### Path A — assess the estate (`vra.py cip`)

```
sandbox/grid/keys.yaml ─────┐
sandbox/grid/packages.yaml ─┼──▶ grid.load_estate()
sandbox/grid/firmware/*.bin ┘         │
                                      ├──▶ Estate {substations, devices,
   generated deterministically        │            deployments, access_sessions,
   from a seed, not committed ────────┘            personnel, vendors, registry}
                                                          │
                                                          ▼
                              cipcrypto.verify_package()  ── real SHA-256
                                  once per distinct package  real Ed25519
                                                          │
                                                          ▼
                              cip.assess_estate()
                                  ├─ firmware_subjects()    (+ verification fields merged in)
                                  ├─ procurement_subjects() (+ vendor_publishes_signing_key)
                                  ├─ access_subjects()
                                  └─ personnel_subjects()
                                                          │
                              for each subject × each control:
                                  applies_when → skip or count as applicable
                                  fails_when   → finding
                                  gap_when     → information gap
                                  else         → pass
                                                          │
                                        ┌─────────────────┴─────────────────┐
                                        ▼                                   ▼
                              findings + gaps                        Coverage per control
                              (Assessment objects)          (population/applicable/pass/fail/gap)
                                        └─────────────────┬─────────────────┘
                                                          ▼
                                              evidence.build_pack()
                                                          │
                                        out/cip/evidence-pack.{md,html,json}
                                        out/cip/findings.json
```

### Path B — onboard a vendor (`vra.py cip onboard`)

```
contracts/*.txt|md|html|pdf ──▶ procure.load_documents()
signing-key.yaml ────────────▶ KeyRegistry  ──┐
                                              │ (loaded FIRST — see §5.2)
                                              ▼
                              procure.VendorFootprint
                                              │
                                              ▼
                    procure.extract_procurement(footprint=...)
                          │
                          ├─ reading_order()      ── prioritise obligations
                          ├─ for each obligation:
                          │     MODEL: "find this clause, quote it verbatim"
                          │     (or offline keyword heuristic)
                          │
                          ▼
                    procure.adjudicate()   ◀── THE SAFETY BOUNDARY (§5)
                          ├─ verify_quote() → is the quote really in the document?
                          ├─ rule 1: absence cannot be evidenced
                          └─ rule 2: verified ≠ licence to raise a critical
                          │
              ┌───────────┴────────────┐
              ▼                        ▼
      tier="extracted"          tier="proposed"
      applied to register       pending_review/*.json
              │
              ▼
      vendor_record{contract: {...}}
              │
              ▼
      Estate of one vendor  ──▶  same assess_estate() as Path A
              │
              ▼
      releases.yaml ──▶ verify_package() per release  (SHA-256, then Ed25519)
```

---

## 3. Module by module

| Module | Lines | Responsibility |
| --- | ---: | --- |
| `cip_controls.yaml` | — | 34 NERC controls. The policy. No code. |
| `src/vra/evaluate.py` | 433 | Condition engine. `Control`, `Assessment`, `evaluate_condition`, due dates, finding records. **[INHERITED]** |
| `src/vra/cipcrypto.py` | 451 | SHA-256, Ed25519, key registry, `verify_package`. |
| `src/vra/grid.py` | 380 | Asset model + deterministic estate generator. |
| `src/vra/gridbuild.py` | 330 | Fixture builder: signs firmware, plants the compromise. |
| `src/vra/cip.py` | 404 | Assessment over four subject types, coverage, citation status. |
| `src/vra/procure.py` | 772 | Document loading, model extraction, quote verification, adjudication, prioritised reading. |
| `src/vra/onboard_cip.py` | 180 | The onboarding sequence. |
| `src/vra/evidence.py` | 575 | Audit evidence pack (markdown / HTML / JSON). |
| `src/vra/cipcli.py` | 328 | `vra.py cip` and `vra.py cip onboard`. |
| `src/vra/config.py` | 192 | Paths, severity policy, due-date table. **[INHERITED]** |
| `src/vra/llm.py` | 652 | Ollama + offline backend, prompt audit log, cache. **[INHERITED]** |

### 3.1 `cip_controls.yaml` — the policy

Every control is a YAML block:

```yaml
- id: CIP-01
  subject: firmware_deployment        # which collection this scores
  question: >                          # plain English, printed in the pack
  frameworks:                          # NERC citation, version-pinned
    - name: "NERC CIP"
      standard: "CIP-010"
      version: "4"
      requirement: "R1"
      part: "1.6.2"
      text: >                          # the requirement's own words
      citation_verified: true          # has a human checked this?
      citation_verified_by: "..."
      superseded_by: "CIP-010-5"       # what replaces it
      enforceable_until: "2028-03-31"  # and when
  applies_when:                        # ALL must hold, or skip entirely
    - field: impact_rating
      in: [high, medium]
  fails_when:                          # ALL must hold → finding
    - field: integrity_verified
      equals: false
  gap_when:                            # ANY holds → information gap
    - field: integrity_verified
      is_unknown: true
  severity: critical                   # policy, never model-set
  remediation: >
  compensating_control: >
```

Operators available: `equals`, `not_equals`, `in`, `not_in`, `is_unknown`,
`gt`, `lt`, `truthy`, `falsy`, `contains_any`, `not_in_baa_scope`.

**There are no crypto-specific or date-specific operators.** See §4.2.

Current shape: 34 controls — 6 `firmware_deployment`, 14 `procurement`,
7 `vendor_access`, 7 `vendor_personnel`. 8 critical, 19 high, 7 medium.

### 3.2 `cipcrypto.py` — verification

`verify_package(package, registry, root, when)` reads the artifact off disk and
returns a `VerificationResult` with these computed fields:

| Field | How it is computed |
| --- | --- |
| `computed_sha256` | `hashlib.sha256` over the actual file bytes |
| `hash_match` | computed vs. the vendor's published digest, case/whitespace normalised |
| `signature_verified` | `cryptography` Ed25519 verify over the exact bytes |
| `signing_key_trusted` | key is in the registry AND `status_on(when) == active` |
| `signing_key_status` | `active` / `revoked` / `expired` / `unknown` |
| `verification_strength` | `signature` / `hash_only` / `none` |
| `source_identity_verified` | `signature_verified AND signing_key_trusted` → **R1.6.1** |
| `integrity_verified` | `signature_verified` (see §4.1) → **R1.6.2** |
| `evidence[]` | human-readable log of every operation performed |

`verify_signature` returns `False` on every failure mode — malformed base64,
wrong key length, signature over different bytes — rather than raising, so an
attacker-supplied value cannot crash an estate-wide run.

### 3.3 `grid.py` / `gridbuild.py` — the estate

`gridbuild.build()` writes the **committed** part: `keys.yaml`,
`packages.yaml`, `vendors.yaml`, and real signed `.bin` files.

`grid.load_estate()` reads those and **generates** the assets in memory from a
seed: 1,300 substations, ~7,500 devices, one firmware deployment per device,
vendor personnel, and vendor access sessions.

The planted compromise is built like a real mirror attack:

1. Build the genuine image, sign it.
2. Substitute the binary on disk.
3. **Update the published hash to match the substituted binary** — the attacker
   controls the mirror, so they control the digest printed beside it.
4. Leave the original signature in place; it cannot be forged.

Result: `hash_match=True`, `signature_verified=False`. A hash-only process
passes it. 131 relays in the estate run that build.

### 3.4 `procure.py` — extraction and adjudication

Four stages, and only the second involves a model:

1. **`load_documents`** — `.txt`, `.md`, `.html`, `.pdf`. A PDF yielding no text
   is kept and reported as unreadable, never silently dropped.
2. **`extract_procurement`** — per obligation, asks the model for
   `{present, quote, confidence, rationale}`. Falls back to a keyword heuristic
   labelled `offline-heuristic` when no model is reachable.
3. **`verify_quote`** — normalises whitespace and case, then checks the quote is
   a substring of a source document. Minimum 40 normalised characters.
4. **`adjudicate`** — decides, in code, what each claim is allowed to do. §5.

### 3.5 `cip.py` — assessment

`assess_estate()` builds four subject streams, dispatches each control to its
stream via `control.subject`, and returns
`(findings, gaps, verification_results, coverage)`.

`Coverage` tracks, per control: `in_population`, `applicable`, `passed`,
`failed`, `gapped`. The invariant `applicable == passed + failed + gapped` is
asserted by a test — nothing may be silently skipped.

`citation_status()` re-checks every verified citation's `enforceable_until`
against the assessment date: warning inside a year, error past it.

### 3.6 `evidence.py` — the output

Organised **by requirement, not by finding**, because an audit opens with "show
me you checked". Every requirement carries its denominator. Exceptions are
grouped by root cause first — 131 relays failing one control is one substituted
package, not 131 problems.

---

## 4. Three design choices that carry the most weight

### 4.1 A matching hash does not close R1.6.2 — **[CLAUDE]**

```python
if verification_strength == "signature":
    source_identity_verified = signature_verified and signing_key_trusted
    integrity_verified       = signature_verified      # deliberately NOT "or hash_match"
```

**The reasoning:** a hash proves the bytes match *a published string*. It does
not prove that string came from the vendor — whoever can substitute a binary on
a mirror can substitute the digest beside it. So where the vendor publishes a
signing key, the signature is the only thing that establishes integrity.

Where the vendor publishes **no** key, the hash is the only method available
from the source, so it is used, and the result is marked
`verification_strength: hash_only` rather than presented as the stronger check.

**This is the core argument of the whole project and it was Claude's call.** A
defensible alternative is `integrity_verified = signature_verified or
hash_match`, which would make the planted scenario fail only R1.6.1 instead of
both. If you prefer that reading of R1.6.2, it is a one-line change in
`cipcrypto.verify_package`.

### 4.2 Computed facts are materialised as plain fields — **[CLAUDE]**

The obvious way to score a signature is to add a `signature_valid` operator to
the evaluator. That is not what happens. `VerificationResult.as_fields()`
flattens the cryptographic outcome onto the subject dict, and the control file
scores it with `equals` — an operator that already existed.

Same for dates: `pra_age_days` is computed as an integer and scored with `gt`.

**Consequence:** the evaluator gained **zero** new operators, the crypto lives
in one auditable place, and the part that has to survive "why did this fail?"
is unchanged from the version that already had to survive it.

### 4.3 Applicability is scoped by standard, not globally — **[OWNER + correction]**

Two different populations:

| Population | Standards | Size in the sandbox |
| --- | --- | ---: |
| High / medium impact | CIP-013, CIP-010 R1.6, CIP-005 R2 | 142 substations |
| Low impact **that allow vendor electronic remote access** | CIP-003-9 Att. 1 §6 | 69 assets |
| Low impact with no vendor access path | — genuinely out of scope | the rest |

An earlier version gated everything on high/medium, which under-reported by
ignoring CIP-003-9. Low-impact assets are reported **not applicable**, never
**passing** — the distinction between a defensible denominator and a padded one.

---

## 5. The safety boundary — what the model can and cannot do

This is the part that distinguishes the project, so it is specified precisely.

### 5.1 The tier model

| Tier | Source | Drives a finding? |
| --- | --- | --- |
| `register` | A human wrote it | Yes |
| `observed` | Parsed from a table or API | Yes |
| `extracted` | Model read prose **and** the quote was located in the source | Yes, capped |
| `proposed` | Model claim it could not evidence | **Never** |

### 5.2 The two rules, verbatim from `adjudicate()`

**Rule 1 — presence can be evidenced, absence cannot. [CLAUDE]**

```python
if claim.present is not True:
    claim.tier = "proposed"
    claim.applied_value = None       # never False, which would be a failure
```

A model can quote §9.1 to prove a clause exists. Nothing it can quote proves a
clause is *missing*. So "not present" produces an information gap with a
question for the vendor, never a control failure. Inverting this would let a
model fail a vendor on a clause it merely failed to find in a 90-page contract.

**Rule 2 — a verified quote is not a licence to raise a critical. [OWNER]**

```python
if claim.field in critical_fields:
    claim.tier = "proposed"
    claim.withheld_reason = "...verification proves the text exists — not that
                             its scope was read correctly."
```

`critical_fields` is derived from the control set at call time, so re-rating a
control in YAML moves the ceiling. Lower CIP-12 to `high` and extraction is
allowed to decide it.

### 5.3 What the model never sees

It receives contract prose and a footprint summary. It never sees a hash, a
signature result, the key registry, asset impact ratings, or existing findings.
Those are computed by code and consumed by code.

### 5.4 Prioritised reading cannot change a verdict — **[OWNER]**

The footprint tells the model what the vendor supplies and whether a key is
already held, and reorders the obligations so the highest-stakes are read first.
It changes **what the model is told** and **the order**. It cannot change
adjudication.

`tests/test_cip_onboarding.py::PrioritizedReadingCannotChangeTheVerdict`
asserts that the same documents under opposite footprints produce identical
claims and an identical register block.

---

## 6. Running it

```bash
python3 vra.py cip build-fixtures            # regenerate keys, packages, firmware
python3 vra.py cip --date 2026-09-21         # assess the estate
python3 vra.py cip --date 2026-09-21 --evidence
python3 vra.py cip onboard --vendor "Kestrel Grid Systems" \
    --docs sandbox/procurement/kestrel-grid --offline
```

Exit codes: `0` clean · `1` open critical · `2` run error.

Tests: 491 total; `tests/test_cip.py` (45) and `tests/test_cip_onboarding.py`
(37) cover this module.

---

## 7. Where to edit for common changes

| You want to... | Edit |
| --- | --- |
| Add / change / re-severity a control | `cip_controls.yaml` only |
| Change what "integrity verified" means | `cipcrypto.verify_package` |
| Change the extraction ceiling | re-severity the control; it derives automatically |
| Add a CIP-013 obligation to detect | `procure.CLAUSE_TARGETS` + `OFFLINE_SIGNATURES` |
| Change reading priority | `procure.BASE_PRIORITY` and `VendorFootprint.priority` |
| Change estate size / shape | `grid._generate_assets`, `config.GRID_SUBSTATIONS` |
| Change the planted scenario | `gridbuild.TAMPERED_PACKAGE` and `build()` |
| Change the evidence pack layout | `evidence.render_markdown` / `render_html` |
| Change severity → due date | `config.DUE_DAYS_BY_SEVERITY` **[INHERITED]** |

---

## 8. Decision register

### The five you should review first — all **[CLAUDE]**

| # | Decision | Alternative | Where |
| --- | --- | --- | --- |
| 1 | A matching hash does **not** satisfy R1.6.2 when a signing key is published | `signature_verified or hash_match` | `cipcrypto.py` §4.1 |
| 2 | Absence can never produce a control failure | let the model's "not present" fail the control | `procure.adjudicate` |
| 3 | Ed25519 for signing | RSA-4096 or ECDSA P-256 under X.509, which is what real relay vendors use | `cipcrypto.py` |
| 4 | Impact distribution ≈ 2% high / 9% medium / 89% low | any other mix; it drives every denominator in the pack | `grid._impact_for` |
| 5 | Evidence pack organised by requirement with denominators | organised by finding, like a normal vuln report | `evidence.build_pack` |

### Decisions you made

| Decision | Where it lives |
| --- | --- |
| Standards: CIP-013 + CIP-004 + CIP-010 R1.6 + CIP-005 R2, plus procurement storage | `cip_controls.yaml` |
| Real cryptography, not simulated status fields | `cipcrypto.py` |
| A separate `cip_controls.yaml`, NERC citations only | `cip_controls.yaml` |
| Both audit artifacts: evidence pack **and** validation suite | `evidence.py`, `tests/` |
| Full 1,300-substation estate | `config.GRID_SUBSTATIONS` |
| Planted scenario: valid hash / invalid signature only | `gridbuild.py` |
| All vendor names fictional | `grid.VENDORS` |
| Extraction ceiling: findings up to `high`, criticals need ratification | `procure.adjudicate` |
| Prioritised reading from machine context | `procure.VendorFootprint` |
| Keep `controls.yaml` / `nhi_controls.yaml` rather than delete | — |
| Work on a separate branch | `claude/nerc-cip-substation-module` |

### Decisions Claude made — all overridable

**Control set**
- ID scheme `CIP-01`…`CIP-34` rather than requirement-keyed IDs
- Four subject types (`firmware_deployment`, `procurement`, `vendor_access`, `vendor_personnel`)
- CIP-003-9 §6 modelled as 4 separate controls rather than one
- Citing "Attachment 1 Section 6" without asserting sub-part numbers
- `citation_verified` / `superseded_by` / `enforceable_until` schema

**Verification**
- Ed25519; deterministic demo keys derived from text labels
- `hash_only` fallback when a vendor publishes no key
- Verification cached per package, not per deployment
- Key fingerprint format (4 hex groups) for out-of-band confirmation
- `verify_signature` swallows all exceptions rather than raising

**Estate**
- Impact distribution and device counts per substation
- 6% of low-impact substations allow vendor remote access
- `FIXTURE_EPOCH = 2026-09-20` so fixtures don't change with the calendar
- Synthetic place names; four states matching Entergy's footprint

**Extraction**
- 40-character minimum for a quote to be verifiable
- Eight `CLAUSE_TARGETS` and their descriptions
- `BASE_PRIORITY` weights and the footprint adjustments
- Offline heuristic keyword signatures
- Prompt wording, including the instruction not to read a large footprint generously

**Output**
- `Coverage` accounting and the `applicable == pass + fail + gap` invariant
- Root-cause grouping before listing exceptions
- Refusing to ever print a compliance claim
- Sampling 5 exceptions per requirement in the pack

---

## 9. Known gaps

- **28 of 34 citations unverified.** The 6 CIP-010 controls the demo exercises
  are verified against NERC's standards listing (CIP-010-4 mandatory and subject
  to enforcement). The rest are flagged and the tool says so.
- **Verified citations expire.** CIP-010-5 takes effect 2028-04-01 under FERC
  Order No. 919; Part 1.6 becomes Part 1.3. Tracked, warned on, not yet acted on.
- **CIP-003-9 may itself be superseded** by Project 2023-04 (CIP-003-A / -11).
- **Extraction only tested on clean demo prose and the offline heuristic.** A
  real MSA is cross-referenced exhibits and amendments.
- **Quote verification does not validate interpretation.** It proves text exists,
  not that a clause was in force or in scope.
- **Impact ratings are a plausible distribution, not a CIP-002 categorisation.**
- **Flat key registry, no X.509 path validation or revocation checking.**
- **No live OT integration.** Deployments are generated, not read from a CMDB.
- **No change detection.** The estate regenerates each run, so the tool cannot
  say "this started failing yesterday" — the one capability the SaaS side has
  that this side does not.
