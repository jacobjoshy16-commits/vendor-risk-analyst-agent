# Architecture Brief — NERC CIP / Substation Supply-Chain Module

**Status:** DECISION DOCUMENT. Nothing here is built yet.
**Audience:** project owner (you). Every decision below is yours to make.
**Date:** 2026-09-20

---

## 0. Read this part first — three corrections to the premise

I am not going to build on a premise that an Entergy compliance engineer will
dismantle in thirty seconds. Fix these first.

### 0.1 The company is Entergy, not "Insergy"

Your request says "a company called Insergy." Every citation, asset count, and
service territory you gave is **Entergy Corporation** (NYSE: ETR). If the word
"Insergy" appears anywhere in the demo, the repo, or your pitch, the conversation
is over before it starts. I am proceeding on **Entergy**. Correct me if I am wrong.

### 0.2 CIP-013 is NOT the standard that requires cryptographic firmware verification

This is the important one.

You wrote: *"Under NERC CIP-013 ... utilities face penalties if they cannot
cryptographically verify the authenticity and integrity of vendor firmware."*

That is not what CIP-013 says. CIP-013 is a **plan** standard — it requires you to
*have and implement a documented supply-chain risk management plan*, and to review
it periodically. It does not itself impose the per-installation technical check.

The standard that imposes the actual operational control is **CIP-010, Requirement
R1, Part 1.6**: prior to a change that deviates from the baseline configuration,
and when the method is available from the software source, verify (1.6.1) the
identity of the software source and (1.6.2) the integrity of the software obtained.
That is the requirement a firmware-verification tool actually evidences.

The relationship is:

| Standard | What it actually requires | Role in this project |
| --- | --- | --- |
| **CIP-013** R1.2.5 | Your *procurement process* must address vendor provision of verification methods for software integrity/authenticity | The contractual / plan layer |
| **CIP-010** R1.6 | *You* must verify source identity + software integrity before deviating from baseline | **The technical control the tool performs** |
| **CIP-013** R1.2.6 | Your plan must address **coordinated controls for vendor remote access** | The plan layer for vendor access |
| **CIP-005** R2.4 / R2.5 | Methods to **determine** active vendor remote sessions, and to **disable** them | **The technical control for ESP access** |
| **CIP-004** R3/R4/R5 | Personnel risk assessment, access authorization + periodic verification, access revocation | **Who** is allowed to hold that access |
| **CIP-002** | BES Cyber System impact categorization (High / Medium / Low) | **Decides which of the above even apply to a given substation** |

**Consequence for your ask:** a YAML encoding only CIP-013 and CIP-004 can express
the *governance* story but cannot express the *technical* controls your demo is
built around. Firmware verification has no home in CIP-013 alone. Vendor remote
session control has no home in CIP-004 alone. See Decision **D4**.

### 0.3 "Up to $1M per day per violation" is real — but it is a ceiling, not a norm

The figure comes from FPA §316A and is accurate as a statutory maximum. Actual NERC
penalties are set by a violation risk factor / violation severity level matrix and
mitigating-factor analysis; most settlements land far below that. Say "statutory
maximum" on the slide. An Entergy compliance lead hears "$1M a day" as a vendor
pitch cliché; they hear "statutory maximum under FPA 316A, actual exposure set by
VRF/VSL" as someone who has read the standard.

### 0.4 One more thing I could not verify from here

NERC revises these standards. The enforceable version numbers (CIP-013-2 vs -3,
CIP-004-7 vs -8, CIP-005-6 vs -7) and the exact part numbering shift between
revisions, and I will not assert a specific enforceable version from memory. This is
**not a reason to guess** — it is a reason to make the version a first-class data
field. See Decision **D4a**.

---

## 1. What already exists (and why that matters)

This repo is not a blank page. It is a working deterministic control engine:

```
controls.yaml        15 AIV-* controls   — scores vendor AI *features*
nhi_controls.yaml     8 NHI-* controls   — scores vendor *identities*
src/vra/evaluate.py   the evaluator      — fails_when / gap_when / applies_when
src/vra/nhi.py        identity inventory + per-identity evaluation
src/vra/observe.py    parsed-artifact overlay with provenance
src/vra/report.py     findings, due dates, owners, evidence
sandbox/              planted scenario incl. a negative control
tests/                11 test modules
```

The parts worth reusing without modification:

- **`load_controls(path)` already takes a path.** A third control file costs one
  constant in `config.py`. No evaluator changes.
- **The severity/due-date/owner policy is in code, not YAML, and the model cannot
  touch it.** This is exactly the property a NERC audit needs. Keep it.
- **`provenance` on every assessment** — each finding records where the fact came
  from. This is the seed of an audit evidence pack.
- **Unknown = information gap, not failure.** Correct behaviour for compliance;
  an auditor distinguishes "non-compliant" from "not evidenced."

The parts that **do not fit** the OT problem:

- The register is **vendor-keyed** (`vendors/{slug}.yaml`). But a substation, a
  relay, and an RTU are **your** assets, not the vendor's. Modelling a breaker
  controller as a field on a vendor record is backwards and will not survive.
- `ai_surface` features and `nhis` are the only two subject types the evaluator
  iterates. Firmware packages, physical assets, and vendor access sessions are
  three new subject types.
- Condition operators (`equals`, `in`, `gt`, `contains_any`, ...) cannot express
  "signature verifies against the pinned key" or "PRA is older than 7 years."
  New operators are needed, in code, deterministic.

---

## 2. The decisions. All of them are yours.

I give a recommendation and the reasoning for each. I am not acting on any of them
until you choose.

---

### D1 — Where does the CIP control set live?

| Option | What it means | Cost | Risk |
| --- | --- | --- | --- |
| **A. New `cip_controls.yaml`** *(my rec)* | Third control file beside the other two; new `CIP_CONTROLS_FILE` constant | One constant, reuses `load_controls()` unchanged | Slightly more surface to explain |
| **B. Append CIP-* into `controls.yaml`** | Literally what you asked for ("the YAML file") | Zero new files | `controls.yaml` is documented as "the vendor AI *feature* control set." Firmware integrity is not an AI feature. It breaks the file's stated contract and the README table, and the AIV-* demo gets noisier |
| **C. Separate repo** | Clean product identity | Highest | Throws away the working evaluator, report, and test suite |

**Why A:** the existing file is a *typed* set — AIV scores features, NHI scores
identities. CIP scores assets, firmware, and access. Three domains, three files, one
evaluator. It also means your existing SaaS/AI demo still runs clean for a different
audience, which matters if you interview anywhere that is not a utility.

---

### D2 — What do the CIP controls actually score?

The evaluator today walks `vendor["ai_surface"]` and `vendor["nhis"]`. CIP needs new
subjects. Where do they live?

| Option | Model | Reasoning |
| --- | --- | --- |
| **A. New top-level keys on the vendor register** (`firmware_packages:`, `vendor_access:`) | Everything stays vendor-keyed | Simple. But a substation asset is not a property of a vendor |
| **B. New `grid/` asset model + vendor-side keys** *(my rec)* | `grid/substations/*.yaml` holds sites, devices, impact rating; the vendor register keeps what the *vendor* supplies (firmware releases, signing keys, technicians) | Matches reality: assets are yours, supply is theirs. A relay is supplied by SEL but owned by Entergy. Findings can then be scoped per-substation and per-impact-rating, which is what CIP-002 demands |
| **C. Reuse `ai_surface` shape** | Pretend a firmware package is a "feature" | Fastest to build, dishonest, and visibly hacky if anyone opens the YAML |

**Why B:** the CIP-002 impact rating (High/Medium/Low) is what determines *which
requirements apply*. If assets do not exist as first-class objects with an impact
rating, you cannot express that, and a compliance person will notice immediately
that you are applying High-impact controls to a Low-impact substation.

---

### D3 — Real cryptography, or simulated status fields?

This is the decision that determines whether the demo survives one follow-up question.

| Option | What happens | My view |
| --- | --- | --- |
| **A. Real crypto** *(strong rec)* | Generate actual keypairs for the fictional/real vendors, sign actual firmware blobs, tool performs actual SHA-256 + signature verification. The tampered binary in the demo genuinely fails verification | The grid can be fake. The **crypto must not be.** The first question any Entergy engineer asks is "what is it actually doing?" — "it reads a `verified: false` field I typed in" ends the conversation |
| **B. Simulated fields** | `signature_valid: false` in YAML | Builds in an afternoon. Worthless under scrutiny |
| **C. Hybrid** | Real verification where cheap, simulated for exotic cases (revoked-key checks, cert chains) | Honest middle ground — but you must *label* which is which in the demo |

**Why A:** this is the single highest-leverage thing in the project. "Fake the grid,
never fake the crypto" is the line that makes this a portfolio piece instead of a
mockup. Cost is maybe a day with `cryptography` or GPG.

---

### D4 — Which standards get encoded?

| Option | Coverage | Consequence |
| --- | --- | --- |
| **A. CIP-013 + CIP-004 only** | Exactly what you asked for | The two technical controls your demo performs (firmware verification, vendor session control) have **no requirement to cite**. See §0.2 |
| **B. CIP-013 + CIP-004 + CIP-010 R1.6 + CIP-005 R2.4/2.5** *(my rec)* | Plan layer *and* technical layer | Every finding cites the requirement that actually governs it. This is what makes it credible |
| **C. Full CIP-002 through CIP-011** | Complete | Scope explosion. Months, not weeks. Most of it (physical security CIP-006, recovery CIP-009) is irrelevant to supply chain |

**Why B:** it is a two-standard addition that closes the exact gap in §0.2. Your
framing stays intact — CIP-013 and CIP-004 remain the headline — but the findings
become defensible. I would also add a *single* CIP-002 field (impact rating) without
encoding CIP-002 controls, purely so applicability scoping works.

#### D4a — Standard version pinning (sub-decision)

Because I will not assert enforceable version numbers from memory (§0.4), I propose
each control carries:

```yaml
frameworks:
  - name: "NERC CIP"
    standard: "CIP-010"
    version: "4"            # you verify this against nerc.com before demo
    requirement: "R1"
    part: "1.6.2"
    verified_by: "<your name>"
    verified_on: "2026-09-XX"
```

plus a test that **fails the build** if any CIP control lacks `verified_by`. That
turns my uncertainty into an enforced human checkpoint rather than a silent guess.
Your call whether that is rigour or friction.

---

### D5 — How big is the simulated grid?

Entergy runs ~1,300 substations and ~16,100 circuit miles.

| Option | Size | Trade-off |
| --- | --- | --- |
| **A. 3 substations / ~12 devices** | Demo-tight | Readable on screen, every device nameable. Does not demonstrate scale |
| **B. ~25 substations / ~200 devices** *(my rec)* | Mid | Big enough that the rollup view earns its place; small enough to still scroll |
| **C. Generated 1,300 substations / ~10k devices** | Full | Proves the scale claim with a real timing number. Unreadable as a screen demo |

**Why B, plus a generator for C:** demo on B, then say "and here is the same run
against 1,300 substations in N seconds" with C generated on demand. You get both
without cluttering the screen. The existing repo already made this exact choice for
NHIs (20k identities link in under a second), so there is precedent.

---

### D6 — What goes wrong in the demo?

The existing sandbox has a strong pattern: planted changes **plus a negative control**
that must produce nothing. Pick 2–3 failures. Candidates:

1. **Tampered binary** — hash mismatch against vendor-published hash. *(obvious, necessary)*
2. **Valid hash, invalid signature** — the file matches a hash someone published, but is not signed by the vendor key. Shows why hash-checking alone is insufficient. *(my favourite — it is the subtle one)*
3. **Correct signature, wrong device model** — genuinely SEL-signed firmware for a different relay family. Flashing it bricks the device. Signature checking alone does not catch this.
4. **Expired signing key** — signature verifies mathematically, key was revoked. CIP-010 R1.6.1 "identity of the software source" fails.
5. **Vendor technician with lapsed PRA holding active ESP access** — CIP-004 R3 + R4. *(needed to make CIP-004 load-bearing rather than decorative)*
6. **Vendor remote session still open past the approved maintenance window** — CIP-005 R2.4/R2.5.
7. **Negative control** — a routine, correctly-signed, correctly-authorized patch deployment that must produce **zero** findings.

**My rec:** 2, 5, and 7. #2 is the intellectually interesting one, #5 makes CIP-004
real, #7 proves you are not just printing alarms. Add #4 if you want a third failure.

---

### D7 — What does "the audit" mean?

You asked for "an audit of this actually working." That is two different artifacts.

| Option | What it is | Who it is for |
| --- | --- | --- |
| **A. Audit evidence pack** | The tool *exports* CIP audit evidence — per-requirement, what was checked, when, against which artifact hash, with the signature verification result. RSAW-shaped | An Entergy compliance lead. **This is a product feature** |
| **B. Engineering validation** | A test suite + VALIDATION.md proving the detector fires on planted failures and stays silent on the negative control | An engineering interviewer. **This is proof the code works** |
| **C. Both** *(my rec)* | | |

**Why C:** they answer different questions from different people, and at a career fair
you do not know which one you are talking to. B is cheap here — the repo already has
the pattern. A is the differentiator.

---

### D8 — What does the demo surface look like at a career fair?

| Option | Trade-off |
| --- | --- |
| **A. CLI only** | Matches the existing product. Signals engineering depth. Risky on a noisy floor with a small laptop screen |
| **B. Extend the existing local web console** | Consistent with repo; more work |
| **C. CLI as truth + generated static HTML evidence report** *(my rec)* | You run the CLI live (proves it is real), and the evidence pack opens as a readable page you can hand over or email afterwards |

**Why C:** at a booth you have ~90 seconds and possibly nowhere to sit. The static
report is also the thing a "pivotal member of their team" can forward internally,
which is the actual conversion event.

---

### D9 — Product identity

The README is currently emphatic: *"the product identity is 800-53 + SOC 2 NHI /
agentic monitoring."* Adding an OT supply-chain module either:

- **A.** Makes it a second module in the same product (README grows a section)
- **B.** Makes it a distinct product identity ("Substation Supply-Chain Integrity Monitor") with the NHI work as shared infrastructure *(my rec for an Entergy pitch)*
- **C.** Re-frames the whole thing as a general "vendor supply-chain control plane" with SaaS and OT as two domains

**Why B for the pitch, and it costs you nothing:** you can present the same repo two
ways to two audiences. But decide now, because it determines whether the README is
rewritten or appended.

---

### D10 — Real vendor names, or fictional?

Your brief names SEL, GE, and Siemens.

| Option | Trade-off |
| --- | --- |
| **A. Real names** | Maximum realism; Entergy actually uses these. But your demo depicts these vendors' firmware failing signature verification. Even clearly-labelled fiction, that is an optics and arguably a defamation-adjacent risk to put in a public GitHub repo |
| **B. Fictional analogues** (e.g. "Sentinel Protective Systems", "Meridian Grid Controls") | Zero risk. Slight realism cost. Consistent with the existing sandbox, which already uses fictional vendors |
| **C. Real names for *correct* behaviour, fictional for the *failures*** *(my rec)* | The negative control uses a real vendor name (nothing bad implied); the tampered/failed cases use fictional ones |

**Why C:** you keep the realism where it helps and take no risk where it hurts. Also:
the tampering scenario is more accurate as fiction anyway — in a real supply-chain
attack the *vendor* is usually not the culprit; the binary is intercepted or a mirror
is poisoned downstream. Fictional names let you depict that honestly.

---

### D11 — Branch

The designated working branch is `claude/architecture-performance-review-4lqk46`,
which is already separate from the main line (nothing of yours lives on a shared
branch). Options: keep it, or I cut and push a purpose-named branch such as
`claude/nerc-cip-substation-module`. Purely cosmetic — but it is your repo history.

---

## 3. Things I want to flag that are not decisions

**Scope.** This repo is 114 files and 29 modules. The CIP module as scoped in my
recommendations (D1-B, D2-B, D3-A, D4-B) is a substantial addition — three new
subject types, new evaluator operators, a real crypto path, a grid asset model, an
evidence exporter, and tests. That is real work, not an afternoon. If your deadline
is a specific career fair date, tell me the date and I will tell you what fits.

**Claim discipline.** Do not say this tool "makes you CIP compliant." Say it
"automates the evidence CIP-010 R1.6 and CIP-004 R4 require you to produce." The
first is a liability claim you cannot back; the second is true and is what compliance
teams actually spend money on.

**Air-gap framing.** Put "synthetic data, air-gapped simulation, no connection to any
real OT network" on the first slide. Anyone at Entergy who deals with CIP will have
that question before they have any other question, and volunteering it buys you
credibility you cannot buy any other way.

**The real bottleneck you identified is correct.** Your observation that firmware
verification is fragmented, semi-manual, and spreadsheet-evidenced is accurate and is
genuinely the pain point. That part of your thesis is sound. It is only the standard
citations that need fixing.

---

## 4. What happens after you decide

Once D1-D11 are answered I will produce a build plan with ordered phases and a
file-by-file change list, and only then write code.
