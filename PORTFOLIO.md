# Verifying vendor firmware before it reaches the grid

A working model of NERC CIP-010 R1.6 and CIP-013 supply-chain verification,
built on a synthetic utility estate.

---

## 1. The problem, in Entergy's own filing

Entergy's FY2025 Form 10-K (filed February 2026) says four things that, put
together, describe a specific gap.

**Their suppliers have already been attacked.** Item 1A states that Entergy and
its third-party suppliers have been the target of cyber attacks and expect to
continue being targeted. This is not a hypothetical risk in their disclosure —
it is a stated history.

**Vendors connected through the grid are a named attack path.** Item 1A
identifies attacks on *"critical suppliers and contractors or other third
parties interconnected through the grid,"* with consequences named as loss of
operational control, outages, and data loss.

**They already monitor vendors.** Item 1C describes a *"vendor risk management
program to assess and monitor security risks that arise from certain third-party
vendors,"* plus threat-intelligence services that *"continuously monitor the
cybersecurity risk of key vendors."*

**They state the limits of detection.** Item 1A: Entergy *"cannot anticipate,
detect, or implement fully preventive measures against all cybersecurity
threats,"* and names *"threats fueled by artificial intelligence."*

### Why this matters now

Entergy's capital plan commits **$6.35B (2026)** and **$8.01B (2027)** to
generation — roughly a dozen new plants, fourteen generators moving through
MISO's expedited study process, and **21 turbine equipment sets from a single
vendor, of which 7 have been delivered**.

Every one of those plants arrives with vendor firmware, from many suppliers, on
a commissioning schedule. That is the window where a substituted package is most
likely to pass unexamined, because the pressure at that moment is to energise.

Separately — and this is public regulatory context, not a quote from the filing
— **CIP-003-9 took effect 1 April 2026**, extending vendor electronic remote
access requirements to low-impact systems. The filing names vendor grid access
as a risk; the standard widened whose assets that applies to.

---

## 2. The specific blind spot

Firmware verification at most utilities is semi-manual: an engineer downloads a
binary, compares the SHA-256 to the vendor's release notes, records it on a
spreadsheet.

**A hash proves the file matches a published string. It does not prove the
string came from the vendor.**

An attacker who can substitute a binary on a distribution mirror can substitute
the digest printed beside it — the binary and the hash travel the same channel.
What they cannot do is forge a signature without the vendor's private key.

This maps cleanly onto the standard:

| Check | Question it answers | NERC |
| --- | --- | --- |
| SHA-256 | Are these the bytes the published digest describes? | CIP-010 R1.6.2 |
| Signature | Did the vendor vouch for these exact bytes? | CIP-010 R1.6.1 + R1.6.2 |

Where a vendor publishes a signing key, a matching hash does **not** close
R1.6.2. Where a vendor publishes no key, the hash is the only method available
from the source — so it is used, and marked as the weaker check rather than
dressed up.

---

## 3. What was built

A tool that verifies a vendor firmware package, reasons about it, blocks it if
it cannot be trusted, produces the CIP evidence, and watches for change
afterwards.

```
vendor package
      ↓
  VERIFY      SHA-256 + Ed25519 over the actual bytes, against a
              registry of pinned vendor keys with status and validity
      ↓
  SCORE       34 NERC controls over four subjects, scoped by
              CIP-002 impact rating
      ↓
  REASON      a local model receives the crypto result, the failed
              controls, the blast radius and the vendor's history,
              and reaches a disposition
      ↓
  DECIDE      block · allow · escalate      exit 1 = do not deploy
      ↓
  RECORD      audit pack by requirement + alert routed by severity
      ↓
  WATCH       seal the approved posture; alert on any later change
              that has no recorded approval
```

### The four subjects

| Subject | Standards |
| --- | --- |
| Firmware deployments | CIP-010 R1.6 |
| Procurement (per vendor) | CIP-013 R1/R2/R3 |
| Vendor ESP access | CIP-005 R2, CIP-003-9 §6 |
| Vendor personnel | CIP-004 R2–R5 |

CIP-002 impact ratings gate every control. In the synthetic estate that produces
two distinct populations: 142 substations at high/medium impact for CIP-013 and
CIP-010, and 69 low-impact assets with vendor remote access for CIP-003-9.
Low-impact assets with no vendor path are reported *not applicable* — never
*passing*.

---

## 4. Where the AI sits, and why it is constrained

Entergy states it cannot detect every threat and names AI-driven threats
specifically. A tool that answers that by putting an AI in the decision path has
to be able to say what the AI did, and to show that it cannot invent a finding.

**Two model roles, deliberately different shapes.**

*Reading a contract is a fact question.* The model locates a CIP-013 clause and
quotes it verbatim; code then checks the quote actually exists in the source
document before it can affect any control. Two rules bound it:

- **Presence can be evidenced; absence cannot.** A model can quote §9.1 to prove
  a clause exists. Nothing it can quote proves a clause is *missing* — so "not
  present" becomes an open question for the vendor, never a control failure.
- **A verified quote cannot raise a critical alone.** Verification proves the
  text exists, not that its scope was read right. Criticals route to human
  ratification.

*Deciding what to do about a package is a judgement.* There the code runs first
and hands the model everything it established — crypto result, failed controls,
how many devices run this build, what this vendor has done before — and the
model reasons over all of it. Who decides is configurable: rule engine, model,
or both.

**Every model invocation is logged**: the task, a digest of what it was shown,
its disposition, confidence, and model build. Append-only. That surfaces whether
the agent's behaviour changed over time, and whether identical inputs produced
different answers.

---

## 5. Validation

568 tests. The ones that matter are the negative controls — a detector that only
ever fires proves nothing.

| Assertion | Why |
| --- | --- |
| Flipping one bit in an 8 KB image breaks verification | Proves the cryptography is real, not a stored field |
| Exactly one of fifteen packages fails | Fourteen good ones must stay silent |
| The tampered package still passes the hash check | If it failed both, the demo would prove nothing |
| A revoked key fails source identity but passes integrity | The two parts of R1.6 must not collapse |
| Same documents, opposite vendor footprints → identical verdict | Machine context steers attention, never outcome |
| Cold start sends zero alerts | A first run that pages 115 times gets the channel muted |

---

## 6. Limitations

Stated plainly, because a project that only lists successes is marketing.

- **Everything is synthetic.** ~7,500 devices across 1,300 substations, modelled
  on a mid-size utility. No real data, no OT connection, invented vendors.
- **22 of 34 control citations verified** against the standard text (CIP-010
  R1.6, CIP-013 R1, CIP-005 R2, CIP-003-9). The remaining 12 — CIP-004 part
  numbers and CIP-013 R2/R3/1.2.4 — are flagged, and the tool prints a banner.
- **Ed25519 is not what most OT vendors ship.** Many publish a digest only; where
  signing exists it is usually X.509 code signing. The `hash_only` path is
  probably the common real-world case.
- **Flat key registry.** Key status and validity windows, but no certificate
  chain validation and no revocation checking. It is not PKI.
- **Contract extraction has never seen a real MSA.** The adjudication rules are
  validated; extraction quality on 90 pages of cross-referenced exhibits is not.
- **No vendor tenant integration.** Drift is detected against sealed posture
  data, not by polling a vendor's system.

---

## 7. What this is not

Entergy has a mature CIP-013 program, a GRC platform, and vendor processes.
This does not fill a gap in any of it.

**It is a working model of the problem that program solves** — built to
understand it end to end, and to produce the kind of artifact that program would
hand an auditor.

---

**Repository:** `cip_controls.yaml` (34 controls) · 12 modules, ~5,600 lines ·
568 tests · runs locally, nothing leaves the machine.
