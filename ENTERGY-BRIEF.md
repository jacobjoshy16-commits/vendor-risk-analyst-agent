# Why this exists — the Entergy case

**Read §6 before you quote anything.** Some of what follows is confirmed against
Entergy's SEC filings and some is not, and the difference is marked. Asserting a
quote from a company's own 10-K, in front of that company, and being wrong about
it, is the one mistake this brief exists to prevent.

---

## 1. The problem, in Entergy's own filings

Entergy Corporation files a **combined** Form 10-K covering the parent and its
registrant subsidiaries, so the same document appears on EDGAR under several
CIKs:

| Registrant | CIK |
| --- | --- |
| Entergy Corporation /DE/ | 0000065984 |
| Entergy Arkansas | 0000007323 |
| Entergy Louisiana, LLC | 0001348952 |

Two disclosures matter here.

### Item 1A — Risk Factors

Entergy's risk factors describe heightened risk of physical and cyber attack
directed at its **generation facilities, transmission operations centers, and
distribution infrastructure**, and state that such an act could affect its
ability to operate, including the information technology systems and network
infrastructure it relies on to conduct business.

Two phrases in that section do the real work for this project:

- Entergy describes operating **"in a highly regulated industry that requires
  the continued operation of sophisticated information technology systems and
  network infrastructure in accordance with mandatory and prescriptive
  standards."**
- It states that such events may expose it to **increased risk of judgments and
  fines**.

That is a utility telling its investors, in a filing, that its compliance
exposure on cyber controls is financial and that the standards are prescriptive
rather than discretionary.

### Item 1C — Cybersecurity

Entergy describes a **three lines of defense** security-risk-management model.
The third line includes Internal Audit, independent third parties, and — in
Entergy's own framing — certain regulatory constructs such as the **NERC
Reliability Standards** and the NRC Cyber Rule, providing assurance to senior
management and the Board. Governance sits with the Board, with the **Audit
Committee holding primary responsibility**, receiving quarterly reports from
the CSO, CISO, CIO and General Auditor.

And, critically:

> Entergy uses a **"vendor risk management program to assess and monitor
> security risks that arise from certain third-party vendors"**, and uses
> threat-intelligence services to **"continuously monitor the cybersecurity risk
> of key vendors."**

---

## 1a. The three hooks, ranked

### Hook 1 — they already run this program; this feeds it

They are not missing the idea. They have a vendor risk program and they
continuously monitor key vendors. What this tool produces is a *specific
artifact* that program would hand an auditor.

> **"Your 10-K says you run a vendor risk management program. Mine produces the
> CIP evidence that program would hand an auditor."**

That lands better than "you have a gap," because it is not a critique of their
program — it is an example of its output.

### Hook 2 — an unusual volume of new vendor equipment is about to arrive

This is the strongest angle and it is spread across several sections:

| Where | What |
| --- | --- |
| MD&A capital plan | Generation spending of **$6.35B in 2026** and **$8.01B in 2027** |
| Item 1 | Roughly a dozen new plants: Orange County, Legend, Lone Star, Franklin Farms, Delta Blues, Traceview, Vicksburg |
| Item 1 (MISO) | Using MISO's expedited study process to connect **fourteen generators** |
| **Note 8, exclusivity agreement** | Committed to **21 power island equipment sets from one turbine vendor**, of which only **7 have been delivered** |
| Item 1 | "Power Through" — utility-owned generators at customer sites in all four states, remotely dispatchable |

New plants mean a large volume of vendor firmware arriving at commissioning,
from many suppliers, against a schedule. That is exactly where a substituted
package slips through, because the pressure at that moment is to energise rather
than to check.

The **Note 8** row is the sharpest of these. A single turbine supplier, 21 sets
committed, 14 still to come, is concentrated dependence with no second source to
compare a build against.

> **"You're commissioning more new generation in the next three years than most
> utilities do in ten. Every one of those plants arrives with vendor firmware.
> That's when signature checks matter most."**

**This is what `vra.py cip commission` demonstrates** — see §4.8.

**Caution on Power Through.** Small units at customer sites are probably below
the size thresholds for NERC CIP to apply. **Verify before the fair and do not
claim CIP covers them.** If it comes up: *"Those likely fall outside CIP, which
is exactly why they'd need a lighter control."*

### Hook 3 — they state detection limits, and name AI-driven threats

Item 1A, cyber risk factor:

> **"Entergy cannot anticipate, detect, or implement fully preventive measures
> against all cybersecurity threats."**

The same section names **"threats fueled by artificial intelligence."**

This is the governance argument for the design, not an "AI will fix it" pitch:
in this tool the model reads documents and **never creates a finding**. Code
decides everything. An entity that has told its investors it cannot detect
everything, and that AI-driven threats are among what it faces, is exactly the
audience for a design where the AI structurally cannot invent a conclusion.

### Only if the conversation turns to nuclear

Item 1A's nuclear risk factor notes that some replacement parts **have to be
reverse-engineered**, with reliance on fewer suppliers. Proving a part is
authentic is the same class of problem as proving firmware is authentic. Raise
it only if they go there.

### Do not raise

- **The SEC investigation in Item 9B** (inventory records, $12M penalty). It is
  public, but bringing it to a recruiter reads as a gotcha.
- **Naming data center customers** as attack surface. It sounds like speculation
  about their clients.

---

## 2. The operational reality behind the disclosure

Entergy operates roughly **1,300 substations** and **16,100 circuit miles** of
transmission across Arkansas, Louisiana, Mississippi and Texas.

Inside those substations, protective relays and remote terminal units decide
whether high-voltage power flows. Their firmware is supplied by vendors. Before
it is flashed, somebody has to establish that it is authentic.

**CIP-010-4 Requirement R1 Part 1.6** requires exactly that, prior to a change
that deviates from the baseline configuration and where the method is available
from the software source:

> 1.6.1 Verify the identity of the software source; and
> 1.6.2 Verify the integrity of the software obtained from the software source.

**CIP-013-2** requires the *procurement process* to address vendor provision of
those verification methods (R1 Part 1.2.5), along with incident notification,
vulnerability disclosure, and coordination of vendor remote access.

The bottleneck is that at most utilities this is semi-manual. An engineer
downloads a firmware binary, compares the SHA-256 to the vendor's release notes,
records it on a spreadsheet, and moves on.

**That process has a specific blind spot, and closing it is the entire point of
this tool.**

---

## 3. The blind spot

A hash proves the file matches **a published string**. It does not prove that
string came from the vendor.

An attacker who can substitute a binary on a distribution mirror can substitute
the digest printed beside it — the binary and the hash travel the same channel.
What they cannot do is forge a signature without the vendor's private key.

So the tool computes both, and treats them as answering different questions:

| Check | Question | NERC part |
| --- | --- | --- |
| **SHA-256** | Are these the bytes the published digest describes? | R1.6.2 |
| **Ed25519 signature** | Did the vendor vouch for these exact bytes? | R1.6.1 + R1.6.2 |

Where a vendor publishes a signing key, **a matching hash does not close
R1.6.2**. Where a vendor publishes no key, the hash is the only method available
from the source, so it is used — and the result is recorded as
`verification_strength: hash_only` rather than presented as the stronger check.

The demo scenario is built to show exactly this: a package that **passes the
hash check and fails the signature check**, constructed the way a real mirror
compromise looks. In the simulated estate it is deployed on **131 protective
relays**. The spreadsheet process returns green on every one of them.

---

## 4. How the system works, end to end

### 4.1 Inputs

| Input | What it is |
| --- | --- |
| Asset estate | 1,300 substations, ~7,500 cyber assets, each with a CIP-002 impact rating |
| Firmware packages | Real binaries with real Ed25519 signatures and published SHA-256 digests |
| Key registry | Trusted vendor signing keys with status, validity window and fingerprint |
| Vendor contracts | Actual documents — MSA, security questionnaire — for procurement analysis |
| Control set | 34 NERC controls in YAML, version-pinned |

### 4.2 The verification core

For each distinct firmware package, once per run:

```
read bytes → SHA-256 → compare to published digest
           → Ed25519 verify against the pinned vendor key
           → check key status on the assessment date
           → derive R1.6.1 (source identity) and R1.6.2 (integrity)
           → record every operation in an evidence log
```

Nothing is asserted. Flip one bit in an 8 KB image and the answer changes,
because the answer is a cryptographic fact. A test does precisely that — XORs a
single bit at three offsets and requires verification to fail each time.

### 4.3 Scoping — which requirements even apply

CIP-002 impact ratings drive `applies_when` on every control. This produces two
distinct populations:

| Population | Standards | Count |
| --- | --- | ---: |
| High / medium impact substations | CIP-013, CIP-010 R1.6, CIP-005 R2 | 142 |
| Low impact assets **that allow vendor electronic remote access** | CIP-003-9 Att. 1 §6 | 69 |
| Low impact with no vendor access path | none — genuinely out of scope | the rest |

Low-impact assets are reported **not applicable**, never **passing**. A tool
that raised CIP-013 findings across all 1,300 sites would be wrong about ~89% of
them, and an auditor finds that in ten minutes.

CIP-003-9 became effective 1 April 2026 and is the reason the second population
exists. It obliges the entity — for low-impact assets that allow vendor
electronic remote access — to determine those sessions, disable them, and detect
malicious communications.

### 4.4 Procurement — the model reads the contract, code decides

CIP-013 R1.2.1–R1.2.6 ask whether the procurement process addresses six
obligations. Answering that from a checkbox somebody typed just moves the work.
So a language model reads the actual master services agreement.

**The model finds and quotes the clause. Code decides what it means.**

```
contract documents → MODEL → claim + verbatim quote
                                    ↓
                              CODE: is the quote really in the document?
                                    is this field critical?
                                    presence, or absence?
                                    ↓
                       finding · information gap · human review queue
```

Two rules bound it:

1. **Presence can be evidenced. Absence cannot.** A model can quote §9.1 to show
   an incident-notification clause exists. Nothing it can quote proves a clause
   is *missing*. So "not present" becomes an information gap with a question for
   the vendor — never a control failure. Inverting this would let a model fail a
   vendor on a clause it merely failed to find in a 90-page contract.
2. **A verified quote is not a licence to raise a critical.** Verification proves
   the text exists, not that its scope was read correctly — a definition, a
   struck exhibit, or a clause scoped to another product line all quote
   perfectly. Criticals route to human ratification.

On the sample vendor: six clauses applied, two withheld with reasons.

### 4.8 Commissioning — a whole plant's batch at once

```bash
python3 vra.py cip commission --plant "Cypress Bend Energy Center" \
    --batch ./vendor-firmware-batch
```

Twelve packages, six vendors, one delivery. Every row passes the hash check.
One signature does not:

```
package                    vendor                         sha-256   signature  verdict
MTS-EXC-220-1.7.1          Meridian Turbine Systems       MATCH     VALID      accepted
MTS-GOV-400-2.0.4          Meridian Turbine Systems       MATCH     VALID      accepted
MTS-PICS-9000-3.1.0        Meridian Turbine Systems       MATCH     INVALID    BLOCKED
SPS-411-3.9.1              Sentinel Protective Systems    MATCH     VALID      accepted
...
ENERGISATION BLOCKED — 1 of 12 packages failed
```

Exit code 1. The blocked package is the **turbine control system** — the item in
a plant that typically comes from a single supplier, where there is no second
source to compare against. That is the Note 8 dependency in §1a, made concrete.

Eleven correctly-signed packages stay silent, which is what makes the twelfth
mean something.

### 4.5 Continuous monitoring

```bash
python3 vra.py cip monitor --interval 15m
```

State persists in `data/cip_findings.json` — when a finding was *first* raised,
whether anyone was told, whether it cleared. Due dates anchor to first sighting,
so a finding re-seen every fifteen minutes still goes overdue.

Alerts fire on transitions only, and two rules keep the channel readable:

- **Cold start is a baseline, not an alert storm.** The first run records what is
  already open and sends nothing.
- **Findings group by root cause.** One substituted package across 17 relays is
  one alert naming 17 assets, not 17 pages.

Flip one bit in a firmware image and the next cycle says so, routed by severity:

```
NEW FINDING  [critical] -> CIP Senior Manager / Security on-call
  17 assets: integrity_verified=False. CIP-010-4 R1 Part 1.6.2.
  e.g. AR-SUB-0001-RTU-05-FW, +14 more. Remediate by 2026-09-28.
```

The alert names **the obligation, not the supplier**. CIP-003-9 obliges the
Responsible Entity; an alert calling the vendor non-compliant is wrong on the
facts.

### 4.6 Enforcement — one place, deliberately

```bash
python3 vra.py cip gate --package KG-RTU-100-2.4.1
#   BLOCKED — do not deploy
#   exit 1
```

CIP-010 R1.6 requires verification *prior to* a change that deviates from
baseline, so a gate that blocks the deployment **is** the requirement. Put it in
a patch pipeline and unverified firmware cannot be flashed.

It will **not** terminate a live vendor session into a substation. That has
reliability consequences and belongs to a human with operational authority.
Those findings alert instead.

### 4.7 Audit evidence

`--evidence` produces a pack organised **by requirement, not by finding** —
because an audit opens with "show me you checked", not "what's broken". Every
requirement carries its denominator:

```
CIP-01  CIP-010-4 R1 Part 1.6.2
        7,464 population · 1,724 applicable · 1,593 passed · 131 exceptions
```

The pack **never states compliance**. That determination belongs to the Regional
Entity, and a tool that claims it is selling something it cannot back.

---

## 5. What this is not

- Not a compliance determination. It automates the evidence CIP-010 R1.6 and
  CIP-004 R4 require an entity to produce.
- Not connected to any OT network. The estate, vendors, personnel and firmware
  are synthetic throughout, and the vendor names are invented.
- Not a certificate-chain implementation. Flat registry of pinned keys; real
  relay vendors sign with RSA or ECDSA under X.509 with path validation.
- Not tested against real contracts. The adjudication logic is validated; the
  extraction quality on a real 90-page MSA is not.

---

## 6. Citation status — verify before you quote

| Claim | Status |
| --- | --- |
| Entergy files a combined 10-K under multiple registrant CIKs | **Confirmed** — the same accession appears under 65984, 7323 and 1348952 |
| Item 1C describes a three lines of defense model | **Confirmed via search of the filing** |
| Item 1C's third line names NERC Reliability Standards and the NRC Cyber Rule | **Confirmed via search of the filing** |
| Audit Committee has primary cybersecurity oversight; quarterly reports from CSO/CISO/CIO/General Auditor | **Confirmed via search of the filing** |
| Item 1A cites attack risk to generation, transmission operations centers and distribution infrastructure | **Confirmed via search of the filing** |
| Item 1A cites "mandatory and prescriptive standards" and "judgments and fines" | **Confirmed via search of the filing** |
| Item 1C: "vendor risk management program to assess and monitor security risks that arise from certain third-party vendors" | **Confirmed by direct read of the filing** |
| Item 1C: threat-intelligence services "continuously monitor the cybersecurity risk of key vendors" | **Confirmed by direct read of the filing** |
| Item 1A: "cannot anticipate, detect, or implement fully preventive measures against all cybersecurity threats" | **Confirmed by direct read of the filing** |
| Item 1A names "threats fueled by artificial intelligence" | **Confirmed by direct read of the filing** |
| Capital plan $6.35B (2026) / $8.01B (2027); ~12 named plants; MISO expedited study for 14 generators | **Confirmed by direct read of the filing** |
| Note 8: 21 power island sets from one turbine vendor, 7 delivered | **Confirmed by direct read of the filing** |
| Whether NERC CIP applies to "Power Through" units at customer sites | **UNVERIFIED — likely below CIP size thresholds. Do not claim CIP covers them.** |
| ~1,300 substations, ~16,100 circuit miles | From Entergy's annual report; verify the current figures |

**Before presenting:**

1. The Item 1C and Item 1A language above came from a direct read of the filing.
   The three lines of defense and Audit Committee details came through search
   summaries — treat those as *reported* rather than *verbatim* until checked.
2. Resolve the Power Through row. It is the only claim here that could be wrong
   in a way a CIP engineer would catch immediately.
3. If penalties come up, say **"the statutory maximum under FPA §316A is roughly
   $1M per day per violation; actual exposure is set by the VRF/VSL matrix and
   mitigating factors."** "A million dollars a day" alone sounds like a brochure.
   The qualified version sounds like someone who has read the standard.
