# Demo script — NERC CIP module

**Audience:** an Entergy engineer, compliance lead, or recruiter at a career
fair. Target 3 minutes. You will often get 90 seconds.

**Before you start, say this sentence.** It buys you credibility you cannot buy
any other way, and anyone who works in CIP is already thinking it:

> "Everything here is synthetic — fabricated substations, fabricated vendors,
> air-gapped. Nothing touches a real OT network."

---

## Setup (before the event)

```bash
pip install -r requirements.txt
python3 vra.py cip build-fixtures --date 2026-09-20   # once; regenerates the estate
python3 vra.py cip --date 2026-09-20 --evidence       # warm the run
```

Pin `--date` so your numbers match what you rehearsed. Have
`out/cip/evidence-pack.html` open in a second tab.

---

## Beat 1 — the problem (25s, no terminal)

> "Entergy runs about 1,300 substations. Inside them, protective relays and
> RTUs decide whether high-voltage power flows. Firmware for those devices comes
> from vendors, and before it's flashed somebody has to prove it's authentic.
>
> Today that's largely manual. An engineer downloads the file, compares the hash
> to the vendor's release notes, and records it on a spreadsheet. That process
> has a specific blind spot, and I built a tool to show it."

Do not say "$1 million a day." If penalties come up, say *"the statutory
maximum under FPA 316A is about $1M per day per violation; actual exposure is
set by the VRF/VSL matrix."* That one sentence signals you've read the standard.

## Beat 2 — the estate (20s)

```bash
python3 vra.py cip --date 2026-09-20
```

Point at the first three lines.

> "1,300 substations, 7,464 cyber assets. Notice the second line — only 142 are
> high or medium impact. That's CIP-002 doing its job. The other 1,158 are
> reported **not applicable**, not passing. If a tool raises CIP-013 findings
> across all 1,300, ninety percent of them are wrong and an auditor finds that
> in ten minutes."

## Beat 3 — the money shot (45s)

Let the red block land. Read it out loud, slowly:

```
FIRMWARE VERIFICATION FAILED  SPS-421-4.7.2
    computed SHA-256 cf57cc28...
    vendor published SHA-256 cf57cc28...: MATCH
    Ed25519 verify against key sentinel-protective-2026: INVALID
```

> "Look at those two middle lines. **The hash matches.** The spreadsheet process
> passes this package. Green tick, sign it off, flash it.
>
> The signature doesn't verify. The bytes match a string the vendor published —
> but if an attacker can swap the binary on a distribution mirror, they can swap
> the hash printed next to it. Same channel. What they can't do is forge the
> vendor's signing key.
>
> That's the gap. Hash-checking proves the file matches a published string. It
> does not prove the string came from the vendor."

Then the scale line:

> "That one package is on 131 protective relays across the estate."

## Beat 4 — this is real crypto (20s)

The question you want is *"what is it actually doing?"* Have this ready:

```bash
python3 -m unittest tests.test_cip.CryptoIsReal -v
```

> "Real Ed25519. That test flips a single bit in an 8 KB firmware image and
> requires verification to fail. Nothing that reads a boolean out of a config
> file passes that test. The grid is fake — the cryptography isn't."

## Beat 5 — the audit artifact (30s)

Switch to `out/cip/evidence-pack.html`.

> "This is what you'd hand a compliance lead. It's organised by requirement, not
> by finding, because an audit doesn't open with 'what's broken' — it opens with
> 'show me you checked.'
>
> Every row has a denominator: CIP-010 R1.6.2, 1,724 applicable, 1,593 passed,
> 131 exceptions. And the 131 collapse to **one root cause**, because it's one
> bad package, not 131 problems."

Scroll to the yellow banner:

> "And it tells you what it hasn't verified. I wrote these citations from
> knowledge; I haven't checked the revision numbers against nerc.com yet. The
> tool refuses to print a confident citation nobody confirmed."

That banner is not a weakness to hide. Volunteering a known limitation is the
single most credible thing you can do in front of a compliance person.

---

## The three questions you will get

**"Is this actually doing cryptography or is it mocked?"**
Run `tests.test_cip.CryptoIsReal`. The bit-flip test settles it in ten seconds.

**"CIP-013 doesn't require firmware signature checking."**
Correct — and say so immediately. *"CIP-013 is a plan standard: R1 develop, R2
implement, R3 review every 15 months. The per-installation check is CIP-010 R1
Part 1.6. CIP-013 R1.2.5 requires your procurement process to make sure the
vendor gives you a verification method. Both are in the control set, cited
separately."* Getting this right is the difference between a student project and
someone who read the standard.

**"How would this work on our actual estate?"**
Be honest about the gap: *"Today the asset data is generated. In production this
reads from your CMDB or asset database and your key registry. The verification
engine and the control set wouldn't change — only the source of the inventory."*

---

## Do not say

- "This makes you CIP compliant." Say *"this automates the evidence CIP-010 R1.6
  and CIP-004 R4 require you to produce."* The first is a claim you cannot back.
- "It's connected to a substation." It is not, and implying so is worse than
  useless in this industry.
- Any real vendor name as the failing one. The failing vendor is fictional on
  purpose.

---

## If you only get 60 seconds

Run the command. Point at MATCH / INVALID. Say:

> "The hash matches, the signature doesn't. A hash-and-spreadsheet process
> passes this firmware. Real cryptography catches it. It's on 131 relays."

Then hand over the HTML pack.
