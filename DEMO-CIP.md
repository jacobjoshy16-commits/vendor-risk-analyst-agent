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
python3 vra.py cip build-fixtures                # once; estate + batch + onboarding
python3 vra.py cip --date 2026-09-21 --evidence  # warm the run
```

Pin `--date` so your numbers match what you rehearsed. Have
`out/cip/evidence-pack.html` open in a second tab.

---

## Beat 0 — the hook from their own filing (15s)

Open with what they already do, not with a gap:

> "Your 10-K says you run a vendor risk management program, and that you use
> threat intelligence to continuously monitor the cybersecurity risk of key
> vendors. I built the piece that produces the CIP evidence that program would
> hand an auditor."

Then the reason it matters *now*:

> "You're spending $6.35 billion on generation this year and $8 billion next,
> across about a dozen new plants, and you're connecting fourteen generators
> through MISO's expedited process. Every one of those arrives with vendor
> firmware. That's when this matters most."

See `ENTERGY-BRIEF.md` §1a for the full citations and the two things not to
raise.

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

## Beat 2 — the estate, and two different scopes (25s)

```bash
python3 vra.py cip --date 2026-09-21
```

Point at the scoping lines. **This is where you prove you know the standards
apart from each other.**

> "1,300 substations, 7,464 cyber assets. Two different populations here.
>
> 142 substations are high or medium impact — that's CIP-013, CIP-010 R1.6 and
> CIP-005 R2 scope. If a tool raises CIP-013 findings across all 1,300, ninety
> percent are wrong and an auditor finds that in ten minutes.
>
> But 69 **low impact** assets allow vendor electronic remote access, and those
> are in scope for CIP-003-9 Attachment 1 Section 6 — determine the sessions,
> disable them, detect malicious communications. Low impact doesn't mean no
> obligation. It means a *different, lighter* obligation.
>
> Low impact sites with no vendor access path are out of scope, and reported
> that way rather than as passing."

If you want the strongest version of this, tell the story:

> "I originally scoped this on high and medium impact only, which is right for
> CIP-013 and wrong for vendor remote access. CIP-003-9 moved that population.
> That's the kind of thing that actually happens to a compliance program — the
> applicable population changes under you."

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

## Beat 3b — the commissioning batch (35s) — the Entergy-specific beat

```bash
python3 vra.py cip commission --plant "Cypress Bend Energy Center" \
    --batch sandbox/commissioning/cypress-bend --date 2026-09-21
```

Let the table land. Point at the **sha-256 column first**:

> "Twelve packages, six vendors, one delivery for a new plant. Look at the hash
> column — every single row says MATCH. A hash-and-spreadsheet process signs off
> on this entire batch.
>
> Now the signature column. One INVALID. And it's the turbine control system —
> the one item in a plant that comes from a single supplier, where there's no
> second source to compare a build against.
>
> Exit code 1. The plant doesn't energise."

Then connect it back:

> "Your Note 8 says you're committed to 21 power island sets from one turbine
> vendor and seven have been delivered. That's fourteen more deliveries where
> this check is the only thing standing between a substituted package and a
> running plant."

This is the beat that makes the demo *theirs* rather than generic.

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

---

## Questions you will get, and the honest answers

### "Your estate is Arkansas, Louisiana, Mississippi and Texas. Is that us?"

Someone will notice. Have this ready, and say it before they finish asking:

> "It's sized and shaped to resemble a utility of your scale — roughly 1,300
> substations across four states — so the numbers are realistic. It contains no
> Entergy data. Every substation name, vendor, technician and firmware image is
> fabricated, and the generator that produces them is one file you can read."

Do not be vague here. Any ambiguity about whether you modelled their actual
system is worse than the demo being less impressive.

### "What version of the standards is this against?"

The honest answer, which is stronger than a confident wrong one:

> "Every control carries a pinned standard, revision, requirement and part, plus
> a `citation_verified` flag. Six of thirty-four are verified — the CIP-010
> controls this demo actually exercises. NERC lists CIP-010-4 as mandatory and
> subject to enforcement, so what you're seeing is cited correctly. The other
> twenty-eight are flagged and the pack says so.
>
> And the verified ones aren't verified forever. CIP-010-5 takes effect
> 1 April 2028 under FERC Order 919, and the software integrity requirement
> moves from Part 1.6 to Part 1.3. The tool knows that date, and it'll start
> warning a year out and error after. A citation check with no expiry is how
> you end up confidently citing a superseded revision."

That last paragraph is the one to land. Anyone who has worked a CIP program has
been bitten by a standard revision, and a tool that tracks the sunset rather
than trusting a one-time check is saying something they will recognise.

### "What about Power Through — are those in scope?"

**Do not claim CIP covers them.** Small utility-owned units at customer sites
are probably below the size thresholds for NERC CIP to apply. The honest answer
is also the better one:

> "Those likely fall outside CIP, which is exactly why they'd need a lighter
> control rather than the same one. Same verification logic, different
> applicability gate — which is what the CIP-003-9 low-impact path already does."

### "Doesn't CIP-015 require monitoring inside the ESP now?"

**No — and do not say it does.** CIP-015-1 is approved but scheduled for
enforcement on **1 October 2028**. It is not in force. If you say "now requires"
to an Entergy engineer they will correct you, and you will have spent your
credibility on a detail you did not need. This tool does not implement CIP-015
and does not claim to.

### "Is this doing real cryptography or is it mocked?"

```bash
python3 -m unittest tests.test_cip.CryptoIsReal -v
```

The bit-flip test settles it in ten seconds.

---

## Before the fair — the one task worth doing

**Done.** The six the demo touches (CIP-01 … CIP-06) are verified: CIP-010-4 is
mandatory and subject to enforcement, the part is 1.6, and the sunset to
CIP-010-5 Part 1.3 on 2028-04-01 is recorded and re-checked every run.

If you have time before the fair, the next most valuable are **CIP-12**
(R1.2.5, software integrity — the critical one) and **CIP-31 … CIP-34**
(CIP-003-9 Section 6, the low-impact story), since those are the two things you
will be talking about. Confirm the revision and part, then set
`citation_verified: true` and `citation_verified_by`.
