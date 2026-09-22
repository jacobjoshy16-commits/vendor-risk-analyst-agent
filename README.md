# Substation Supply-Chain Integrity Monitor

**Verifies vendor firmware is authentic before it reaches grid equipment, and
produces the NERC CIP evidence for it.**

Built on a synthetic utility estate. Runs locally; nothing leaves the machine.

---

## The problem

A protective relay in a substation decides whether high-voltage power flows. Its
firmware comes from a vendor. Before install, someone has to prove it is
authentic — that is **NERC CIP-010 R1 Part 1.6**.

Today that is often an engineer downloading a file, comparing a SHA-256 to the
vendor's release notes, and recording it on a spreadsheet.

**That has a specific blind spot.** A hash proves the file matches *a published
string*. It does not prove the string came from the vendor — whoever can swap
the binary on a mirror can swap the hash printed beside it. Same channel.

A signature is the part they cannot forge.

| Check | Answers | NERC |
| --- | --- | --- |
| SHA-256 | Are these the bytes the published digest describes? | R1.6.2 |
| Ed25519 signature | Did the vendor vouch for these exact bytes? | R1.6.1 + R1.6.2 |

The demo shows a package that **passes the hash check and fails the signature
check**. The spreadsheet process approves it.

---

## Walk the whole lifecycle

```bash
python3 scripts/walkthrough.py           # straight through
python3 scripts/walkthrough.py --pause   # stop between stages, for a demo
python3 scripts/walkthrough.py --live    # use Ollama instead of the stand-in
```

Six stages, in the order they happen, with the real command printed at each step
so you can run any stage on its own:

| | Stage | What you see |
| --- | --- | --- |
| 1 | **Onboard** | The model reads the vendor's contracts and quotes each CIP-013 clause; code verifies every quote |
| 2 | **Cryptography** | SHA-256 then Ed25519 over the bytes they shipped — one release passes, one does not |
| 3 | **NERC controls** | Which requirements applied, to how many assets, with a denominator |
| 4 | **The model** | It reasons over everything the code found and decides |
| 5 | **Memory** | Seal the state, flip one bit, watch it get caught next cycle |
| 6 | **Output** | Audit pack, agent ledger, the alert a security team receives |

---

## The demo: a vendor pushes an update that is not from the vendor

```bash
python3 scripts/simulate_push.py
```

Stands up a fake vendor distribution server on localhost and drives the whole
chain against it over HTTP — twice.

**Round 1, genuine release:** fetched, hash matches, signature valid, `ACCEPTED`,
exit 0.

**Then the attacker takes the mirror.** They replace the binary *and* update the
SHA-256 published beside it — both are served from a host they control. What they
cannot do is forge the signature; the vendor publishes their key through a
separate channel.

**Round 2, substituted release:**

```
vendor published SHA-256 086b04f8…: MATCH
Ed25519 verify against key sentinel-protective-2026: INVALID
BLOCKED — do not deploy                                        exit 1
```

Then the governance half runs: NERC controls evaluate, an audit record is written
back, and an alert is routed.

```
blocked-SPS-680-2.3.0-2026-09-21.json
  disposition              block
  citation                 NERC CIP-010-4 R1 Part 1.6
  hash_match               True
  signature_verified       False
  integrity_verified       False

alert → CIP Senior Manager / Security on-call
```

The vendor was never breached. Their mirror was. The hash check passed and the
signature check is what caught it.

---

## Quick start

```bash
pip install -r requirements.txt
python3 vra.py cip build-fixtures
```

The one command that shows the point:

```bash
python3 vra.py cip gate --package SPS-421-4.7.2 --offline
```

```
  vendor published SHA-256 cf57cc28…: MATCH
  Ed25519 verify against key sentinel-protective-2026: INVALID
  BLOCKED — do not deploy
```

Exit code `1`. In a deployment pipeline, that firmware does not get flashed.

---

## Commands

| Command | What it does | Exit |
| --- | --- | --- |
| `cip gate --package X` | Verify one package | **1 = do not deploy** |
| `cip commission --batch DIR` | Verify a whole plant's firmware delivery | 1 if any blocked |
| `cip onboard --vendor X --docs DIR` | Read a vendor's contracts, score CIP-013 | 1 if critical |
| `cip` | Assess the whole estate | 1 if critical |
| `cip monitor` | Re-assess on a timer, alert on change | 0 |
| `cip seal` / `cip drift` | Baseline a vendor, then detect undeclared change | 1 on drift |
| `cip agent-log` | What the AI decided, and on which model | 0 |

Add `--evidence` to write the audit pack. Add `--offline` to skip the model.

---

## How it works

```
firmware .bin ──▶ SHA-256 + Ed25519 against a registry of pinned vendor keys
                        │
                        ▼
                  34 NERC controls over four subjects,
                  scoped by CIP-002 impact rating
                        │
                        ▼
                  a local model receives the crypto result, the failed
                  controls, the blast radius and the vendor's history,
                  and reaches a disposition
                        │
                        ▼
                  block · allow · escalate  →  audit pack + routed alert
                        │
                        ▼
                  seal the approved state; alert on later change
                  that carries no recorded approval
```

### The four subjects

| Subject | Standards |
| --- | --- |
| Firmware deployments | CIP-010 R1.6 |
| Procurement, per vendor | CIP-013 R1/R2/R3 |
| Vendor ESP access | CIP-005 R2, CIP-003-9 §6 |
| Vendor personnel | CIP-004 R2–R5 |

CIP-002 impact ratings gate every control, producing two populations: high and
medium impact for CIP-013 and CIP-010, and low-impact assets *that allow vendor
remote access* for CIP-003-9. Low-impact assets with no vendor path are reported
**not applicable** — never **passing**.

### Where the AI sits

**Reading a contract is a fact question.** The model locates a CIP-013 clause and
quotes it; code then checks the quote exists in the document, is *about* that
obligation, and was not reused for another one.

Two rules bound it:

- **Presence can be evidenced; absence cannot.** Nothing a model can quote proves
  a clause is *missing*, so "not present" becomes a question for the vendor —
  never a control failure.
- **A verified quote cannot raise a critical alone.** Verification proves the text
  exists, not that its scope was read right.

**Deciding about a package is a judgement.** There the code runs first and hands
the model everything it found. `--decision code|model|both` picks the authority.

**Every model call is logged** — task, input digest, disposition, confidence,
model build. Append-only.

---

## Running the proof yourself

Nothing below is a claim you have to take on faith. Both scripts write a report
of what actually happened on your machine.

### 1. The pipeline

```bash
python3 scripts/prove.py
```

18 checks end to end → writes **`RESULTS.md`**: for each claim, the command, the
expected outcome, the real captured output, PASS/FAIL. Exits non-zero if any
check fails.

The run flips a bit in a firmware image, detects it, restores it, seals a
baseline, drifts it, approves the drift, and reverts everything. Your repo is
unchanged afterwards.

Checks are ordered **negative controls first** — "it caught the bad firmware"
means nothing until you have seen it stay silent on the fourteen good ones.

### 2. The model path

```bash
ollama serve &
ollama pull qwen2.5:7b-instruct        # or qwen2.5:3b on less memory
python3 scripts/prove_live.py
```

Five steps against your real model → writes **`LIVE-RESULTS.md`** with what the
model actually said. If Ollama is not reachable it tells you the commands to fix
it rather than failing quietly.

No Ollama handy:

```bash
python3 scripts/prove_live.py --fake
```

Stands up a local server speaking Ollama's HTTP API that behaves like a small
model having a bad day — prose instead of JSON, code fences, invalid enums, and
one genuine sentence offered as evidence for every obligation. Everything past
the socket is the real code path.

That last behaviour found a real bug: **quote verification alone is not enough.**
A model can satisfy it by quoting any sufficiently long real sentence, and the
register then gains a clause the contract does not contain. The offline
heuristic could never expose it, because it finds quotes *by* keyword.

### 3. The test suite

```bash
python3 -m unittest discover -s tests -t .      # 574 tests
```

`RESULTS.md` and `LIVE-RESULTS.md` are gitignored. They are yours to generate,
not something the repo ships.

---

## Honest limits

- **Everything is synthetic.** ~7,500 devices across 1,300 substations, modelled
  on a mid-size utility. Invented vendors. No OT connection, no real data.
- **22 of 34 citations verified** against the standard text (CIP-010 R1.6,
  CIP-013 R1, CIP-005 R2, CIP-003-9). The rest are flagged and the tool prints a
  banner. CIP-004 part numbers are unread.
- **Ed25519 is not what most OT vendors ship.** Many publish a digest only; where
  signing exists it is usually X.509. The `hash_only` path is probably the common
  real-world case.
- **Flat key registry** — status and validity windows, no certificate chain
  validation, no revocation checking. It is not PKI.
- **Contract extraction has never seen a real MSA.**
- **No vendor tenant integration.** Drift compares against sealed data, not a
  vendor's live system.

**This does not fill a gap in anyone's compliance program.** A utility of any
size already has CIP-013 processes, a GRC platform, and vendor management. It is
a working model of the problem those programs solve.

---

## Repository

```
cip_controls.yaml       34 NERC controls — the policy, editable without code
src/vra/cipcrypto.py    SHA-256, Ed25519, key registry
src/vra/grid.py         the synthetic estate
src/vra/cip.py          control evaluation + coverage
src/vra/procure.py      contract reading, quote verification
src/vra/analyst_cip.py  the model's judgement
src/vra/ledger.py       sealed baselines, drift, agent log
src/vra/evidence.py     audit pack
src/vra/cipcli.py       the commands
scripts/prove.py        proves the pipeline
scripts/prove_live.py   proves the model path
PORTFOLIO.md            the write-up
```
