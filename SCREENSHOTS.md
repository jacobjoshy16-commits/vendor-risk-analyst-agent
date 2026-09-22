# Screenshots for the portfolio

```bash
./scripts/portfolio-run.sh          # list the scenes
./scripts/portfolio-run.sh 2        # run one, screenshot it
./scripts/portfolio-run.sh all      # every scene, pausing between
```

Each scene clears the screen and prints one self-contained result, so the
screenshot needs no cropping.

**Before you start:**

```bash
pip install -r requirements.txt
python3 vra.py cip build-fixtures
rm -rf data out          # clean slate, so counters start at zero
```

Terminal settings that make the shots readable: **dark background, 14pt+ font,
~100 columns wide**. Resize before you start so every shot matches.

---

## The five that matter

If you only take five, take these.

### 1. Scene 2 — the blind spot

**Caption:** *"The published hash matches. The signature does not. A
hash-and-spreadsheet process approves this package."*

The shot is the four-line verification log. Both SHA-256 values are identical
and the Ed25519 line says INVALID. That contrast is the entire project.

### 2. Scene 3 — the negative control

**Caption:** *"A correctly signed package from the same pipeline. Exit 0."*

Put this **immediately after** shot 1. A detector that only ever fires proves
nothing; the pair proves it discriminates. Most portfolios skip this, and it is
the shot a security engineer will actually respect.

### 3. Scene 4 — the commissioning batch

**Caption:** *"Twelve packages for one new plant. Every row passes the hash
check. One signature fails — the turbine control system, from the single-source
vendor."*

Crop nothing. The point is the whole `sha-256` column reading MATCH with one
`INVALID` in the signature column.

### 4. Scene 5 — reading a vendor contract

**Caption:** *"The model reads the contract and quotes each clause. Code
verifies the quote exists in the source before it can affect a control. Two
claims were refused."*

Make sure step 4 ("What the code refused to let the model decide") is in frame —
that is the differentiator, not the extraction.

### 5. Scene 8 — drift

**Caption:** *"The approved vendor state is sealed. A release re-published under
the same version number is caught on the next cycle."*

Shows all three steps in one shot: seal, change, detect.

---

## The rest, if you have room

| Scene | Caption |
| --- | --- |
| **1** | *"568 tests. The load-bearing ones are negative controls."* |
| **6** | *"Two scoping populations: 142 substations for CIP-013, 69 low-impact assets for CIP-003-9. The rest are not applicable, not passing."* |
| **7** | *"Requirement coverage with a denominator on every row — an audit opens with 'show me you checked.'"* |
| **9** | *"Every AI decision is logged: what it saw, what it chose, which model. The AI is auditable too."* |
| **10** | *"Flipping a single bit breaks verification. Proof the cryptography is real, not a stored field."* |
| **11** | Browser shot of `out/cip/evidence-pack.html` — *"The audit evidence pack, organised by NERC requirement."* |

---

## Where they go in the paper

`PORTFOLIO.md` has seven sections. Suggested placement:

| Section | Shots |
| --- | --- |
| §2 The blind spot | **2, 3** side by side |
| §3 What was built | **4**, then **11** |
| §4 Where the AI sits | **5**, then **9** |
| §5 Validation | **10**, then **1** |
| §3 or §5 | **8** |

Two shots on the first page. Everything else earns its place or gets cut.

---

## Three things to avoid

**Never crop out the "synthetic" line.** Every scene prints it. If a shot is
missing that line, add it to the caption — a screenshot that looks like real
utility data is the one mistake you cannot walk back.

**Do not screenshot a scrolling wall.** Scenes 6, 7 and 5 are already truncated
to fit. If a shot needs scrolling, it needs a smaller scene.

**Do not annotate with red arrows and circles.** Let the MATCH / INVALID
contrast do the work. The caption carries the point.
