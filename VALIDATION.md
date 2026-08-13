# Validation — measured against `sandbox/expected_findings.md`

Ground truth was written in Phase 0, **before** `watch.py`, `triage.py`, or `evaluate.py` existed. It has
not been edited since. Where the tool and the ground-truth document disagreed, the disagreement is
recorded below along with which one was wrong — nothing was silently reconciled.

**Reproduce:**

```bash
rm -rf data out pending_review          # clear prior state
python3 vra.py --offline --snapshot v1  # baseline    -> exit 0
python3 vra.py --offline --snapshot v2  # change run  -> exit 1
python3 tests/test_vra.py               # 46 tests    -> OK
```

Backend for all runs below: `offline-heuristic` (no Ollama runtime in this environment — see
[Limitation 1](#1-the-scored-runs-used-the-offline-backend-not-a-real-model)). Run date 2026-08-13.

---

## Scoreboard

| # | Expected behaviour | Result |
| --- | --- | --- |
| 1 | Baseline: no change detections on any vendor | ✅ 0 changed sources, 0 AI-relevant |
| 2 | Baseline: no criticals for Vendor A or B | ✅ 10 open findings, **critical 0** |
| 3 | Baseline: Aegis gaps on provider / training / retention / addendum | ✅ AIV-01, 04, 05, 11, 14, 15 |
| 4 | Baseline: Meridian bias-testing failure or gap | ✅ AIV-13 failure (high) |
| 5 | A: `ai_relevant` on changelog | ✅ `new_agent`, confidence 0.86 |
| 6 | A: `change_type` in {`new_agent`, `autonomy_increase`} | ✅ `new_agent` (preferred value) |
| 7 | A: `affected_fields` includes `autonomy` | ✅ `[autonomy, human_in_loop, status]` |
| 8 | A: proposed update `suggests` → `acts` | ✅ `{autonomy: acts, human_in_loop: false}` |
| 9 | A: trust center diff also AI-relevant | ✅ `autonomy_increase`, confidence 0.70 |
| 10 | A: **critical** AIV-07 autonomous action without review | ✅ `AIV-07-78e00591`, critical, open |
| 11 | A: provider/retention stay gaps, not failures | ✅ AIV-01 and AIV-05 remain gaps |
| 12 | B: `ai_relevant` on subprocessors | ✅ `new_subprocessor`, confidence 0.78 |
| 13 | B: **evidence excerpt contains the Perplexity line** (Phase 8.4) | ✅ verbatim row, quoted below |
| 14 | B: `affected_fields` includes `model_provider` | ✅ `[model_provider]` |
| 15 | B: **critical** AIV-03 — "Pending" ≠ executed BAA | ✅ `AIV-03-f1456963`, critical, open |
| 16 | B: nothing raised from the cosmetic changelog diff | ✅ changelog → `ai_relevant: false` |
| 17 | C: every diffed source triages `ai_relevant: false` | ✅ 2 changed sources, **0 AI-relevant** |
| 18 | C: zero new findings | ✅ 5 findings, all carried from baseline, 0 new |
| 19 | Probe: unassessed live write scope reconciliation | ✅ `autonomy_drift` + `unassessed_write_scope` |
| 20 | No finding where all required fields are `unknown` | ✅ 12 gaps tracked separately from findings |
| 21 | No LLM output creates or re-severities a finding | ✅ enforced structurally, see below |
| 22 | Rerun on same snapshot reports zero changes | ✅ 0 changed, 0 new, 0 closed |

**Caught: 22 / 22 expected behaviours. Misses: 0. False positives: 0.**

That clean sheet is the *final* state. It is not the whole story — **four defects were found during
validation, three of them by these checks**, and one was a false critical on the baseline. They are
documented in full below, because a validation record that only shows the passing run is worthless.

---

## Run 1 — baseline (`--snapshot v1`), exit 0

```
Vendors assessed : 3      AI-relevant changes : 0
Open findings    : 10     (critical 0, high 2)
Information gaps : 12     New this run : 22     Closed : 0
```

| Vendor | Sources changed | AI-relevant | Findings | Gaps |
| --- | --- | --- | --- | --- |
| Aegis Identity Cloud | 0 | 0 | 3 | 6 |
| Loop Workspace | 0 | 0 | 2 | 3 |
| Meridian RevCycle | 0 | 0 | 5 | 3 |

No prior snapshot exists, so every source is a baseline capture and nothing is diffed — as required.
The 10 findings come from the hand-authored register alone. **Zero criticals**, matching ground truth:
criticals must arrive in run 2, otherwise the run-2 result proves nothing.

## Run 2 — change run (`--snapshot v2`), exit 1

```
Vendors assessed : 3      AI-relevant changes : 3
Open findings    : 12     (critical 2, high 2)
Information gaps : 12     New this run : 2      Closed : 0

NEW CRITICAL AIV-07  Aegis Identity Cloud — Access Copilot
NEW CRITICAL AIV-03  Loop Workspace — Loop Assist
```

| Vendor | Sources changed | AI-relevant | Findings | Gaps | Δ vs baseline |
| --- | --- | --- | --- | --- | --- |
| Aegis Identity Cloud | 3 | 2 | 4 | 6 | +1 critical |
| Loop Workspace | 2 | 1 | 3 | 3 | +1 critical |
| Meridian RevCycle | 2 | **0** | 5 | 3 | **no change** |

Exactly two new findings across the run, both critical, both planted. Nothing else moved.

### Vendor A — the autonomous agent

`AIV-07-78e00591` · critical · due 2026-08-20 (7 days, from the severity table) · owner CISO / Vendor Risk Lead

Provenance is the tenant probe, **not** the changelog prose:

```json
"autonomy": {
  "value": "acts",
  "provenance": "in_tenant_probe:unassessed_write_scope",
  "evidence": "AI component 'Access Copilot Agent' is ACTIVE in the tenant and holds directory
               write scopes (okta.groups.manage, okta.sessions.revoke, okta.users.manage) under
               principal(s) copilot-agent. The register carries autonomy=suggests."
}
```

This is the distinction that matters for a compliance artifact. The changelog *announced* agent mode; the
probe *proved* it was live in our tenant with write scope. The finding rests on the provable fact.

### Vendor B — the buried subprocessor (Phase 8.4 target)

`AIV-03-f1456963` · critical · due 2026-08-20

```json
"subprocessor": {
  "value": "Perplexity AI, Inc.",
  "provenance": "parsed_artifact:subprocessors",
  "evidence": "Perplexity AI, Inc. | Retrieval and answer generation for Assist Answers (beta) | US | Pending"
}
```

The row was planted at position 6 of 9, between `Anthropic PBC` and `Intercom, Inc.`, with no changelog
mention. It was recovered verbatim. The changelog diff for the same vendor correctly triaged to
`ai_relevant: false` — the tool did not launder a cosmetic diff into a finding.

### Vendor C — negative control

Two sources changed (release notes, trust-center marketing line). Both triaged `ai_relevant: false`,
`change_type: none`. Findings identical to baseline: same five IDs, no new IDs, no severity change. The
pre-existing bias-testing and error-rate items persisted and aged, which ground truth explicitly calls
correct behaviour rather than a false positive.

---

## Defects found during validation

### D1 — False critical on the baseline (fixed)

**Severity: this one invalidated the experiment.** The first wired-up run raised a critical AIV-07 against
Aegis *at baseline*. There was a single probe fixture, `aegis_tenant.json`, holding post-change March
tenant state, and it was applied to every snapshot version. The v1 "baseline" was therefore being
evaluated against v2 tenant reality.

A baseline that already contains the finding you intend to detect proves nothing — run 2 would have
"caught" a critical that was present the whole time. Fixed by splitting the fixture into
`aegis_tenant_v1.json` (agent mode off, read-only scopes, per-action approval on) and
`aegis_tenant_v2.json`, with `{version}` substitution in the register's `probe.fixture` path.

**Generalised rule:** any tenant-state fixture must be version-matched to the artifact snapshot set, or
the baseline is not a baseline.

### D2 — Model proposals could never produce a finding (fixed by redesign)

The original design routed the model's `proposed_surface_update` toward the register. But proposals are
quarantined in `pending_review/` by design — a human accepts them. So `evaluate_vendor` never saw them,
and **both planted criticals silently failed to fire** while every individual component reported success.
The triage was correct, the controls were correct, and the run was clean and wrong.

Fixed by introducing a third state tier rather than by auto-applying proposals:

| Tier | Source | Authority | Can drive a finding? |
| --- | --- | --- | --- |
| `register` | human-authored YAML | authoritative | yes |
| `observed` | parsed subprocessor tables + tenant JSON | deterministic, quotable | yes — overlays register, carries provenance |
| `proposed` | model prose inference | advisory | **no** — quarantined in `pending_review/` |

The rule: a tier may drive a finding only if its claims are quotable back to a specific artifact line or
API field. Model prose is not, so it never does. Auto-applying `proposed_surface_update` was rejected —
it would have let the model author findings, breaking the core design rule.

### D3 — `affected_fields` dropped from the JSON report (fixed)

Checks 7 and 14 failed on first measurement: `affected_fields` was `None` for every triage in
`out/latest.json`. The triage layer had it right all along (`pending_review/` showed
`[autonomy, human_in_loop, status]`); the CLI's report serializer simply never copied the key. A
reporting bug, not a detection bug — but it would have made the report unusable as evidence, since a
reader could not see which register fields a change bore on. Fixed in `cli.py`.

### D4 — Unreachable `fails_when` clause on AIV-01 (fixed)

A unit test asserted an undisclosed model provider should fail AIV-01. It didn't — it produced a gap.
Checking ground truth (`expected_findings.md` L51: *"Must remain a gap, not a failure: model provider
undisclosed"*) showed **the test was wrong and the tool was right**, so the test was corrected rather
than the behaviour.

But it exposed dead config: AIV-01 carried `fails_when: {field: model_provider, equals: undisclosed}`,
and `undisclosed` is an unknown token, and the unknown check runs first. That clause could never fire
under any input. Removed, with a comment recording why non-disclosure is deliberately a gap. Dead config
in a control file is a latent hazard — the next person to read it would reasonably believe non-disclosure
was enforced as a failure.

---

## How design rule 2 is enforced structurally

"No LLM output may create, delete, or re-severity a finding" is not a prompt instruction — prompts are
not a control surface. It holds because of where the model sits in the pipeline:

- **Severity** is read from `controls.yaml` only. There is no code path from model output to a severity
  value. (`test_severity_comes_from_config_only`)
- **Due dates** derive from severity via a table in `config.py`. (`test_due_dates_derive_from_severity_table`)
- **POA&M rows** are built by `build_poam`, which is pure and deterministic. (`test_poam_is_fully_deterministic`)
- **Change types** are validated against a closed 8-value enum; an invented value is rejected as malformed
  and retried. (`test_schema_rejects_invented_change_type`)
- **Narratives** are checked for severity words that contradict the record's actual severity; a model that
  editorialises gets its draft discarded for a deterministic fallback. (`test_narrative_falls_back_when_model_editorialises`)
- **A failed model call fails closed** — the source is flagged for manual review, never passed as clean.

The model's only outputs that survive into the report are prose and a quarantined proposal.

---

## Test suite

46 tests, all passing (`python3 tests/test_vra.py`).

| Group | Tests | What it protects |
| --- | --- | --- |
| `TestVolatileStripping` | 7 | Timestamps, GUIDs, build numbers, promo banners stripped; substantive change survives |
| `TestSubprocessorParsing` | 6 | Buried row parsed; "Pending" ≠ covered; header row not mistaken for a vendor |
| `TestControlEvaluation` | 13 | Unknown → gap; ANDed conditions; `applies_when` scoping; stable IDs; severity from config |
| `TestTriageGuardrails` | 7 | Closed enum; confidence range; JSON extraction from fenced/prose output |
| `TestFindingLifecycle` | 6 | `accepted_risk` survives re-runs; resolved findings close; overdue escalates |
| `TestAnalystGuardrails` | 3 | POA&M determinism; narrative guardrail |
| `TestGroundTruthScenario` | 4 | Registers well-formed; baseline has no critical; Vendor C quiet |

Two tests are deliberately negative controls at the unit level:
`test_acting_agent_with_human_review_does_not_fire_aiv07` (autonomy alone is not the failure — the
conditions are ANDed) and `test_covered_ai_provider_does_not_fire` (Anthropic under an executed BAA is
fine; the control targets *uncovered* providers, not AI providers generally).

---

## Limitations of this validation

### 1. The scored runs used the offline backend, not a real model

No Ollama runtime exists in this environment (`which ollama` → nothing), so all runs above used the
deterministic `offline-heuristic` backend. **This is the single biggest caveat here.** The offline backend
recognises the planted changes through keyword heuristics tuned against this sandbox. It tells you the
pipeline, controls, state machine, and guardrails work end to end. It does **not** tell you a 7B instruct
model would triage these diffs correctly, and it certainly does not tell you how one behaves on real
vendor prose that nobody wrote to be caught.

The two critical findings do not depend on the model — both come from the deterministic `observed` tier
(parsed subprocessor table, tenant probe), which is why they fire identically with any backend. But
triage quality on messy real-world text is **unmeasured**. Re-running with `--model` against a live Ollama
instance is the first thing to do before trusting this on real vendors.

### 2. The sandbox was authored by the same person as the detector

Three vendors, one planted change each, written by me. Real changelogs are longer, worse structured, and
not written to be caught. The negative control is one vendor across two sources — it demonstrates the
tool *can* stay quiet, not that it stays quiet at scale. A meaningful false-positive rate needs dozens of
real vendors over months.

### 3. Structural blind spots not exercised

- **Non-pipe-delimited subprocessor tables.** `parse_subprocessor_table` expects pipe-delimited rows after
  normalisation. A vendor publishing subprocessors as prose, nested HTML, or a PDF is not parsed — and AIV-03
  detection depends entirely on that parse.
- **Diff-blind to unpublished change.** If a vendor swaps model providers without touching any watched
  artifact, nothing fires. The probe partially covers this for the identity provider only.
- **Probe coverage is one vendor.** Aegis alone has a management API modelled. For the other two, the
  register is the only claim about tenant state, and it is trusted.
- **Fixture-mode probe.** The probe reads a JSON fixture, not a live API. Auth, pagination, rate limits,
  and schema drift are all unexercised.
- **No adversarial vendor text.** Nothing tests a vendor that describes an agent in deliberately soft
  language ("Copilot streamlines routine access workflows") with no autonomy keyword.

### 4. What a clean sheet does and does not mean

22/22 means the tool does what the ground truth said it should on the scenario the ground truth
describes. Given that four real defects surfaced *during* this validation — one of which produced a false
critical on the baseline, and one of which made both planted criticals silently fail — the honest reading
is that the checks were load-bearing, not decorative. The value was in D1–D4, not in the final row of
green ticks.
