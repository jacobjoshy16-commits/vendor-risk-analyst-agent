# Local Vendor AI Risk Analyst

A local GRC analyst for the gap between annual vendor reviews. It tracks each vendor's **AI surface** —
agents, copilots, embedded model features — detects when that surface changes, re-assesses the change
against healthcare compliance controls, and drafts the response.

Runs entirely on your workstation. No vendor risk data leaves the machine by default.

> **Status: draft.** The pipeline works end to end and is validated against a planted-change sandbox.
> The scored runs used a deterministic offline backend rather than a live model — see
> [Limitations](#limitations).

---

## The problem

Vendor reviews happen annually. Vendor AI features ship weekly.

In between, an identity provider can promote its copilot from *suggesting* access changes to *making*
them — writing to your directory, revoking sessions, no per-action approval, enabled by default on your
SKU. A collaboration tool can add a new model provider to its subprocessor list as row six of nine, BAA
status "Pending", with no changelog entry. Both are material. Neither generates a notification.

The next scheduled look is eleven months away.

This tool closes that window: it watches the public artifacts vendors *do* update, notices the changes
that touch AI, and produces the finding, the vendor email, and the POA&M row.

## What it does

```
watch → normalize → diff → triage → observe → evaluate → draft → persist → report
```

1. **Watch** — fetch each vendor's changelog, trust center, subprocessor list, and DPA.
2. **Normalize** — HTML to text, then strip volatile content (page timestamps, session GUIDs, build
   numbers, render times, rotating promo banners) so hashes are stable. Without this, everything looks
   changed every run and the tool is noise.
3. **Diff** — hash, compare to the last snapshot, emit unified diffs. Unchanged sources cost nothing.
4. **Triage** — a local instruct model reads each diff against the vendor's current AI surface and
   returns forced JSON: is this AI-relevant, what kind of change, which register fields it bears on, a
   proposed update, and a verbatim evidence excerpt.
5. **Observe** — deterministically parse subprocessor tables and in-tenant API responses into an
   *observed* state that overlays the register, carrying provenance for every field.
6. **Evaluate** — run 15 controls against the merged surface. Deterministic. Config-driven.
7. **Draft** — for each finding and gap: a narrative, a vendor outreach email, and a POA&M row.
8. **Persist** — reconcile against prior findings, age them, escalate overdue ones, close resolved ones.
9. **Report** — one Markdown report plus machine-readable JSON; nonzero exit on any open critical.

## Design rules

These are the load-bearing constraints. Everything else is implementation detail.

**1. The model never invents a finding.** Control mapping and severity are deterministic, from
`controls.yaml` and code. There is no code path from model output to a severity value, a due date, or the
existence of a finding. A model that editorialises about severity in a narrative gets its draft discarded
for a deterministic fallback.

**2. The model's only job is reading unstructured vendor text and drafting language.** It decides whether
prose is worth a human's attention and writes the email. It does not decide what is true.

**3. State is the product.** A tool that re-derives everything each run is a linter. The register, the
finding lifecycle, and the snapshot history are the thing of value — they're what let you say "this
changed on this date, here's the line, here's what we did about it."

**4. Local by default.** Model inference is a local Ollama instance. `--offline` disables network access
entirely.

### Three tiers of state

The tier a claim lives in determines whether it can drive a finding:

| Tier | Source | Can drive a finding? |
| --- | --- | --- |
| `register` | Human-authored YAML in `vendors/` | **Yes** — authoritative |
| `observed` | Parsed subprocessor tables, in-tenant API responses | **Yes** — overlays the register, carries provenance |
| `proposed` | Model inference from prose | **No** — quarantined in `pending_review/` for human review |

The rule: **a tier may drive a finding only if its claims are quotable back to a specific artifact line
or API field.** Model prose is not, so it never does. This is why both criticals in the demo cite either
a parsed table row or a tenant API scope list — you can put either in front of a vendor.

This design was arrived at the hard way; see [D2 in VALIDATION.md](VALIDATION.md#d2--model-proposals-could-never-produce-a-finding-fixed-by-redesign).

## Setup

Python 3.10+.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pyyaml requests
```

*(Not using a venv on a PEP 668 system? `pip install --break-system-packages pyyaml requests`.)*

For model-backed triage, install [Ollama](https://ollama.com) and pull a model:

```bash
ollama pull llama3.1:8b
```

Ollama is optional. Without it, run with `--offline` — the tool falls back to a deterministic heuristic
backend and the report states that no language model was used. If Ollama is configured but unreachable,
the run falls back automatically with a warning rather than failing.

## Usage

```bash
python3 vra.py --offline --snapshot v1     # baseline
python3 vra.py --offline --snapshot v2     # change run -> exit 1
python3 tests/test_vra.py                  # 46 tests
```

| Flag | Effect |
| --- | --- |
| `--snapshot VERSION` | Sandbox snapshot set to read (substitutes `{version}` in watch paths). Default `v1` |
| `--vendor SLUG` | Limit the run to one vendor. Repeatable |
| `--out DIR` | Report output directory. Default `out/` |
| `--model TAG` | Ollama model tag. Default `$VRA_MODEL` or `llama3.1:8b` |
| `--offline` | No network. Deterministic heuristic backend instead of Ollama |
| `--dry-run` | Assess and print, persist nothing — no snapshots, findings, or report files |
| `--no-probe` | Skip all in-tenant probes |
| `--no-fail` | Always exit 0, even with open criticals |

**Exit codes:** `0` clean · `1` at least one open critical finding · `2` run error.

`--dry-run` is the safe way to preview against a new snapshot: it will not write a snapshot, will not
mutate finding state, and will not close anything. Note that a `--vendor`-filtered run only reconciles
that vendor's findings — other vendors' findings are left alone rather than closed as resolved.

### Outputs

| Path | Contents |
| --- | --- |
| `out/latest.md`, `out/vendor-ai-risk-{stamp}.md` | The report |
| `out/latest.json` | Same run, machine-readable |
| `data/findings.json` | Finding lifecycle store — **the durable state** |
| `data/snapshots/{vendor}/{stamp}/` | Normalized artifact snapshots + hashes |
| `data/llm_audit.jsonl` | Every prompt and response, for audit |
| `pending_review/{vendor}-{stamp}.json` | Model-proposed register updates awaiting human acceptance |

## Configuration

### `controls.yaml` — the control set

15 controls, editable without touching code. Each has a question, framework citations (HIPAA Security
Rule, NIST AI RMF, HICP), a severity, `fails_when` / `gap_when` conditions, remediation, and a
compensating control.

| ID | Severity | Control |
| --- | --- | --- |
| AIV-01 | high | Model provider disclosed per AI feature |
| AIV-02 | medium | AI-specific addendum executed |
| AIV-03 | **critical** | Every model provider named as subprocessor and BAA-covered |
| AIV-04 | high | Customer data not used for training/fine-tuning |
| AIV-05 | medium | Retention period for prompts and outputs documented |
| AIV-06 | high | Data reach limited to minimum necessary |
| AIV-07 | **critical** | No autonomous action on clinical/identity records without human review |
| AIV-08 | high | AI actions and outputs written to an auditable log |
| AIV-09 | medium | Notification of material model/version changes |
| AIV-10 | medium | Error/accuracy/hallucination rates disclosed |
| AIV-11 | high | Prompt injection and adversarial input testing |
| AIV-12 | high | Inference within contracted residency boundary |
| AIV-13 | high | Bias/performance testing across clinical population |
| AIV-14 | medium | AI-specific incident response process |
| AIV-15 | medium | Feature disableable at tenant level |

Conditions are ANDed — AIV-07 requires *both* `autonomy: acts` and `human_in_loop: false`. An agent that
acts under human review is not a finding. AIV-13 carries an `applies_when` clause scoping it to features
touching clinical data.

Severity drives due dates, in `config.py`: critical 7 days, high 30, medium 60, low 90; information gaps
get 21 days.

### `vendors/*.yaml` — the register

One file per vendor:

```yaml
vendor: Aegis Identity Cloud
slug: aegis-identity-cloud
tier: critical
contract:
  baa_on_file: true
  ai_addendum_signed: false
  baa_covered_subprocessors: [...]
ai_surface:
  - feature: Access Copilot
    status: enabled            # available | enabled | disabled
    autonomy: suggests         # suggests | acts
    data_reach: [identity_attributes, group_membership, access_logs]
    model_provider: undisclosed
    training_on_customer_data: unknown
    human_in_loop: true
    retention_days: unknown
    # ... plus output_logged, change_notification, error_rate_disclosed,
    #     prompt_injection_tested, data_residency, bias_tested_clinical,
    #     ai_incident_process
watch:
  changelog: sandbox/vendors/aegis-identity-cloud/snapshots/{version}/changelog.html
  # ... trust_center, subprocessors, dpa
probe:                          # optional, per-vendor
  type: okta_management_api
  enabled: true
  mode: fixture
state:
  last_assessed: ...
  snapshot_hashes: {...}
```

### `unknown` is a question, not a failure

This matters enough to state plainly: **`unknown` fields are information gaps — questions for the vendor —
not control failures.**

If a vendor hasn't told us their retention period, we don't know that it's wrong. We know we don't know.
Those are tracked separately from findings, get their own 21-day response clock, and each one produces a
drafted question in the vendor outreach email. Conflating "unanswered" with "non-compliant" produces
reports nobody trusts, because the first vendor who reads one will correctly point out that half the
"failures" are things they were never asked.

Unknown tokens: `unknown`, `undisclosed`, `tbd`, `not_provided`, null, empty.

## Sandbox

`sandbox/vendors/` holds three fictional vendors with mirrored public artifacts (changelog, trust center,
subprocessor list, DPA) in two snapshot sets, `v1` and `v2`:

| Vendor | Type | Planted change in v2 |
| --- | --- | --- |
| Aegis Identity Cloud | Identity provider | **Critical.** Agent Mode GA — copilot creates/modifies/deactivates accounts and revokes sessions without per-action approval, default-on for the Advanced SKU |
| Loop Workspace | Collaboration | **Critical.** `Perplexity AI, Inc.` added as row 6 of 9 in the subprocessor list, BAA "Pending", no changelog mention |
| Meridian RevCycle | Revenue cycle | **Negative control.** Release notes, a marketing line, wording churn. Must produce nothing |

`sandbox/expected_findings.md` is ground truth, written in Phase 0 **before any detection code existed**
and never edited since. Writing it afterward would be validation theater — you'd be describing what the
tool does, not what it should do.

Vendor C exists because a tool that flags everything is worthless. A detector is only credible if it can
be shown staying quiet on a real diff.

## Validation

Full record with reproduction steps in **[VALIDATION.md](VALIDATION.md)**.

Baseline run: 10 findings, **0 critical**, 12 gaps. Change run: **2 new criticals**, exit 1, Vendor C
unchanged. All 22 ground-truth assertions met; 46 unit tests pass.

**The clean sheet is not the story.** Validation surfaced four real defects:

- **A false critical on the baseline.** One probe fixture held post-change tenant state and was applied
  to every snapshot version, so the "baseline" already contained the finding run 2 was meant to detect.
  A baseline that contains the answer proves nothing.
- **Both planted criticals silently failing to fire** while every individual component reported success —
  model proposals are quarantined by design, so nothing that depended on them could ever reach the
  evaluator. Fixed by the three-tier state model, not by auto-applying proposals.
- **`affected_fields` dropped from the JSON report**, making it impossible to see which register fields a
  change bore on.
- **An unreachable `fails_when` clause** on AIV-01 that could never fire under any input — found by a unit
  test that was itself wrong, and corrected against ground truth rather than by changing behaviour.

Known misses and untested paths are listed below and in VALIDATION.md. Nothing in either document is a
clean sheet by omission.

## Limitations

**The scored runs used the deterministic offline backend, not a real model.** No Ollama runtime was
available in the build environment. The offline backend recognises the planted changes via keyword
heuristics tuned to this sandbox. That validates the pipeline, controls, state machine, and guardrails —
it does **not** validate that a 7B instruct model triages real vendor prose correctly. Both criticals come
from the deterministic `observed` tier and fire identically under any backend, but triage quality on messy
real-world text is unmeasured. Re-run with `--model` against live Ollama before trusting this on real
vendors.

**Structural blind spots:**

- **Subprocessor parsing expects pipe-delimited tables** after normalisation. A vendor publishing
  subprocessors as prose, deeply nested HTML, or a PDF is not parsed — and AIV-03 depends on that parse.
- **Diff-blind to unpublished change.** A vendor that swaps model providers without touching a watched
  artifact triggers nothing. The in-tenant probe partially covers this, for one vendor.
- **Probe coverage is one vendor.** Only the identity provider has a management API modelled, in fixture
  mode. Auth, pagination, rate limits, and schema drift are unexercised.
- **The register is trusted.** Except where the probe or a parsed artifact overrides it, the tool believes
  what a human wrote. A stale register produces confident, wrong output.
- **No adversarial text testing.** Nothing exercises a vendor describing an agent in deliberately soft
  language with no autonomy keyword.
- **The sandbox was authored by the same person as the detector.** Three vendors, one planted change each.
  A meaningful false-positive rate needs dozens of real vendors over months.

**`data/findings.json` is gitignored** in this demo repo. In a real deployment, commit it or back it with
a database — it holds every `accepted_risk` decision a human has made, and losing it loses all of them.

## Roadmap (not in v1)

Browser extension for capturing artifacts behind auth · multi-tenant / multi-analyst state · scheduled
unattended runs · cloud sync of findings · model distillation for faster local triage · custom
quantization.

## Repository layout

```
vra.py                  entry point
controls.yaml           15 controls — edit without touching code
vendors/*.yaml          per-vendor AI surface register
src/vra/
  cli.py                orchestration, console summary, exit codes
  watch.py              fetch, snapshot, diff
  normalize.py          HTML->text, volatile stripping
  llm.py                pluggable backends (Ollama / offline), JSON extraction, audit log
  triage.py             AI-relevance triage, forced JSON schema
  observe.py            deterministic parsing -> observed state overlay
  evaluate.py           control evaluation, findings vs gaps
  probe.py              in-tenant management API probe
  analyst.py            narratives, outreach drafts, POA&M rows
  register.py           register I/O, finding store, lifecycle
  report.py             Markdown + JSON report
sandbox/                three vendors, v1/v2 snapshots, ground truth
tests/test_vra.py       46 tests
VALIDATION.md           validation record, including every defect found
DEMO.md                 demo recording notes
```
