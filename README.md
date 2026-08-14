# Local Vendor AI Risk Analyst

A workstation GRC analyst for the eleven months between annual vendor reviews.

It watches each vendor’s **AI surface** (agents, copilots, embedded models) and the
**non-human identities** those features run as (service accounts, OAuth apps, agent
principals). When something material changes, it re-scores the vendor against
healthcare controls and drafts the finding, the vendor email, and the POA&M row.

Runs on your machine. Vendor risk data does not leave the workstation by default.

---

## What you are getting

Four things, not a chatbot that “looks at vendors.”

| You get | What that actually is |
| --- | --- |
| **A register** | One YAML file per vendor: contract facts, AI features, NHIs, watch URLs. You own it. The tool never rewrites the human-authored parts on its own. |
| **A watcher** | Re-fetches each vendor’s changelog, trust center, subprocessor list, and DPA. Hashes are stable (timestamps and promo banners are stripped). Unchanged pages cost nothing. |
| **A scorer** | 15 feature controls (`AIV-*`) and 8 identity controls (`NHI-*`). Severity, due dates, and whether something is a finding come from YAML + code. **The language model cannot create, delete, or re-severity a finding.** |
| **A draft pack** | For every finding and every information gap: a narrative, a vendor outreach email, and a POA&M row. Ready to send or file. |

Plus a **daemon** that keeps doing that while the PC is on, and a **local console**
(no CDN, works offline) to onboard vendors, start/stop the monitor, and see the
NHI inventory.

### What a cycle produces

```
out/latest.md            human-readable assessment
out/latest.json          same run, machine-readable
data/findings.json       finding lifecycle (the durable state)
data/nhis.json           every identity seen across vendors
pending_review/          model proposals — quarantined, never auto-applied
```

Exit codes: `0` clean · `1` open critical · `2` run error.

### What it will not do

- It will not invent a finding from model prose. Claims that drive a finding must
  quote a table row or an API field.
- It will not treat “we don’t know” as “they failed.” Unknown fields are
  **information gaps** (a 21-day question), not control failures.
- It will not read a SafeBase / Whistic / Vanta page behind an NDA. That is
  recorded as `blocked` with a drafted access-request email — not a silent pass.
- It will not see a change the vendor never published. If they swap model
  providers and touch none of the watched pages (and there is no tenant probe),
  nothing fires.
- It is not a hosted SaaS. Leave `python3 vra.py monitor` running, or enable the
  login unit `monitor install` writes. Closing the laptop stops it.

---

## How a real deployment looks

```
1. Bootstrap the vendor     python3 vra.py bootstrap Slack --offline
2. Review the proposal      pending_review/{slug}-bootstrap-*.json
3. Accept by hand           edit vendors/{slug}.yaml  (the model never writes it)
4. Leave it running         python3 vra.py monitor --offline --webui --interval 15m
5. Read the pack            out/latest.md
```

Day one, the tool either **parses the subprocessor list** (AIV-03 has coverage)
or it **says it cannot** (`parse_failed` / `blocked` / `missing`) and drafts the
outreach. A quiet pass on a list nobody could read is how a vendor adds OpenAI
as row six and nobody notices.

Slack, Atlassian, Zoom, Notion, and Datadog need no URL — their public
subprocessor pages are in a catalog. Anyone else: name + trust-center URL.

The monitor is **the same assess you run by hand**, on a timer. It re-reads
`vendors/` every cycle, so a vendor you onboard at 2pm is in the 2:15 run. A
critical finding is recorded, not a crashed daemon. Two copies cannot run
(`data/monitor.lock`). Identical fetches do not write another snapshot folder.

```bash
python3 vra.py monitor --offline --webui --interval 15m
python3 vra.py monitor status          # pid, last cycle, next cycle
python3 vra.py monitor stop
python3 vra.py nhis                    # every identity in the portfolio
python3 vra.py monitor install --offline --webui   # writes login units; does not enable them
```

The console (`--webui`, port 8765) is onboard + Start/Stop + NHI table. It talks
only to the local disk.

---

## Two control families

**AIV-*** asks “what can this *feature* do?”  
**NHI-*** asks “what *identity* is it doing it as?”

| ID | Sev | Question |
| --- | --- | --- |
| AIV-01 | high | Model provider disclosed per AI feature |
| AIV-02 | medium | AI-specific addendum executed |
| AIV-03 | **critical** | Every model provider named as subprocessor and BAA-covered |
| AIV-04 | high | Customer data not used for training / fine-tuning |
| AIV-05 | medium | Retention of prompts and outputs documented and bounded |
| AIV-06 | high | Data reach limited to minimum necessary |
| AIV-07 | **critical** | No autonomous action on clinical / identity records without human review |
| AIV-08 | high | AI actions written to an exportable audit log |
| AIV-09 | medium | Advance notice of material model changes |
| AIV-10 | medium | Error / accuracy / hallucination rates disclosed |
| AIV-11 | high | Prompt-injection / adversarial testing shared |
| AIV-12 | high | Inference inside the contracted residency boundary |
| AIV-13 | high | Bias / performance testing on clinical populations *(only if the feature touches clinical data)* |
| AIV-14 | medium | AI-specific incident response process |
| AIV-15 | medium | Feature disableable at tenant level |
| NHI-01 | **critical** | Agent principal holds write scopes and acts without human review |
| NHI-02 | high | Every NHI has a named human owner |
| NHI-03 | high | Credentials rotated at least annually |
| NHI-04 | high | Every identity seen in a tenant is in the inventory (no orphans) |
| NHI-05 | medium | NHI actions written to an exportable audit log |
| NHI-06 | high | Cross-vendor NHIs declared on the home vendor |
| NHI-07 | medium | Disabled identities retain no write scopes |
| NHI-08 | high | A suggests-only identity does not hold standing write scopes |

Edit `controls.yaml` / `nhi_controls.yaml` without touching code. Severity
drives due dates: critical 7 days, high 30, medium 60, low 90, gaps 21.

AIV-07 is AND: `autonomy: acts` **and** `human_in_loop: false`. An agent that
acts under human review is not a finding.

Cross-vendor example: Loop’s provisioning client living in Aegis’s tenant is
observed on Aegis, declared on Loop with `resides_in`, and **NHI-06** fires
only if that declaration is missing.

---

## Design rules (why a customer can trust the score)

**1. The model never invents a finding.** There is no code path from model
output to a severity, a due date, or the existence of a finding. A draft that
editorialises about severity is discarded for a template.

**2. The model reads unstructured vendor text and drafts language.** It does
not decide what is true.

**3. State is the product.** The register, the finding lifecycle, and the
snapshot history are what let you say “this changed on this date, here is the
line, here is what we did.”

**4. Local by default.** Inference is a local Ollama instance. `--offline`
uses a deterministic heuristic and the report says so.

A claim may drive a finding only if it is quotable to an artifact line or API
field:

| Tier | Source | Drives a finding? |
| --- | --- | --- |
| `register` | Human YAML in `vendors/` | **Yes** |
| `observed` | Parsed table / tenant API | **Yes** — overlays the register, with provenance |
| `proposed` | Model inference | **No** — `pending_review/` only |

---

## Setup

Python 3.10+.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pyyaml requests pypdf
```

Model-backed triage (optional):

```bash
ollama pull qwen2.5:7b-instruct
```

Default model: `qwen2.5:7b-instruct` (`--model` or `$VRA_MODEL`). Swapping the
model changes triage and draft quality only. Without Ollama, `--offline` is
the whole backend and the report states that no language model was used.

### One-shot assess

```bash
python3 vra.py --offline --snapshot v1     # sandbox baseline
python3 vra.py --offline --snapshot v2     # planted change → exit 1
python3 vra.py --vendor acme-corp          # one live vendor
```

| Flag | Effect |
| --- | --- |
| `--snapshot VERSION` | Sandbox snapshot set (`{version}` in watch paths). Default `v1` |
| `--vendor SLUG` | Limit to one vendor. Repeatable |
| `--out DIR` | Report directory. Default `out/` |
| `--model TAG` | Ollama model |
| `--offline` | No network; heuristic backend |
| `--dry-run` | Print only — no snapshots, findings, or reports written |
| `--no-probe` | Skip in-tenant probes |
| `--no-fail` | Exit 0 even with open criticals |

A `--vendor`-filtered run only reconciles that vendor’s findings. Everyone
else is left alone.

### Onboard / bootstrap

```bash
python3 vra.py onboard "Acme Corp" --tier critical --trust-center https://acme.safebase.io --offline
python3 vra.py bootstrap Slack --offline
python3 vra.py bootstrap "Acme Corp" --trust-center https://acme.example/trust --offline
```

Order of operations: fetch → detect SafeBase/Whistic/Vanta/PDF/HTML (including
NDA gates) → discover changelog / subprocessors / DPA links → **parse
subprocessors on day one** → scaffold a conservative register → cache artifacts
→ draft outreach if gated. `--bootstrap` then reads the artifacts **in full**
(not a diff) and writes a proposed `ai_surface` to `pending_review/`. You accept
by editing the YAML.

Flags: `--tier` `--category` `--description` `--trust-center` `--changelog`
`--subprocessors` `--dpa` `--offline` `--dry-run` `--assess` `--bootstrap`.

### Console

```bash
python3 vra.py webui --host 0.0.0.0 --port 8765
# or, with the daemon:
python3 vra.py monitor --offline --webui --host 0.0.0.0 --port 8765
```

### Outputs

| Path | Contents |
| --- | --- |
| `out/latest.md`, `out/vendor-ai-risk-{stamp}.md` | The report |
| `out/latest.json` | Same run, machine-readable |
| `data/findings.json` | Finding lifecycle — **back this up** |
| `data/nhis.json` | Portfolio NHI inventory |
| `data/monitor.json` / `data/monitor.lock` / `data/monitor.log` | Daemon heartbeat, lock, cycle log |
| `data/snapshots/{vendor}/{stamp}/` | Normalized artifacts + hashes |
| `data/llm_audit.jsonl` | Every prompt and response |
| `pending_review/` | Model proposals and gated-list outreach drafts |
| `artifacts/vendors/{slug}/` | Onboarding cache |

`data/findings.json` is gitignored in this demo repo. In production, commit it
or put it in a database. It holds every `accepted_risk` decision. Losing it
loses all of them.

---

## The register

One file per vendor in `vendors/`:

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
    data_reach: [identity_attributes, auth_events]
    model_provider: undisclosed
    human_in_loop: true
    # plus training, retention, logging, residency, …
nhis:                          # optional; probes also discover these
  - id: access-copilot
    kind: agent_principal
    principal: copilot-assist
    owner: Identity Operations
watch:
  changelog: https://…
  trust_center: https://…
  subprocessors: https://…
  dpa: https://…
probe:                         # optional
  enabled: true
  mode: fixture                # or live, token from the environment only
```

**`unknown` is a question, not a failure.** If they have not told you the
retention period, you do not know it is wrong — you know you do not know.
Those become drafted questions, not “failures” a vendor will correctly reject.

---

## Sandbox (what “it works” means here)

Three fictional vendors, two snapshot sets:

| Vendor | Planted change in v2 |
| --- | --- |
| Aegis Identity Cloud | **Critical.** Agent Mode GA — writes directory and sessions with no per-action approval, default-on |
| Loop Workspace | **Critical.** Perplexity added as row 6 of 9, BAA “Pending”, no changelog mention |
| Meridian RevCycle | **Negative control.** Release notes and wording churn. Must produce nothing |

Ground truth was written **before** the detector (`sandbox/expected_findings.md`)
and has not been edited since. Vendor C exists because a tool that flags
everything is ignored by week three.

`sandbox/real_world/` holds structurally faithful copies of Slack, Atlassian,
Zoom, Notion, and Datadog public subprocessor pages. AIV-03 is only as good as
that parse. A JS-rendered shell with no table is `parse_failed`, not a pass.

```bash
python3 -m unittest tests.test_vra tests.test_monitor_nhi tests.test_real_world_vendors
```

Full record, including every defect found in validation: **[VALIDATION.md](VALIDATION.md)**.

---

## Limitations (read this before you trust it on live vendors)

**The scored sandbox runs used the offline heuristic, not a live 7B model.**
That validates the pipeline, controls, state machine, and guardrails. It does
**not** validate triage quality on messy real vendor prose. Re-run with
`--model` against Ollama before relying on it.

- **Gates stop the parse, loudly.** NDA / login walls are `blocked` + outreach.
  The tool cannot read what it is not granted.
- **Parse is structural.** HTML tables and PDF text work. Scanned PDFs, image
  tables, and buried spreadsheet attachments still produce a gap.
- **Diff-blind to unpublished change.** No watched page and no probe → nothing.
- **Probes are fixture-mode in the sandbox.** Live API auth, pagination, and
  schema drift are unexercised.
- **The register is trusted** except where a probe or parsed artifact overrides
  it. A stale register produces confident, wrong output.
- **The sandbox was authored by the same person as the detector.** A real
  false-positive rate needs dozens of live vendors over months.

---

## Status

Draft. End-to-end pipeline, sandbox-validated, with a monitor, NHI inventory,
and onboarding that tries the subprocessor parse on day one.

Not in this version: browser capture of NDA-gated portals, multi-analyst
tenancy, live (non-fixture) probes beyond the modelled IdP shape, cloud sync,
OCR for scanned PDFs.

---

## Repository

```
vra.py                  entry point
controls.yaml           15 AIV-* controls — edit without code
nhi_controls.yaml       8 NHI-* controls — identities, not features
vendors/*.yaml          per-vendor register
src/vra/
  cli.py                one assess pass
  monitor.py            daemon: lock, heartbeat, cycle, autostart units
  nhi.py                identity inventory + NHI-* evaluation
  onboard.py            onboard / bootstrap
  webui.py              local console
  watch.py              fetch, snapshot, diff
  observe.py            parse subprocessors → observed overlay
  evaluate.py           deterministic scoring
  probe.py              tenant API / fixture probe
  …                     triage, analyst drafts, report, register I/O
sandbox/                planted-change vendors + real-world page fixtures
tests/                  pipeline, monitor, NHI, real-world parser
VALIDATION.md           validation record, including defects found
```
