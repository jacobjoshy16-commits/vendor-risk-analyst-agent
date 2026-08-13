# Local Vendor AI Risk Analyst (`vra`)

A local GRC tool that monitors vendor AI surfaces (agents, copilots, embedded models), detects changes across public disclosures and tenant APIs, evaluates them against healthcare compliance controls (HIPAA, NIST AI RMF, HICP), and drafts remediation workflows.

Runs 100% locally with zero vendor risk data leaving your workstation.

---

## Key Features

- **Continuous Surface Monitoring**: Automated ingestion and unified diffing of vendor changelogs, trust centers, subprocessor tables, and DPAs.
- **Volatile Content Stripping**: Normalizes HTML and strips timestamps, session tokens, build IDs, and layout churn to prevent false-positive diffs.
- **3-Tier State Architecture**: Strict separation between authoritative register data, observed/parsed artifacts, and model-proposed drafts.
- **15 Configurable Controls**: Out-of-the-box controls in `controls.yaml` evaluating autonomy, data residency, retention, subprocessor BAA coverage, and model training.
- **Findings vs. Information Gaps**: Distinguishes verified control failures (remediation + POA&M) from missing vendor disclosures (gap outreach + 21-day timer).
- **Automated Onboarding & Web UI**: CLI (`vra onboard`) and local web console for portal discovery (SafeBase, Whistic, Vanta), gated NDA handling, and register scaffolding.
- **Privacy-Preserving & Air-Gapped**: Supports local Ollama models (`qwen2.5:7b-instruct`) or completely offline execution with deterministic heuristics (`--offline`).

---

## Architecture & Data Flow

```
watch ──> normalize ──> diff ──> triage ──> observe ──> evaluate ──> draft ──> persist ──> report
```

1. **Watch & Ingest**: Fetches public artifacts (HTML, PDF, portals) and polls tenant management APIs.
2. **Normalize & Diff**: Strips volatile page elements and compares normalized text to snapshot history.
3. **Triage**: Classifies diffs for AI relevance and maps changes to register fields using local LLM or heuristics.
4. **Observe & Overlay**: Deterministically parses subprocessor tables and API responses into verified state overlays.
5. **Evaluate**: Evaluates 15 compliance controls from `controls.yaml` against the merged surface.
6. **Draft**: Generates analyst narratives, vendor outreach emails, and POA&M tracking rows.
7. **Persist**: Reconciles findings, escalates overdue items, and records full audit logs in `data/`.
8. **Report**: Outputs Markdown and JSON executive reports; exits with code `1` on open criticals.

### State Tiers

| Tier | Source | Can Drive Findings? | Description |
| :--- | :--- | :---: | :--- |
| **`register`** | Human-authored YAML in `vendors/` | **Yes** | Authoritative contract and surface definitions. |
| **`observed`** | Parsed tables & tenant API responses | **Yes** | Verified, quotable facts with full provenance. |
| **`proposed`** | Local LLM inference from prose diffs | **No** | Quarantined in `pending_review/` until accepted by an analyst. |

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- (Optional) [Ollama](https://ollama.com) for local LLM-assisted triage and email drafting.

### Setup

```bash
# Clone the repository
git clone https://github.com/jacobjoshy16-commits/vendor-risk-analyst-agent.git
cd vendor-risk-analyst-agent

# Create virtual environment and install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install pyyaml requests pypdf

# (Optional) Pull recommended Ollama model
ollama pull qwen2.5:7b-instruct
```

> **Note**: If Ollama is not installed or running, pass `--offline` to use the built-in deterministic heuristic engine.

---

## Quickstart & Usage

### 1. Run an Assessment

```bash
# Run baseline assessment (sandbox snapshot v1)
python3 vra.py --offline --snapshot v1

# Run change detection assessment (sandbox snapshot v2 -> exits 1 on criticals)
python3 vra.py --offline --snapshot v2

# Run using a local Ollama model
python3 vra.py --snapshot v2 --model qwen2.5:7b-instruct

# Preview changes without modifying state
python3 vra.py --offline --snapshot v2 --dry-run
```

### 2. Onboard a New Vendor

```bash
# Discover artifacts, parse subprocessors, and scaffold register
python3 vra.py onboard "Acme Corp" \
  --tier critical \
  --category collaboration \
  --trust-center https://acme.safebase.io \
  --assess
```

### 3. Launch Web Console

```bash
# Start local web console (zero external dependencies)
python3 vra.py webui --host 0.0.0.0 --port 8765
```

---

## CLI Reference

### Main Command (`vra.py` / `vra.py run`)

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--snapshot VERSION` | Snapshot version tag (interpolated into watch paths) | `v1` |
| `--vendor SLUG` | Filter run to specific vendor slug (repeatable) | All vendors |
| `--out DIR` | Output directory for reports | `out/` |
| `--model TAG` | Ollama model tag | `$VRA_MODEL` or `qwen2.5:7b-instruct` |
| `--offline` | Run deterministic heuristic backend without network/LLM | `false` |
| `--dry-run` | Evaluate and print without writing state or report files | `false` |
| `--no-probe` | Skip in-tenant API probes | `false` |
| `--no-fail` | Always exit with code `0`, ignoring open critical findings | `false` |

### Onboarding Command (`vra.py onboard`)

| Flag | Description | Default |
| :--- | :--- | :--- |
| `name` *(positional)* | Vendor display name (e.g., `"Acme Corp"`) | *(Required)* |
| `--tier LEVEL` | Vendor criticality (`critical`, `high`, `medium`, `low`) | `high` |
| `--category CAT` | Vendor category (e.g., `identity_provider`, `collaboration`) | None |
| `--trust-center URL` | Trust center or security page URL / local HTML file | None |
| `--changelog URL` | Explicit changelog URL | None |
| `--subprocessors URL` | Explicit subprocessor list URL (HTML, PDF, or local file) | None |
| `--dpa URL` | Explicit DPA / BAA URL | None |
| `--assess` | Run an immediate assessment after scaffolding | `false` |
| `--dry-run` | Print scaffolded register without saving | `false` |

### Exit Codes

| Code | Meaning |
| :---: | :--- |
| `0` | Clean run (no open critical findings). |
| `1` | One or more open critical findings detected. |
| `2` | Execution or runtime error. |

---

## Control Set (`controls.yaml`)

The 15 compliance controls evaluate AI features against HIPAA Security Rule, NIST AI RMF, and HICP:

| ID | Severity | Name / Scope | Frameworks |
| :--- | :---: | :--- | :--- |
| **AIV-01** | High | Model provider disclosed per AI feature | HIPAA 164.308(b)(1), NIST AI RMF GOVERN-6.1, HICP TV-1 |
| **AIV-02** | Medium | AI-specific addendum executed | HIPAA 164.502(e)(2), NIST AI RMF GOVERN-1.2, HICP TV-2 |
| **AIV-03** | **Critical** | Model provider named in subprocessor list with BAA | HIPAA 164.504(e)(1), NIST AI RMF GOVERN-6.2, HICP TV-1 |
| **AIV-04** | High | Customer data excluded from model training/tuning | HIPAA 164.502(a), NIST AI RMF MANAGE-1.3, HICP TV-1 |
| **AIV-05** | Medium | Prompt and output retention period documented | HIPAA 164.316(b), NIST AI RMF GOVERN-4.1, HICP TV-2 |
| **AIV-06** | High | Data reach limited to minimum necessary | HIPAA 164.306(a), NIST AI RMF MAP-1.5, HICP PR-1 |
| **AIV-07** | **Critical** | Autonomous actions require human-in-the-loop review | HIPAA 164.312(a)(1), NIST AI RMF GOVERN-4.2, HICP PR-1 |
| **AIV-08** | High | AI actions and outputs recorded in audit logs | HIPAA 164.312(b), NIST AI RMF MEASURE-2.6, HICP PR-2 |
| **AIV-09** | Medium | Notification provided for model/version changes | NIST AI RMF GOVERN-6.1, HICP TV-2 |
| **AIV-10** | Medium | Error and hallucination rates disclosed | NIST AI RMF MEASURE-2.2, HICP TV-1 |
| **AIV-11** | High | Prompt injection and adversarial testing conducted | NIST AI RMF MANAGE-2.4, HICP TV-1 |
| **AIV-12** | High | Inference confined to contracted data residency | HIPAA 164.308(a)(1), NIST AI RMF MAP-1.5, HICP PR-1 |
| **AIV-13** | High | Bias and clinical performance testing performed | NIST AI RMF MEASURE-2.5, HICP TV-1 |
| **AIV-14** | Medium | AI-specific incident response process established | HIPAA 164.308(a)(6), NIST AI RMF MANAGE-4.1, HICP IR-1 |
| **AIV-15** | Medium | AI features configurable/disableable at tenant level | HIPAA 164.312(a)(1), NIST AI RMF MANAGE-1.2, HICP PR-1 |

---

## Output & Artifacts

| Path | Description |
| :--- | :--- |
| `out/latest.md`, `out/vendor-ai-risk-*.md` | Human-readable Markdown executive report. |
| `out/latest.json` | Full assessment results in machine-readable JSON format. |
| `data/findings.json` | Finding lifecycle and status database (`new`, `open`, `escalated`, `accepted_risk`, `resolved`). |
| `data/snapshots/{vendor}/{timestamp}/` | Normalized artifact snapshots and computed SHA-256 hashes. |
| `data/llm_audit.jsonl` | Audit log recording prompts, model completions, and latency. |
| `pending_review/` | Model-proposed register updates and blocker outreach drafts. |
| `artifacts/vendors/{slug}/` | Cached trust center pages, PDFs, and discovered artifacts. |

---

## Testing & Validation

```bash
# Run test suite (66 tests covering extraction, parsing, triage, lifecycle, and controls)
python3 tests/test_vra.py
```

For validation against ground-truth sandbox scenarios and recorded defect resolutions, refer to [VALIDATION.md](VALIDATION.md).

---

## Project Structure

```
.
├── vra.py                  # CLI entry point (run, onboard, webui)
├── controls.yaml           # 15 compliance controls definition
├── vendors/                # Per-vendor registers (YAML)
├── src/vra/
│   ├── cli.py              # CLI execution and console reporting
│   ├── onboard.py          # Vendor discovery and register scaffolding
│   ├── webui.py            # Local web console and REST API
│   ├── extract.py          # Portal detection and table/PDF extraction
│   ├── watch.py            # Artifact fetching, hashing, and diffing
│   ├── normalize.py        # Volatile content stripping
│   ├── triage.py           # Diff relevance classification
│   ├── observe.py          # Deterministic table/API parsing
│   ├── evaluate.py         # Control evaluation engine
│   ├── probe.py            # In-tenant API probes
│   ├── analyst.py          # Narrative, outreach, and POA&M drafting
│   ├── register.py         # Register I/O and finding lifecycle store
│   └── report.py           # Markdown and JSON report generation
├── sandbox/                # Multi-vendor test fixtures (v1/v2 snapshots)
├── tests/                  # Unit and integration test suite
└── VALIDATION.md           # Ground truth validation records
```
