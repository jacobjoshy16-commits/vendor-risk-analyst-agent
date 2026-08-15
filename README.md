# Vendor NHI Compliance Monitor

An **independent** workstation monitor for **non-human identities** that vendor
applications drop into your estate — especially **agentic AI** (copilots, agents,
service principals with write scopes).

It scores those identities, and the features they power, against **NIST SP 800-53
Rev. 5** and **SOC 2 Trust Services Criteria**. Leave it running. It re-checks
every vendor on a timer.

Vendor risk data does not leave the machine by default.

---

## What this is

Companies buy vendor SaaS. Those vendors ship **agentic** features that run as
**NHIs** inside *your* tenants: OAuth apps, service accounts, agent principals,
bots. Annual SOC 2 / 800-53 reviews do not see a copilot that gained
`users.manage` last Tuesday.

This tool is the independent monitor for that gap.

| You get | What that is |
| --- | --- |
| **A multi-vendor NHI inventory** | Every service account / OAuth app / agent / bot pulled from **that vendor’s API** — Atlassian, Slack, Okta, Auth0, … — paginated, not typed into YAML. Two planes: identities inside the vendor product, and vendor apps that landed in your IdP. |
| **A daemon** | `vra.py monitor` — the same assess, on a timer, while the PC is on. A critical is a finding, not a crash. |
| **A NIST 800-53 / SOC 2 score** | 8 identity controls (`NHI-*`) + 15 feature controls (`AIV-*`). Severity and whether something is a finding come from YAML + code. **The language model cannot create or re-severity a finding.** |
| **A draft pack** | Narrative, vendor email, POA&M row — citing 800-53 and SOC 2, not a chatbot opinion. |

### What it is not

- Not a hosted SIEM or a Microsoft / Okta / vendor-native dashboard. It is
  **independent** — it reads what vendors publish and what your tenant APIs
  return, and it scores *your* control set.
- Not a HIPAA-only healthcare reviewer. The sandbox vendors happen to be
  clinical so the planted scenario is sharp. The product identity is
  **800-53 + SOC 2 NHI / agentic monitoring**.
- Not an auto-remediator. It does not revoke tokens or write answers into the
  register.
- Not a reader of NDA-gated SafeBase/Whistic/Vanta pages. That is `blocked` +
  a drafted access request, never a silent pass.

---

## How you run it

Three commands. You do not need flags.

```
1. Connect a vendor     python3 vra.py connect
2. Leave it running     python3 vra.py monitor
3. Read the report      python3 vra.py report
```

**`connect`** asks what it needs — which vendor, the org URL, the API token
(hidden) — stores the token in the OS keychain, checks the connection, pulls
the identities, and writes a starter `vendors/{slug}.yaml`. Same command each
time. Run it once per vendor.

```
Vendor? [okta / auth0 / slack / atlassian]  > okta
Org URL?  > https://acme.okta.com
Paste API token (hidden)  > ••••••••
✓ stored in keychain   ✓ connection ok   ⚠ token has write scope — use read-only
✓ discovered 12 identities   ✓ created vendors/okta.yaml
```

**`monitor`** turns itself on. It finds Ollama if you have it, otherwise uses
the built-in checker. It re-checks every 15 minutes. The local console opens
on port 8765. Every vendor you connected is picked up on the next cycle.

**`report`** prints the finding summary and opens `out/latest.md`. One place
to look. At ~20 vendors / ~60 identities, start with the portfolio rollup
instead of scrolling per-vendor markdown:

```
python3 vra.py portfolio
```

---

## Connectors (how it scales past four vendors)

The CLI menu is generated from a **connector registry**. Adding a vendor is
registering a manifest (id, auth, fields, pagination, `list_nhis()`). There
is no hardcoded vendor list in `connect` / `creds` / `discover`.

Protocol connectors cover a *class* of APIs, not a brand:

| Connector | What it lists | You give it |
| --- | --- | --- |
| `oidc_apps` | Registered apps + granted scopes | Org URL + token. Flavor (Okta / Auth0 / Entra / Ping / OneLogin) is inferred from the hostname. |
| `scim` | Service accounts from any SCIM 2.0 `/Users` | SCIM base URL + bearer. Humans are skipped. |
| `generic_rest` | Whatever your endpoint returns | List URL + JSONPath mapping for `id` / `scopes` / `owner`. |

Native connectors stay for products that are not a protocol: **GitHub**
(app installations), **Google Workspace** (directory service accounts),
**AWS IAM** (users + roles), **Atlassian**, **Slack**.

At this size the monitor also:

- **Keys identities by immutable id**, not display name. A rename does not
  fork history or drop entitlement tracking.
- **Polls vendors on a bounded worker pool** (`VRA_WORKERS`, default 4).
- **Isolates failure.** One vendor's 401 or timeout is logged; last-known
  inventory is kept; the other 19 still run.

### What you get on day one, and what waits

The 3-step path starts **NHI discovery and entitlement tracking** immediately.
The richer AIV-* feature score (autonomy, model provider, BAA/DPA coverage)
needs register fields a stub cannot invent. Those show up as `unknown` — a
21-day question, not a failure. Fill them later:

```
python3 vra.py enrich okta          # lists what is still unknown
python3 vra.py enrich okta --edit   # opens the file; you type the answers
```

The model will not fill these in for you.

Credentials survive a shell restart because they live in the OS keychain
(macOS Keychain, Windows Credential Locker, Linux Secret Service), not in the
terminal. If this machine has no keychain (a headless Linux box, this
sandbox), they go in `~/.local/share/vra/keyring.json` at mode `0600` and
the CLI says so. That is a last resort, not the desktop path. The monitor remints Auth0 from the stored client id/secret and
retries once on 401. 429s honor `Retry-After` and keep a partial list. The
same principal seen on your IdP and on the vendor API is linked
(`also_seen_on`). If an agent **gains a write scope** since last cycle, that
is recorded as an `entitlement_change` in `data/findings.json`.

Two copies of the monitor cannot run (`data/monitor.lock`).

```bash
python3 vra.py monitor status
python3 vra.py monitor stop
python3 vra.py monitor install     # writes login units; does not enable them
```

---

## The two control families

**NHI-*** is the product. It scores the *identity*.
**AIV-*** is the companion. It scores the *agentic feature* that identity powers.

Every control cites **NIST SP 800-53** and **SOC 2 TSC**. Tests refuse a
control that does not.

| ID | Sev | Question | 800-53 | SOC 2 |
| --- | --- | --- | --- | --- |
| **NHI-01** | critical | Agent principal holds write scopes and acts without human review | AC-3, AC-6 | CC6.1, CC6.3 |
| **NHI-02** | high | Every NHI has a named human owner | AC-2 | CC6.1 |
| **NHI-03** | high | Credentials rotated at least annually | IA-5, IA-5(1) | CC6.1 |
| **NHI-04** | high | Every identity seen in a tenant is inventoried (no orphans) | AC-2, CM-8 | CC6.1 |
| **NHI-05** | medium | NHI actions written to an exportable audit log | AU-2, AU-12 | CC7.2 |
| **NHI-06** | high | Cross-vendor NHIs declared on the home vendor | AC-3, CA-3 | CC6.6, CC9.2 |
| **NHI-07** | medium | Disabled identities retain no write scopes | AC-2(3), AC-6 | CC6.2 |
| **NHI-08** | high | A suggests-only identity does not hold standing write scopes | AC-6, AC-6(2) | CC6.3 |
| AIV-01 | high | Model provider disclosed per AI feature | SA-9, SR-3 | CC9.2 |
| AIV-02 | medium | AI addendum executed | SA-9, SA-4 | CC9.2 |
| **AIV-03** | critical | Every model provider named as subprocessor and BAA/DPA-covered | SA-9, CA-3 | CC9.2 |
| AIV-04 | high | Customer data not used to train / fine-tune | SI-12, AC-4 | CC6.1 |
| AIV-05 | medium | Prompt/output retention documented and bounded | SI-12, AU-11 | C1.1 |
| AIV-06 | high | Data reach limited to minimum necessary | AC-6 | CC6.1 |
| **AIV-07** | critical | No autonomous action on production records without human review | AC-3, AC-6 | CC6.1, CC6.3 |
| AIV-08 | high | AI actions written to an exportable audit log | AU-2, AU-12 | CC7.2 |
| AIV-09 | medium | Advance notice of material model changes | CM-3, SA-9 | CC8.1 |
| AIV-10 | medium | Error / accuracy rates disclosed | SI-10, SA-11 | CC7.1 |
| AIV-11 | high | Prompt-injection / adversarial testing shared | SI-10, SA-11 | CC7.1 |
| AIV-12 | high | Inference inside contracted residency | SC-28, SA-9 | CC6.7 |
| AIV-13 | high | Bias / performance testing *(when the feature touches clinical records)* | SA-11, SI-10 | CC7.1 |
| AIV-14 | medium | AI-specific incident response | IR-4, IR-6 | CC7.3, CC7.4 |
| AIV-15 | medium | Feature disableable at tenant level | CM-7, AC-3 | CC6.3 |

Edit `nhi_controls.yaml` / `controls.yaml` without touching code. Due dates:
critical 7 days, high 30, medium 60, low 90, gaps 21.

AIV-07 and NHI-01 are AND conditions: acting **and** no human in the loop.
An agent that acts under review is not a finding.

---

## Design rules (why the score is usable in an audit)

**1. The model never invents a finding.** No code path from model output to a
severity, a due date, or the existence of a finding.

**2. The model reads unstructured vendor text and drafts language.** It does
not decide what is true.

**3. A claim drives a finding only if it is quotable** to an artifact line or
an API field.

| Tier | Source | Drives a finding? |
| --- | --- | --- |
| `register` | Human YAML in `vendors/` | **Yes** |
| `observed` | Parsed table / tenant API | **Yes** — with provenance |
| `proposed` | Model inference | **No** — `pending_review/` only |

**4. Unknown is a question, not a failure.** Unanswered fields are 21-day
information gaps, not “non-compliant.”

**5. Local by default.** Ollama on the workstation, or the built-in checker.

---

## Setup

Python 3.10+.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # pyyaml requests pypdf keyring
# optional, for live-model triage:
ollama pull qwen2.5:7b-instruct
```

Then the three commands above. To replay the planted sandbox scenario:

```bash
python3 vra.py --offline --snapshot v1          # sandbox baseline
python3 vra.py --offline --snapshot v2          # planted change → exit 1
python3 -m unittest tests.test_vra tests.test_monitor_nhi tests.test_real_world_vendors tests.test_idp_discover tests.test_creds tests.test_connect
```

Exit codes: `0` clean · `1` open critical · `2` run error.

### Outputs

| Path | Contents |
| --- | --- |
| `out/latest.md` / `out/latest.json` | The assessment |
| `data/nhis.json` | Portfolio NHI inventory — **this is the product** |
| `data/findings.json` | Finding lifecycle — **back this up** |
| `data/monitor.json` | Daemon heartbeat, last 20 cycles |
| `data/snapshots/` | Normalized artifacts + hashes |
| `pending_review/` | Model proposals (never auto-applied) |

---

## Scripts and CI

The 3-step path is the human front door. Flags stay underneath so a daemon
or a pipeline never has to answer a prompt.

```bash
# Store / list / forget a token without the wizard
python3 vra.py creds set okta
python3 vra.py creds list
python3 vra.py creds test okta --base-url https://your-org.okta.com
python3 vra.py creds rm slack

# Discover without writing a stub
python3 vra.py discover --provider okta --base-url https://your-org.okta.com
python3 vra.py discover --fixture sandbox/probe/idp/okta_pages.json

# Connect without prompts (token already in the keychain, or CI env)
python3 vra.py connect --provider okta --base-url https://acme.okta.com --yes
python3 vra.py connect --provider okta --base-url https://acme.okta.com --allow-env-creds --yes

# Monitor without the console, or one cycle for cron
python3 vra.py monitor --no-webui --offline --interval 15m
python3 vra.py monitor --once --offline
python3 vra.py report --no-open
```

`--allow-env-creds` is CI only. It prints a warning. Prefer the keychain.

| Flag | Effect |
| --- | --- |
| `--offline` | No network; heuristic backend. Report says so. |
| `--vendor SLUG` | One vendor. Repeatable. Does not close others. |
| `--dry-run` | Print only. |
| `--once` | Monitor: one cycle then exit (cron). |
| `--no-webui` | Monitor: do not serve the local console. |
| `--yes` | Connect: never prompt; fail if a value is missing. |

---

## Sandbox

Three fictional vendors so the detector can be shown firing *and* staying quiet:

| Vendor | v2 planted change |
| --- | --- |
| Aegis Identity Cloud | Agent Mode GA — directory writes, no per-action approval → AIV-07 + NHI-01 |
| Loop Workspace | Perplexity added as row 6 of 9, BAA “Pending”, no changelog → AIV-03 |
| Meridian RevCycle | Negative control. Wording churn. Must produce nothing new. |

`sandbox/real_world/` is Slack / Atlassian / Zoom / Notion / Datadog public
subprocessor pages. A JS shell with no table is `parse_failed`, not a pass.

---

## Limitations

The scored sandbox runs used the offline heuristic, not a live 7B model. That
validates the pipeline and the control mapping. It does **not** validate triage
on messy real vendor prose. Run against Ollama before relying on it.

- NDA / login walls stop the parse, loudly (`blocked` + outreach).
- Unpublished change with no probe → nothing fires.
- Sandbox probes are fixture-mode. Live API drift is unexercised.
- A stale register produces confident, wrong output except where a probe or
  parsed table overlays it.
- A connect stub is enough for NHI discovery. It is **not** a complete AIV-*
  register — those fields stay `unknown` until a human fills them.

---

## Repository

```
vra.py                  entry point — connect / monitor / report
nhi_controls.yaml       8 NHI-* controls — the identity set (800-53 + SOC 2)
controls.yaml           15 AIV-* controls — the feature set (800-53 + SOC 2)
vendors/*.yaml          per-vendor register; nhis: is overlay, not the list
src/vra/connect.py      the interactive front door
src/vra/idp.py          IdP connectors (Okta / Auth0) + dispatcher
src/vra/connectors.py   vendor connectors (Atlassian, Slack, …)
src/vra/discover.py     `vra.py discover`
src/vra/monitor.py      the daemon
src/vra/nhi.py          inventory + NHI-* evaluation
src/vra/cli.py          one assess pass
src/vra/onboard.py      onboard / bootstrap (trust-center path)
src/vra/creds.py        OS keychain
src/vra/webui.py        local console
sandbox/                planted scenario + real-world page fixtures
sandbox/probe/idp/      recorded Okta / Auth0 pages (same walker as live)
VALIDATION.md           including every defect found
```
