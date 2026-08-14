# Vendor NHI Complaince Monitor (1.2) 

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
- Not an auto-remediator. It does not revoke tokens or write the register.
- Not a reader of NDA-gated SafeBase/Whistic/Vanta pages. That is `blocked` +
  a drafted access request, never a silent pass.

---

## How you run it

```
1. Bootstrap each vendor     python3 vra.py bootstrap Slack --offline
2. Accept the proposal       edit vendors/{slug}.yaml  (model never writes it)
3. Point probe: at each vendor API   Atlassian / Slack / Okta / Auth0 + token env
4. Discover the identities           python3 vra.py discover --provider atlassian --base-url https://api.atlassian.com
5. Leave the monitor up      python3 vra.py monitor --offline --webui --interval 15m
6. Read the pack             out/latest.md
7. List the identities       python3 vra.py nhis
```

You do **not** type NHIs into YAML. `vra.py discover` (and every monitor cycle)
pages the Okta or Auth0 management API until there is no next page, and writes
`data/nhis.json`. `vendors/*.yaml` `nhis:` is an optional overlay — owner,
last-rotated, `resides_in` — for identities the API cannot annotate.

```bash
# Live IdP — full list, paginated. Token stays in the environment.
export OKTA_API_TOKEN=...          # SSWS, never written to disk
python3 vra.py discover --provider okta --base-url https://your-org.okta.com

export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
python3 vra.py discover --provider auth0 --domain your-tenant.us.auth0.com

# Recorded pages (same walker as live, no network):
python3 vra.py discover --fixture sandbox/probe/idp/okta_pages.json
```

The monitor remints Auth0 from `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET` into
an in-process vault (`expires_in` minus 60s) and retries once on 401. A
static `AUTH0_MGMT_TOKEN` cannot be refreshed and will 401 after ~24h — the
cycle then keeps last inventory instead of wiping it. 429s honor
`Retry-After` / `X-Rate-Limit-Reset` and return a partial list. The same
principal seen on your IdP and on the vendor API is linked (`also_seen_on`);
that observation satisfies NHI-06 without a YAML row.

The monitor re-reads `vendors/` every cycle. A vendor you onboard at 2pm is in
the 2:15 run. Two copies cannot run (`data/monitor.lock`). Identical fetches
do not write another snapshot.

```bash
python3 vra.py monitor --offline --webui --interval 15m
python3 vra.py monitor status
python3 vra.py monitor stop
python3 vra.py monitor install --offline --webui   # writes login units; does not enable them
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

Cross-vendor example (NHI-06): Loop’s provisioning client living in Aegis’s
tenant is *observed* on Aegis, *declared* on Loop with `resides_in`, and
only fires if that declaration is missing.

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

**5. Local by default.** Ollama on the workstation, or `--offline`.

---

## Setup

Python 3.10+.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pyyaml requests pypdf
# optional, for live-model triage:
ollama pull qwen2.5:7b-instruct
```

```bash
python3 vra.py --offline --snapshot v1          # sandbox baseline
python3 vra.py --offline --snapshot v2          # planted change → exit 1
python3 vra.py bootstrap Slack --offline        # new vendor, catalog URL
python3 vra.py discover --fixture sandbox/probe/idp/okta_pages.json
python3 vra.py monitor --offline --webui --interval 15m
python3 vra.py nhis
python3 -m unittest tests.test_vra tests.test_monitor_nhi tests.test_real_world_vendors tests.test_idp_discover
```

| Flag | Effect |
| --- | --- |
| `--offline` | No network; heuristic backend. Report says so. |
| `--vendor SLUG` | One vendor. Repeatable. Does not close others. |
| `--dry-run` | Print only. |
| `--once` | Monitor: one cycle then exit (cron). |
| `--webui` | Local console on `:8765` (onboard, Start/Stop, NHI table). |

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
on messy real vendor prose. Run `--model` against Ollama before relying on it.

- NDA / login walls stop the parse, loudly (`blocked` + outreach).
- Unpublished change with no probe → nothing fires.
- Sandbox probes are fixture-mode. Live API drift is unexercised.
- A stale register produces confident, wrong output except where a probe or
  parsed table overlays it.

---

## Repository

```
vra.py                  entry point
nhi_controls.yaml       8 NHI-* controls — the identity set (800-53 + SOC 2)
controls.yaml           15 AIV-* controls — the feature set (800-53 + SOC 2)
vendors/*.yaml          per-vendor register; nhis: is overlay, not the list
src/vra/idp.py          IdP connectors (Okta / Auth0) + dispatcher
src/vra/connectors.py   vendor connectors (Atlassian, Slack, …)
src/vra/discover.py     `vra.py discover`
src/vra/monitor.py      the daemon
src/vra/nhi.py          inventory + NHI-* evaluation
src/vra/cli.py          one assess pass
src/vra/onboard.py      onboard / bootstrap
src/vra/webui.py        local console
sandbox/                planted scenario + real-world page fixtures
sandbox/probe/idp/      recorded Okta / Auth0 pages (same walker as live)
VALIDATION.md           including every defect found
```
