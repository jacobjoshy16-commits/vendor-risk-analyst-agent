# Substation Supply-Chain Integrity Monitor

**NERC CIP-013 supply chain risk management, evidenced cryptographically.**

For an electric utility, a vendor firmware package is not a compliance
checkbox — it is code that will execute on a protective relay deciding whether
high-voltage power flows. This tool verifies that code before it is trusted, and
produces the evidence a NERC audit asks for.

```bash
python3 vra.py cip                  # assess the estate
python3 vra.py cip --evidence       # + write the audit evidence pack
python3 vra.py cip onboard --vendor "…" --docs ./contracts   # onboard a supplier
```

Vendor risk data does not leave the machine by default.

---

## What this is

Firmware verification at most utilities is semi-manual: an engineer downloads a
binary, compares the hash to the vendor's release notes, and records it on a
spreadsheet. That process has a specific blind spot, and this tool exists to
close it.

| You get | What that is |
| --- | --- |
| **Real cryptographic verification** | Actual SHA-256 over the bytes on disk and actual Ed25519 signature verification against a registry of pinned vendor keys. No field asserts a verification result. Flip one bit in an 8 KB image and the answer changes. |
| **A NERC CIP score** | **30 `CIP-*` controls** over four subjects — firmware deployments, procurement, vendor ESP access, vendor personnel. CIP-013 R1/R2/R3, CIP-010 R1.6, CIP-005 R2.4/2.5, CIP-004 R2–R5, scoped by CIP-002 impact rating. |
| **Procurement detection** | The model reads the vendor's actual contract documents and locates each CIP-013 R1.2 obligation. **Code verifies every quote against the source** before it may affect a control. |
| **An audit evidence pack** | Organised by requirement, not by finding, with a denominator on every row and the cryptographic working shown. Markdown, HTML and JSON. |
| **A companion SaaS set** | A trimmed 7 `NHI-*` + 4 `AIV-*` controls citing 800-53 / SOC 2, for vendor agents and non-human identities. Not the load-bearing set. |

Severity and whether something is a finding come from YAML plus code.
**The language model cannot create a finding or set a severity.**

### Why two cryptographic checks, not one

Both are computed, in this order, and they answer different questions:

| Check | Question | NERC part |
| --- | --- | --- |
| **SHA-256** | Are these the bytes the published digest describes? | CIP-010 R1.6.2 (integrity) |
| **Ed25519 signature** | Did those bytes come from the vendor, and are they unmodified since signing? | CIP-010 R1.6.1 (source identity) + R1.6.2 |

A hash proves the file matches *a published string*. It does not prove the
string came from the vendor — an attacker who can substitute a binary on a
distribution mirror can substitute the digest printed beside it, because both
travel the same channel. A signature is the part they cannot forge without the
vendor's private key.

So **where a vendor publishes a signing key, a matching hash does not close
CIP-010 R1.6.2.** Where a vendor publishes no key, the hash is the only method
available from the source, it is used, and the result is recorded as
`verification_strength: hash_only` rather than dressed up as the stronger check.

This is the argument of the whole project, and the planted demo scenario is
built to show it: a package that **passes the hash check and fails the
signature check**. The spreadsheet process returns green on it.

### What it is not

- **Not a compliance determination.** It automates the evidence CIP-010 R1.6 and
  CIP-004 R4 require you to produce. Whether you are compliant is a Regional
  Entity's finding, not a tool's output, and the evidence pack never claims
  otherwise.
- **Not connected to any OT network.** The estate, vendors, personnel and
  firmware are synthetic throughout.
- **Not an auto-remediator.** It does not quarantine binaries, revoke access, or
  write answers into the register.
- **Not a certificate-chain implementation.** The trust model is a flat registry
  of pinned keys. Real relay vendors sign with RSA or ECDSA under X.509 with
  path validation and revocation checking; see
  [`VALIDATION-CIP.md`](VALIDATION-CIP.md) for the full list of gaps.

### Where the model sits

The model reads prose. It does not decide anything.

```
vendor contract documents ──▶ [ MODEL ] ──▶ claim + verbatim quote
                                                   │
                                                   ▼
                                         [ CODE ] quote located in source?
                                                   │  severity ceiling?
                                                   │  absence or presence?
                                                   ▼
                                         finding · gap · review queue
```

It never sees a hash, a signature result, a key, or an asset inventory. Those
are computed by code and consumed by code. See
[Detecting the procurement process](#detecting-the-procurement-process-the-agent-reads-the-contract).

---

---

## The NERC CIP assessment

The load-bearing control set. It cites **NERC and nothing else** — a utility is
audited against NERC, and carrying 800-53 and SOC 2 alongside it makes the file
longer without making it more defensible. It is scored by the same deterministic
evaluator as the companion sets further down.

```bash
python3 vra.py cip                  # assess the estate
python3 vra.py cip --evidence       # + write the audit evidence pack
python3 vra.py cip build-fixtures   # regenerate keys, packages, firmware
```

### What it scores

25 controls over four subjects, with the standards split the way they actually
apply:

| Standard | What it governs here | Controls |
| --- | --- | --- |
| **CIP-013** | The procurement *plan* layer: R1.1 risk assessment process, R1.2.1–R1.2.6 contract clauses, R2 implementation, R3 15-month CIP Senior Manager approval | CIP-07 … CIP-15 |
| **CIP-010 R1.6** | The per-installation technical check: verify software **source identity** (1.6.1) and **integrity** (1.6.2) before deviating from baseline | CIP-01 … CIP-06 |
| **CIP-005 R2** | Vendor remote access into the ESP: methods to **determine** active sessions (2.4) and to **disable** them (2.5) | CIP-16 … CIP-18 |
| **CIP-004** | Who may hold that access: training (R2), personnel risk assessment (R3), authorization and quarterly verification (R4), revocation (R5) | CIP-19 … CIP-25 |
| **CIP-002** | Not encoded as controls. Its High/Medium/Low impact rating drives `applies_when` on everything above. | — |

**CIP-013 does not impose the firmware check.** It is a plan standard; the
operational requirement to verify source identity and software integrity is
CIP-010 R1 Part 1.6, and vendor session control is CIP-005 R2.4/R2.5. Getting
this split right is why findings cite a requirement that actually governs them.

### The verification is real

`src/vra/cipcrypto.py` performs actual Ed25519 verification and actual SHA-256
over the bytes on disk. No field asserts a verification result.

The judgement that matters: **where a vendor publishes a signing key, a matching
published hash does not close CIP-010 R1.6.2.** The bytes matching a published
string does not establish that the string came from the vendor — an attacker who
can substitute a binary on a mirror can substitute the hash beside it. Where a
vendor publishes no key, the hash is the only available method and is used, but
recorded as `verification_strength: hash_only` rather than dressed up.

### The simulated estate

1,300 substations and ~7,500 cyber assets across four states, generated
deterministically from a seed. Impact ratings are deliberately lopsided — 26
high, 116 medium, 1,158 low — because CIP-013 attaches to high and medium impact
systems and a tool that ignores that is ~89% false positives.

All vendors are **fictional**. Real relay vendors are deliberately absent: this
repo is public and the planted scenario is a package that fails verification.

One planted compromise, built the way a mirror compromise actually looks — the
attacker substitutes the binary *and* the published hash, but cannot forge the
signature:

```
FIRMWARE VERIFICATION FAILED  SPS-421-4.7.2
    vendor published SHA-256 cf57cc28…: MATCH
    Ed25519 verify against key sentinel-protective-2026: INVALID
```

A hash-and-spreadsheet process passes that package. It is deployed on 131
protective relays.

### Detecting the procurement process (the agent reads the contract)

CIP-013 R1.2.1–R1.2.6 ask whether your procurement process addresses six
obligations. Answering that from a boolean somebody typed into YAML just moves
the work — a human still has to read the master services agreement. So the model
reads it.

```bash
python3 vra.py cip onboard --vendor "Kestrel Grid Systems" \
    --docs sandbox/procurement/kestrel-grid
```

**The model finds and quotes the clause. The code decides what it means.** This
adds one tier to the existing provenance model in `observe.py`:

| Tier | What it is | Drives a finding? |
| --- | --- | --- |
| `register` | A human wrote it down | **Yes** |
| `observed` | Parsed deterministically from a table or API | **Yes** |
| **`extracted`** | **A model read prose AND the quote it gave was located in the source document** | **Yes — capped** |
| `proposed` | A model said something it could not evidence | **Never** |

Two rules are not negotiable:

**1. Presence can be evidenced. Absence cannot.** The model can quote MSA §9.1 to
show an incident-notification clause exists. It cannot quote anything to show a
clause is *missing* — an absence has no text. So "this clause is not present"
never produces a control failure; it produces an information gap with a question
for the vendor. Inverting this would let a model fail a vendor on a clause it
merely failed to find in a 90-page contract.

**2. A verified extraction may not raise a critical on its own.** Quote
verification proves the text exists. It does not prove the model read the *scope*
right — a definition, a struck exhibit, or a clause scoped to a different product
line all quote perfectly. Criticals route to `pending_review/` with the reason.
The ceiling is derived from the control set, so re-rating a control in YAML moves
it.

On the sandbox vendor, six clauses are applied and two are withheld:

```
CIP-013 R1.2.1   incident_notification_clause      found  verified   yes
CIP-013 R1.2.3   access_termination_notice_clause  -      -          held
CIP-013 R1.2.5   software_integrity_clause         found  verified   held
CIP-013 R1.2.6   remote_access_coordination_clause found  verified   yes
```

R1.2.3 is genuinely absent from the documents, and the questionnaire answer that
*looks* like it addresses the obligation commits the vendor to nothing — the case
a human skimming would tick off. R1.2.5 was quoted correctly but drives a
critical, so it waits for ratification.

Then the same run registers the vendor's signing key and verifies each release —
**SHA-256 first, then Ed25519**:

```
ACCEPTED  KG-RTU-100-2.4.0    hash MATCH · signature VALID
REJECTED  KG-RTU-100-2.4.1    hash MATCH · signature INVALID
```

Without a local model the extractor falls back to a deterministic keyword
heuristic, labelled `offline-heuristic` everywhere it appears. It is held to the
same rules: it must return a real verbatim sentence, and that sentence goes
through the same verification. A heuristic that could bypass the check would
leave the safety boundary untested in CI, which is where it matters most.

### The evidence pack

`--evidence` writes `out/cip/evidence-pack.{md,html,json}` plus `findings.json`.
Organised **by requirement, not by finding**, because an audit opens with "show
me you checked", so every requirement carries its denominator:

```
CIP-01  CIP-010-4 R1 Part 1.6.2   7,464 population · 1,724 applicable · 1,593 passed · 131 exceptions
```

Exceptions collapse to root causes — 131 relays running one bad build is one
remediation, not 131. The pack **never asserts compliance** (that is the
Regional Entity's determination), always declares the data synthetic, and prints
a banner while any citation is unverified.

> **Citations are currently unverified.** All 25 controls carry
> `citation_verified: false`. The standard revisions and part numbers were
> written from knowledge, not checked against nerc.com. Confirm each and set the
> flag before showing this to a compliance audience.

See `VALIDATION-CIP.md` for what is proven (and what is not) and `DEMO-CIP.md`
for the presentation script.

---

---

## The SaaS companion: running the NHI / AIV monitor

> This is the original product and it still works. It monitors vendor
> non-human identities and agentic features against 800-53 / SOC 2, on a
> timer. It is unrelated to the NERC path above and needs no OT data.

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
on `127.0.0.1:8765` and prints a URL with a one-time token — open that exact
URL; the console 401s without it. Every vendor you connected is picked up on
the next cycle.

The console is loopback-only by default because its POST routes start
processes and read local paths. `--host 0.0.0.0` still works for a preview
proxy, warns when it does, and needs the proxy hostname in
`VRA_WEBUI_ALLOWED_HOSTS`.

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
| `entra` | Applications, service principals, **and the permissions actually granted** — appRole assignments resolved from GUID to name, plus delegated `oauth2PermissionGrants` | Graph token. |
| `scim` | Service accounts from any SCIM 2.0 `/Users` | SCIM base URL + bearer. Humans are skipped. |
| `generic_rest` | Whatever your endpoint returns | List URL + JSONPath mapping for `id` / `scopes` / `owner`. |

**Microsoft Entra ID** is a first-class target, not a listing. Entra keeps
entitlements on the service principal in two shapes — `appRoleAssignments`
(a GUID that only means something against the resource principal's catalogue)
and `oauth2PermissionGrants` (a space-separated string). Both are pulled, so an
Entra agent holding `User.ReadWrite.All` is scored by NHI-01 rather than
reported as having no scopes. An app registration and its service principal are
collapsed into one identity; a managed identity with no registration is still
inventoried. A permission whose catalogue is missing is kept as
`appRole:<guid>` and warned about — never dropped.

Native connectors stay for products that are not a protocol: **GitHub**
(app installations), **Google Workspace** (directory service accounts),
**AWS IAM** (users + roles), **Atlassian**, **Slack**.

At this size the monitor also:

- **Keys identities by immutable id**, not display name. A rename does not
  fork history or drop entitlement tracking.
- **Links identities through an inverted index.** Matching is exact-token
  equality, so cross-plane linking is near-linear rather than comparing every
  identity against every other one: 20k identities link in well under a second.
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

### How long it keeps watching, and how long it keeps the record

A stored token has **no expiry in this tool** — it is used until you run
`vra creds rm`. Its age is tracked, though: `vra creds list` shows when each
secret was stored and flags anything past `VRA_CREDENTIAL_MAX_AGE_DAYS`
(default 365), and a run says so in its summary. NHI-03 asks vendors to rotate
non-human credentials at least annually; this token is one, so it is held to
the same rule rather than exempted. Re-running `vra creds set <connector>`
restarts the clock. So the failure that matters is revocation, not expiry: the
tenant stops answering and the inventory freezes. When a configured probe
cannot run, its identities are kept but marked **last known**, the run reports
INCOMPLETE and exits non-zero, and the report says which tenant was not reached
and why. They are never presented as current.

Entitlement changes are the only permanent record that a permission moved —
`data/nhis.json` holds current state, not history. So the log is **archived,
not deleted**: every save rolls anything past the retention window out to
`data/events/events-YYYY-MM.jsonl`, keeping `findings.json` bounded (it is
re-serialised every cycle, so an unbounded array there costs write bandwidth as
well as space). At 50 vendors a simulated year of changes leaves 2.7 MB hot and
6.4 MB archived, with every event still readable.

```bash
python3 vra.py events                    # counts, sizes, oldest record
python3 vra.py events show --limit 20    # recent changes
python3 vra.py events prune              # roll aged events out now
python3 vra.py events purge --before 2025-01-01 --yes   # destroy them
```

`purge` is the only path that destroys anything, it refuses without `--yes`,
and it tells you how many of the doomed events record an identity *gaining* a
write scope. Tune with `VRA_EVENT_RETENTION_DAYS` (default 90) and
`VRA_EVENT_HOT_MAX` (default 5000).

```bash
python3 vra.py monitor status
python3 vra.py monitor stop
python3 vra.py monitor install     # writes login units; does not enable them
```

---

## The companion control families

> These are **not** the load-bearing set. `cip_controls.yaml` is — see
> [NERC CIP module](#the-nerc-cip-assessment). Both sets below were trimmed
> to a utility-relevant core (23 controls down to 11) when NERC became the
> product identity; healthcare-specific and SaaS-governance controls were
> dropped.

**NHI-*** scores the *identity*.
**AIV-*** scores the *agentic feature* that identity powers.

Every control cites **NIST SP 800-53** and **SOC 2 TSC**. Tests refuse a
control that does not.

| ID | Sev | Question | 800-53 | SOC 2 |
| --- | --- | --- | --- | --- |
| **NHI-01** | critical | Agent principal holds write scopes and acts without human review | AC-3, AC-6 | CC6.1, CC6.3 |
| **NHI-02** | high | Every NHI has a named human owner | AC-2 | CC6.1 |
| **NHI-03** | high | Credentials rotated at least annually | IA-5, IA-5(1) | CC6.1 |
| **NHI-04** | high | Every identity seen in a tenant is inventoried (no orphans) | AC-2, CM-8 | CC6.1 |
| **NHI-06** | high | Cross-vendor NHIs declared on the home vendor | AC-3, CA-3 | CC6.6, CC9.2 |
| **NHI-07** | medium | Disabled identities retain no write scopes | AC-2(3), AC-6 | CC6.2 |
| **NHI-08** | high | A suggests-only identity does not hold standing write scopes | AC-6, AC-6(2) | CC6.3 |
| AIV-01 | high | Model provider disclosed per AI feature | SA-9, SR-3 | CC9.2 |
| **AIV-03** | critical | Every model provider named as subprocessor and BAA/DPA-covered | SA-9, CA-3 | CC9.2 |
| **AIV-07** | critical | No autonomous action on production records without human review | AC-3, AC-6 | CC6.1, CC6.3 |
| AIV-11 | high | Prompt-injection / adversarial testing shared | SI-10, SA-11 | CC7.1 |

Edit `nhi_controls.yaml` / `controls.yaml` without touching code. Due dates:
critical 7 days, high 30, medium 60, low 90, gaps 21 — counted from the day
the finding was **first raised**, not from the current cycle, so a finding the
monitor re-sees every 15 minutes still goes overdue and escalates. Re-rating a
control in YAML moves the deadline; it does not restart the clock.

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
| `extracted` | Model read prose **and** the quote it gave was located in the source document | **Yes** — capped below critical |
| `proposed` | Model inference it could not evidence | **No** — `pending_review/` only |

The `extracted` tier is where the model does real work. It is bounded by two
rules in `src/vra/procure.py`: a claim of *absence* can never fail a control
(an absence has no text to quote), and a verified quote may not raise a
critical on its own (verification proves the text exists, not that its scope
was read correctly).

**4. Unknown is a question, not a failure.** Unanswered fields are 21-day
information gaps, not “non-compliant.”

**4a. The register is yours.** A run never rewrites `vendors/*.yaml`. Machine
bookkeeping goes to `data/registry_state.json`, so your comments survive and a
cycle leaves no diff. Your registers are gitignored; the three demo vendors
ship in `sandbox/registers/` and a register of yours shadows a demo one with
the same slug. Point elsewhere with `VRA_VENDORS_DIR`.

**5. Local by default.** Ollama on the workstation, or the built-in checker.

**6. The model is asked once per distinct prompt.** Narrative and outreach text
is cached in `data/llm_cache.json`, keyed by a hash of the exact
backend/model/task/system/prompt. A finding the monitor re-sees unchanged costs
zero model calls; change anything that reaches the prompt and that entry — only
that entry — is regenerated. Only the hash is stored, never the prompt text.
Set `VRA_LLM_CACHE=0` to re-ask every cycle.

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
python3 -m unittest discover -s tests -t .   # every test module, incl. new ones
```

Exit codes: `0` clean · `1` open critical · `2` run error.

### Outputs

| Path | Contents |
| --- | --- |
| `out/latest.md` / `out/latest.json` | The assessment |
| `data/nhis.json` | Portfolio NHI inventory — **this is the product** |
| `data/findings.json` | Finding lifecycle — **back this up** |
| `data/monitor.json` | Daemon heartbeat, last 20 cycles |
| `data/registry_state.json` | Per-vendor last_assessed + snapshot hashes |
| `data/events/` | Archived entitlement changes, one JSONL per month |
| `data/llm_cache.json` | Model answers, keyed by prompt hash (LRU, capped) |
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

**On the NERC path specifically:**

- **The NERC citations are unverified.** All 30 controls carry
  `citation_verified: false`. Standard revisions (CIP-013-2, CIP-004-7,
  CIP-005-7, CIP-010-4) and part numbers were written from knowledge, not
  checked against the enforceable standards. Every artifact prints a banner
  until a human does that pass.
- **Extraction has only run against the offline heuristic and clean demo
  prose.** A real master services agreement is 90 pages of cross-referenced
  exhibits and amendments. The *adjudication* is validated; *extraction quality
  on messy contracts* is not.
- **Quote verification does not validate interpretation.** It proves the text is
  in the document. It cannot tell whether a clause was struck by a later
  amendment or scoped to a different product line. That is why criticals are
  withheld — but an applied `high` still rests on the model reading scope right.
- **Impact ratings are a plausible distribution, not a categorisation.** Real
  CIP-002 work runs Attachment 1 criteria against each BES Cyber System.
- **No live OT integration.** Deployments are generated, not read from a CMDB or
  a patch management system.

**On the SaaS companion:**



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
- **NHI-01 cannot fire from IdP discovery alone.** It needs `human_in_loop`,
  and no directory API reports whether a vendor's agent asks before it acts —
  Okta, Entra and the rest return identities and scopes, not the vendor
  product's approval setting. Live discovery therefore gets you as far as an
  NHI-01 *gap* naming the missing field; `vra enrich <slug>` (or a vendor probe
  that reads the product's own tenant settings) is what turns it into a
  critical. The tool will not guess the field from a display name.

---

## Repository

```
vra.py                  entry point — connect / monitor / report / cip
cip_controls.yaml       30 CIP-* controls — the NERC set (NERC only). THE PRODUCT.
nhi_controls.yaml       7 NHI-* controls — trimmed identity companion (800-53 + SOC 2)
controls.yaml           4 AIV-* controls — trimmed feature companion (800-53 + SOC 2)
vendors/*.yaml          YOUR registers (gitignored) — `vra connect` writes here
sandbox/registers/      the three demo registers that ship with the repo
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
src/vra/cip.py          NERC assessment over the estate
src/vra/cipcrypto.py    real Ed25519 + SHA-256 firmware verification
src/vra/grid.py         the simulated substation estate
src/vra/gridbuild.py    fixture builder — signs the firmware, plants the compromise
src/vra/evidence.py     CIP audit evidence pack (md / html / json)
src/vra/procure.py      reads vendor contracts; verifies every quote in code
src/vra/onboard_cip.py  documents -> procurement -> key -> firmware -> score
src/vra/cipcli.py       `vra.py cip` / `vra.py cip onboard`
sandbox/procurement/    contract documents for the vendor onboarding demo
sandbox/grid/           signing keys, packages, signed firmware images
VALIDATION.md           including every defect found
VALIDATION-CIP.md       what the NERC module proves, and what it does not
DEMO-CIP.md             career-fair script for the NERC demo
docs/ARCHITECTURE-CIP-BRIEF.md   the decision record behind the module
```
