# Demo recording notes

Target: 3–4 minutes. The point to land is **the tool caught a change nobody announced**, and it did so
with an auditable citation rather than a model's opinion.

Reset before recording:

```bash
rm -rf data out pending_review
```

---

## Beat 1 — the problem (20s, no terminal)

> "We review vendors annually. Their AI features ship weekly. Between reviews, a vendor can turn a
> suggestion engine into an agent that writes to our identity directory, or quietly add a model provider
> to their subprocessor list that isn't covered by our BAA. Nobody sends a notice. The next time anyone
> looks is eleven months later."

## Beat 2 — the register (25s)

Show `vendors/aegis-identity-cloud.yaml`. Scroll the `ai_surface` block.

> "Each vendor gets a register of its AI surface — what the feature is, whether it acts or suggests,
> whose model is behind it, retention, whether a human is in the loop."

Point at a field set to `unknown`:

> "Unknown is not a failure. It's a question we haven't gotten an answer to. The tool tracks those
> separately and drafts the email that asks."

## Beat 3 — baseline (20s)

```bash
python3 vra.py --offline --snapshot v1
```

> "First run establishes the baseline. Ten findings from the register itself, twelve open questions,
> **zero criticals**. Remember that number."

## Beat 4 — the change run (40s) — the money shot

```bash
python3 vra.py --offline --snapshot v2
```

Let the two red lines land, then read them:

```
NEW CRITICAL AIV-07  Aegis Identity Cloud — Access Copilot
NEW CRITICAL AIV-03  Loop Workspace — Loop Assist
```

```bash
echo $?    # 1
```

> "Exit code 1. This can gate a pipeline or page someone."

## Beat 5 — the buried row (45s) — the part that sells it

Open `out/latest.md`, jump to the Loop Workspace AIV-03 finding.

> "The second one is the interesting one. Loop's changelog said nothing. The change was one row added to
> a subprocessor table — row six of nine, sitting between Anthropic and Intercom."

Show the evidence block:

```
Perplexity AI, Inc. | Retrieval and answer generation for Assist Answers (beta) | US | Pending
```

> "New model provider, processing customer data, BAA status *Pending*. Pending is not executed. That's a
> critical BAA-scope finding, and the tool quotes the exact line it came from — provenance
> `parsed_artifact:subprocessors`. This isn't a model's summary. It's the row."

Scroll to the drafted outreach email and the POA&M row.

> "Finding narrative, the email to send the vendor, and the POA&M row with a due date — seven days, from
> the severity table, not from a model."

## Beat 6 — the negative control (30s)

> "Third vendor also changed in this run — release notes, a marketing line, some wording churn."

Point at the Meridian line: `2 source(s) changed, 0 AI-relevant`.

> "Zero AI-relevant. Same five findings as baseline, nothing new. A tool that flags everything gets
> ignored by week three, so the sandbox has a vendor whose only job is to produce nothing."

## Beat 7 — where the model sits (30s)

Open `pending_review/loop-workspace-*.json`.

> "The model read the diff and proposed a register update. That proposal is quarantined here for a human
> to accept. It did not create the finding."

> "Control logic and severity are deterministic, from `controls.yaml`. The model reads unstructured vendor
> text and drafts language. It never decides whether something is a finding or how bad it is. Both
> criticals came from parsed artifacts and a tenant API probe — facts you can quote back to the vendor."

## Beat 7b — onboarding (30s, optional if time allows)

Show `python3 vra.py webui`, or the CLI:

```bash
python3 vra.py onboard "Acme Corp" --trust-center https://acme.safebase.io --offline
```

> "How does a new vendor get in? Before this it was hand-writing YAML and guessing URLs. Now you give
> it a name and a trust-center link, it detects the platform — SafeBase, Whistic, Vanta, a PDF —
> tries the subprocessor parse on day one, and either AIV-03 has coverage immediately or the
> click-through NDA is recorded as a blocker with the access-request email already drafted."

Land the point from review: *"the parser that AIV-03 depends on must survive real trust centers,
not pipe-delimited sandbox fixtures."*

## Beat 7c — leave it running (20s, optional)

```bash
python3 vra.py monitor --offline --webui --interval 2m
```

> "And then you leave it. Same pipeline, on a timer, against every vendor and every non-human
> identity in the portfolio — Loop's provisioning client living in Aegis's tenant included. The
> console shows the heartbeat. A critical is a finding, not a crashed daemon."

## Beat 7d — discover the identities (20s, optional)

```bash
python3 vra.py discover --fixture sandbox/probe/idp/okta_pages.json --dry-run
```

> \"The list is not something a human typed. That is every application and API token the IdP
> returned, across every page. A hundred NHIs per human identity is a pagination problem, not
> a YAML problem.\"

## Beat 8 — honesty close (20s)

Open `VALIDATION.md`, show the scoreboard, then scroll straight to Defects.

> "Twenty-two of twenty-two on the scenario. But validation found four real bugs — including a fixture
> that made the baseline raise a false critical, and a design flaw where both planted criticals silently
> failed while every component reported success. And the scored runs used the deterministic backend, not
> a real model, so triage quality on messy real prose is still unmeasured. That's the next thing to fix."

---

## Recording notes

- Terminal at ~110 columns; the summary block is boxed and wraps badly narrower.
- `--offline` in every command so nothing waits on a model and the demo is reproducible.
- Don't skip Beat 6. Reviewers discount a tool that only ever shows itself firing.
- If time is tight, cut Beat 2, never Beat 5 or 8.
