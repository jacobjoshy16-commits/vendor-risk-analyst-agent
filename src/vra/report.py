"""Phase 7.3 — reporting.

Section order is fixed by the build guide and is not cosmetic: a compliance
reader wants the portfolio number first, then what moved, then what it means,
then what to ask, then the plan, then an honest statement of what the tool could
not see.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .config import SEVERITIES, RunConfig

SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def _sev_key(rec: dict) -> tuple[int, str]:
    return (SEV_ORDER.get(rec.get("severity", "low"), 9), rec.get("control_id", ""))


def _esc(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def build_report(ctx: dict[str, Any], cfg: RunConfig) -> str:
    now = datetime.now(timezone.utc)
    vendors = ctx["vendors"]
    findings = ctx["findings"]
    gaps = ctx["gaps"]
    triages = ctx["triages"]
    probes = ctx["probes"]
    new_ids = ctx["new_ids"]
    closed = ctx["closed"]
    store = ctx["store"]
    backend = ctx["backend"]

    open_findings = [f for f in findings if f.get("state") not in ("closed",)]
    by_sev = {s: [f for f in open_findings if f.get("severity") == s] for s in SEVERITIES}
    changed_sources = [t for t in triages if t["changed"]]
    ai_changes = [t for t in changed_sources if t["ai_relevant"]]
    feature_count = sum(len(v.get("ai_surface") or []) for v in vendors)

    L: list[str] = []
    a = L.append

    a("# Vendor AI Risk Assessment")
    a("")
    a(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M UTC')}  ")
    a(f"**Snapshot set:** `{cfg.snapshot_version}`  ")
    a(f"**Previous run:** {store.last_run or 'none — this is the baseline run'}  ")
    a(f"**Model backend:** `{backend}`" + ("  _(deterministic heuristic, not a language model)_" if backend != "ollama" else f" — model `{cfg.model}`"))
    a(f"**Mode:** {'dry-run (nothing persisted)' if cfg.dry_run else 'persisted'}"
      f"{', offline' if cfg.offline else ''}")
    a("")

    # ---------------------------------------------------------------- 1
    a("## 1. Portfolio summary")
    a("")
    nhis = ctx.get("nhis") or []
    a(f"- **Vendors assessed:** {len(vendors)}")
    a(f"- **AI features tracked:** {feature_count}")
    a(f"- **NHIs inventoried:** {len(nhis)}")
    a(f"- **Watch sources checked:** {len(triages)}")
    a(f"- **Sources changed since last run:** {len(changed_sources)}")
    a(f"- **Changes judged AI-relevant:** {len(ai_changes)}")
    a(f"- **Open findings:** {len(open_findings)} "
      f"(critical {len(by_sev['critical'])}, high {len(by_sev['high'])}, "
      f"medium {len(by_sev['medium'])}, low {len(by_sev['low'])})")
    a(f"- **New findings this run:** {len([f for f in findings if f['id'] in new_ids])}")
    a(f"- **Information gaps:** {len(gaps)}")
    a(f"- **Findings closed this run:** {len(closed)}")
    a("")
    a("| Vendor | Tier | AI features | Open findings | Critical | Gaps |")
    a("| --- | --- | --- | --- | --- | --- |")
    for v in vendors:
        vf = [f for f in open_findings if f["vendor"] == v["slug"]]
        vg = [g for g in gaps if g["vendor"] == v["slug"]]
        a(f"| {v['vendor']} | {v['tier']} | {len(v.get('ai_surface') or [])} | {len(vf)} | "
          f"{len([f for f in vf if f['severity'] == 'critical'])} | {len(vg)} |")
    a("")

    # ---------------------------------------------------------------- 2
    a("## 2. Changes detected this run")
    a("")
    if not changed_sources:
        baseline = [t for t in triages if t.get("is_baseline")]
        if baseline:
            a("_Baseline run — snapshots stored for the first time, so no prior state exists to diff "
              "against. Change detection begins on the next run._")
        else:
            a("_No watch source changed since the previous run._")
        a("")
    else:
        for t in changed_sources:
            verdict = "**AI-RELEVANT**" if t["ai_relevant"] else "not AI-relevant"
            a(f"### {t['vendor_name']} — `{t['source']}` — {verdict}")
            a("")
            a(f"- **Change type:** `{t['change_type']}`")
            a(f"- **Lines added/removed:** +{t['added']} / -{t['removed']}")
            a(f"- **Confidence:** {t['confidence']:.2f}")
            a(f"- **Hash:** `{(t['old_hash'] or 'none')[:12]}` → `{t['new_hash'][:12]}`")
            if t.get("error"):
                a(f"- **Triage error:** {t['error']}")
            a("")
            a(f"{t['summary']}")
            a("")
            if t["ai_relevant"] and t.get("evidence_excerpt"):
                a("**Evidence excerpt (verbatim from diff):**")
                a("")
                a("```")
                a(t["evidence_excerpt"])
                a("```")
                a("")
            if t["ai_relevant"] and t.get("proposed_surface_update"):
                a("**Proposed register update — NOT APPLIED, awaiting human review:**")
                a("")
                a("```json")
                a(json.dumps(t["proposed_surface_update"], indent=2))
                a("```")
                a("")

    # ---------------------------------------------------------------- 3
    a("## 3. Findings")
    a("")
    if not open_findings:
        a("_No open findings._")
        a("")
    else:
        new = sorted([f for f in open_findings if f["id"] in new_ids], key=_sev_key)
        aging = sorted([f for f in open_findings if f["id"] not in new_ids], key=_sev_key)

        if new:
            a("### 3.1 New this run")
            a("")
            for f in new:
                _emit_finding(a, f, store, is_new=True)
        if aging:
            a("### 3.2 Aging / carried forward")
            a("")
            for f in aging:
                _emit_finding(a, f, store, is_new=False)

    if closed:
        a("### 3.3 Closed this run")
        a("")
        a("| Control | Vendor | Feature | Reason |")
        a("| --- | --- | --- | --- |")
        for f in closed:
            a(f"| {f['control_id']} | {_esc(f['vendor_name'])} | {_esc(f['feature'])} | "
              f"{_esc(f.get('closure_reason', ''))} |")
        a("")

    # ---------------------------------------------------------------- 4
    a("## 4. Information gaps and drafted vendor questions")
    a("")
    a("_A gap is a field the vendor has not answered. Gaps drive outreach, not remediation, and are "
      "tracked separately from control failures._")
    a("")
    if not gaps:
        a("_No information gaps._")
        a("")
    else:
        a("| Control | Vendor | Feature | Unknown field(s) | Response by |")
        a("| --- | --- | --- | --- | --- |")
        for g in sorted(gaps, key=lambda x: (x["vendor"], x["control_id"])):
            a(f"| {g['control_id']} | {_esc(g['vendor_name'])} | {_esc(g['feature'])} | "
              f"`{', '.join(g['observed'].keys())}` | {g['due_date']} |")
        a("")
        a("<details><summary><strong>Drafted vendor outreach emails</strong> "
          f"({len(gaps)} gaps)</summary>")
        a("")
        for g in sorted(gaps, key=lambda x: (x["vendor"], x["control_id"])):
            a(f"#### {g['vendor_name']} — {g['control_id']} — {g['feature']}")
            a("")
            a(f"**Subject:** {g['outreach']['subject']}")
            a("")
            a("```text")
            a(g["outreach"]["body"])
            a("```")
            a("")
        a("</details>")
        a("")

    # ---------------------------------------------------------------- 4b
    a("## 5. Subprocessor parse coverage (AIV-03)")
    a("")
    a("_AIV-03 — every model provider named as a subprocessor and BAA-covered — can only be "
      "assessed if the subprocessor disclosure can actually be read. This table records what the "
      "tool saw, not just what it parsed._")
    a("")
    parses = ctx.get("parses") or []
    if not parses:
        a("_No vendor in scope publishes a subprocessor disclosure through a watch source._")
        a("")
    else:
        a("| Vendor | Source | Status | Platform | Rows |")
        a("| --- | --- | --- | --- | --- |")
        for p in parses:
            status = p["status"]
            mark = {"parsed": "✅ parsed", "blocked": "🚧 blocked", "empty": "⚠️ empty",
                    "error": "⛔ error", "missing": "⚠️ missing",
                    "not_attempted": "—"}.get(status, status)
            a(f"| {_esc(p['vendor_name'])} | `{p['source']}` | {mark} | "
              f"{_esc(p.get('platform') or '—')} | {p['rows']} |")
        a("")
        unparsed = [p for p in parses if p["status"] not in ("parsed", "not_attempted")]
        if unparsed:
            a("**Not assessable this run** — an AIV-03 information gap (with a drafted outreach "
              "requesting the subprocessor list or portal access) has been raised for each of these:")
            a("")
            for p in unparsed:
                a(f"- `{p['vendor_name']}` — **{p['status']}**: {p['reason']}")
            a("")

    # ---------------------------------------------------------------- 5
    probe_ran = [p for p in probes if p["ran"]]
    a("## 6. In-tenant probe")
    a("")
    if not probe_ran:
        skipped = [p for p in probes if p.get("error")]
        if skipped:
            for p in skipped:
                a(f"- `{p['vendor']}`: {p['error']}")
        else:
            a("_No vendor in scope has a probe configured. This is expected: most vendors never will._")
        a("")
    else:
        for p in probe_ran:
            a(f"### {p['vendor']} — mode `{p['mode']}`")
            a("")
            for key, val in p["tenant"].items():
                if key == "org":
                    continue
                a(f"- **{key}:** `{val}`")
            a("")
            if p["ai_components"]:
                a("| AI component | Status | Principal | Write scopes |")
                a("| --- | --- | --- | --- |")
                for c in p["ai_components"]:
                    a(f"| {_esc(c['label'])} | {c['status']} | {_esc(', '.join(c['principals']))} | "
                      f"`{', '.join(c['write_scopes']) or 'none'}` |")
                a("")
            if p["reconciliation"]:
                a("**Register reconciliation — tenant reality vs. recorded state:**")
                a("")
                for r in p["reconciliation"]:
                    a(f"- **{r['type']}** ({r['feature']}) — register says `{r['register_says']}`, "
                      f"tenant says `{r['tenant_says']}`. {r['detail']}")
                a("")
            else:
                a("_Tenant state matches the register._")
                a("")

    # ---------------------------------------------------------------- 6b
    a("## 7. Non-human identities")
    a("")
    a("_An NHI is a service account, OAuth app, agent principal, or bot a vendor "
      "runs as inside a tenant. AIV-* assesses the feature; NHI-* assesses the "
      "identity it acts as. Cross-vendor principals (vendor A's client living in "
      "vendor B's tenant) are flagged when they are not declared on the home vendor._")
    a("")
    nhis = ctx.get("nhis") or []
    if not nhis:
        a("_No non-human identities inventoried this run. Add a `nhis:` block to the "
          "vendor register, or enable a tenant probe._")
        a("")
    else:
        a("| Vendor | Identity | Kind | Principal | Write scopes | Owner | Source | Flags |")
        a("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for n in nhis:
            flags = []
            if n.get("orphan"):
                flags.append("orphan")
            if n.get("cross_vendor"):
                flags.append("cross-vendor")
            if n.get("write_scopes"):
                flags.append("write")
            writes = ", ".join(n.get("write_scopes") or []) or "none"
            a(
                f"| {_esc(n.get('vendor_name') or n.get('vendor'))} | "
                f"{_esc(n.get('name') or n.get('principal') or '—')} | "
                f"`{n.get('kind') or '—'}` | `{_esc(n.get('principal') or '—')}` | "
                f"`{_esc(writes)}` | {_esc(n.get('owner') or 'unknown')} | "
                f"{n.get('source') or '—'} | {_esc(', '.join(flags) or '—')} |"
            )
        a("")
        nhi_findings = [
            f for f in open_findings
            if str(f.get("control_id") or "").startswith("NHI-")
        ]
        if nhi_findings:
            a("**NHI control failures this run:**")
            a("")
            for f in sorted(nhi_findings, key=_sev_key):
                a(f"- `{f['severity'].upper()}` **{f['control_id']}** — "
                  f"{_esc(f['vendor_name'])} / {_esc(f['feature'])}: {f['reason']}")
            a("")

    # ---------------------------------------------------------------- 7
    a("## 8. POA&M")
    a("")
    poam_rows = sorted(
        [f for f in open_findings] + [g for g in gaps],
        key=lambda r: (SEV_ORDER.get(r.get("severity", "low"), 9), r.get("due_date", "")),
    )
    if not poam_rows:
        a("_Nothing to plan._")
        a("")
    else:
        a("| ID | Vendor | Weakness | Sev | Remediation | Compensating control | Owner | Due | Status |")
        a("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in poam_rows:
            p = r["poam"]
            overdue = " ⚠️" if store.is_overdue(r) else ""
            a(f"| {p['poam_id']} | {_esc(p['vendor'])} | {_esc(p['weakness'])[:110]} | {p['severity']} | "
              f"{_esc(p['remediation_action'])[:150]} | {_esc(p['compensating_control'])[:120]} | "
              f"{_esc(p['owner_role'])} | {p['due_date']}{overdue} | {p['status']} |")
        a("")

    # ---------------------------------------------------------------- 6
    a("## 9. Limitations")
    a("")
    a("What this report is, and what it is not:")
    a("")
    a("- **Human-entered, not observed.** Every field in the vendor register — contract status, BAA "
      "coverage, feature autonomy, retention — was entered by an analyst reading vendor documentation. "
      "The tool assesses what the register says. If the register is wrong, the assessment is wrong.")
    a("- **Public artifacts only.** Except where an in-tenant probe is configured, the tool sees what "
      "the vendor publishes. Vendors ship AI features before they document them.")
    if backend != "ollama":
        a("- **No language model was used in this run.** The `offline` backend is a deterministic "
          "keyword heuristic that returns the same JSON shape. It is adequate for pipeline testing and "
          "for the sandbox scenario; it is not a substitute for model judgement on real vendor prose.")
    else:
        a(f"- **Model-read prose.** Change triage used `{cfg.model}` locally. The model classified "
          "whether prose changes affect the AI surface; it did not decide any finding or severity. "
          "Every prompt and response is in `data/llm_audit.jsonl`.")
    a("- **Findings are deterministic.** Control failures and severities come from `controls.yaml` "
      "evaluated in code. No model output can create, suppress, or re-severity a finding.")
    a("- **Register updates are never automatic.** Proposed surface updates are written to "
      "`pending_review/` and require a human edit to take effect.")
    a("- **Unknown is not a pass.** Fields marked unknown produce information gaps, listed in section 4. "
      "A vendor with many gaps is not low risk — it is unassessed.")
    a("- **Diff-blind to unpublished change.** If a vendor changes model providers without updating any "
      "watched page, this tool will not see it.")
    a("- **Gated disclosures stop at the gate.** Subprocessor lists behind SafeBase/Whistic/Vanta "
      "click-through NDAs or login walls are reported as blocked (section 5) with a drafted outreach, "
      "not silently skipped — but the tool cannot read what it is not granted access to.")
    a("- **PDF and portal parsing are best-effort.** HTML tables and PDFs are parsed structurally; "
      "scanned PDFs, images, or tables nested inside prose still require manual review (flagged as "
      "`empty` in section 5).")
    a("- **Volatile-content stripping is heuristic.** Timestamps, session tokens, build numbers, render "
      "times and rotating banners are normalized away before hashing. A novel volatile element could "
      "still produce a false change on first encounter.")
    a("")

    return "\n".join(L) + "\n"


def _emit_finding(a, f: dict, store, *, is_new: bool) -> None:
    age = store.age_days(f)
    flags = []
    if is_new:
        flags.append("NEW")
    if store.is_overdue(f):
        flags.append("OVERDUE")
    if f.get("escalated"):
        flags.append("ESCALATED")
    flag = f" — **{' / '.join(flags)}**" if flags else ""

    a(f"#### `{f['severity'].upper()}` {f['control_id']} — {f['vendor_name']} — {f['feature']}{flag}")
    a("")
    a(f"> {f['narrative']}")
    a("")
    a(f"- **Control:** {f['control_question']}")
    a(f"- **Citation:** {f['citation']}")
    a(f"- **Observed:** " + "; ".join(f"`{k}={v}`" for k, v in f["observed"].items()))
    a(f"- **State:** `{f.get('state', 'open')}` · first seen {f.get('first_seen')} "
      f"({age} day{'s' if age != 1 else ''} old) · due {f.get('due_date')} · owner {f.get('owner')}")
    if not f.get("narrative_model_generated", True):
        a("- **Note:** narrative produced by the deterministic template (model unavailable or output rejected).")
    if f.get("evidence"):
        a("- **Evidence:**")
        for ev in f["evidence"][:3]:
            excerpt = (ev.get("excerpt") or "").strip()
            if excerpt:
                a(f"  - `{ev.get('source')}`: {excerpt[:300]}")
    a("")


def write_report(text: str, ctx: dict, cfg: RunConfig) -> Path | None:
    if cfg.dry_run:
        return None
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = cfg.out_dir / f"vendor-ai-risk-{stamp}.md"
    path.write_text(text, encoding="utf-8")
    latest = cfg.out_dir / "latest.md"
    latest.write_text(text, encoding="utf-8")

    # Machine-readable sidecar for downstream GRC tooling.
    json_path = cfg.out_dir / "latest.json"
    json_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "snapshot_version": cfg.snapshot_version,
                "backend": ctx["backend"],
                "findings": ctx["findings"],
                "gaps": ctx["gaps"],
                "changes": ctx["triages"],
                "probes": ctx["probes"],
                "subprocessor_parses": ctx.get("parses", []),
                "nhis": ctx.get("nhis", []),
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return path
