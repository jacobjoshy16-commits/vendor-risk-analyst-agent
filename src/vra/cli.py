"""Command-line entry point — orchestrates one analyst run.

Pipeline per run:
    load register -> watch & diff -> triage diffs (model) -> probe tenant
    -> evaluate controls (deterministic) -> draft narratives (model)
    -> reconcile finding lifecycle -> report

Exit codes:
    0  clean
    1  at least one open critical finding (Phase 7.4)
    2  run error
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import DEFAULT_OUT_DIR, RunConfig
from . import analyst, evaluate as ev, report as rp
from .llm import get_backend, probe_ollama
from .nhi import (
    NHIInventory,
    assessments_to_records,
    discover_nhis,
    evaluate_nhis,
    link_cross_plane,
    load_nhi_controls,
)
from .register import FindingStore, load_vendors, update_vendor_state


@dataclass
class RunResult:
    """Structured outcome of one assessment pass. Used by the monitor daemon."""

    exit_code: int = 0
    vendor_count: int = 0
    feature_count: int = 0
    nhi_count: int = 0
    changed_sources: int = 0
    ai_relevant: int = 0
    open_findings: int = 0
    critical: int = 0
    new_findings: int = 0
    gaps: int = 0
    nhi_findings: int = 0
    nhi_gaps: int = 0
    closed: int = 0
    backend: str = ""
    error: str | None = None
    report_path: str | None = None
    vendors: list[str] = field(default_factory=list)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra",
        description="Local Vendor AI Risk Analyst — track, assess, and draft on vendor AI surface change.",
    )
    p.add_argument("--snapshot", default="v1", dest="snapshot_version",
                   help="sandbox snapshot set to read ({version} in watch paths). Default: v1")
    p.add_argument("--vendor", action="append", default=[], dest="vendors",
                   help="limit the run to a vendor slug (repeatable)")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR, help="report output directory")
    p.add_argument("--model", default=None,
                   help="Ollama model tag (default: $VRA_MODEL or qwen2.5:7b-instruct)")
    p.add_argument("--offline", action="store_true",
                   help="no network at all: use the deterministic heuristic backend instead of Ollama")
    p.add_argument("--dry-run", action="store_true",
                   help="assess and print, but persist nothing (no snapshots, findings, or report files)")
    p.add_argument("--no-probe", action="store_true", help="skip all in-tenant probes")
    p.add_argument("--no-fail", action="store_true",
                   help="always exit 0, even with open critical findings")
    p.add_argument("--allow-env-creds", action="store_true",
                   help="CI only: read tokens from the environment if the keychain is empty")
    return p


def run(cfg: RunConfig) -> int:
    return assess(cfg).exit_code


def assess(cfg: RunConfig) -> RunResult:
    result = RunResult()
    vendors = load_vendors(cfg)
    if not vendors:
        print("No vendors matched. Check vendors/ and --vendor filters.", file=sys.stderr)
        result.exit_code = 2
        result.error = "no vendors matched"
        return result

    # Full portfolio (unfiltered) so cross-vendor NHI declarations resolve
    # even when this run is scoped to one vendor.
    portfolio = load_vendors(RunConfig())
    controls = ev.load_controls()
    nhi_controls = load_nhi_controls()
    store = FindingStore()
    inventory = NHIInventory()

    backend = get_backend(cfg)
    backend_name = backend.name
    if backend_name == "ollama" and not probe_ollama(cfg):
        print(
            f"! Ollama not reachable at {cfg.ollama_host} (or model '{cfg.model}' not pulled).\n"
            f"  Falling back to the deterministic offline heuristic. Run with --offline to silence "
            f"this, or start Ollama and `ollama pull {cfg.model}`.",
            file=sys.stderr,
        )
        cfg.offline = True
        backend_name = get_backend(cfg).name

    from .pool import worker_count

    workers = worker_count(cfg)
    print(f"vra: assessing {len(vendors)} vendor(s), snapshot set '{cfg.snapshot_version}', "
          f"backend '{backend_name}', workers {workers}"
          f"{' [dry-run]' if cfg.dry_run else ''}")

    all_findings: list[dict] = []
    all_gaps: list[dict] = []
    all_triages: list[dict] = []
    all_probes: list[dict] = []
    all_parses: list[dict] = []
    all_nhis: list[dict] = []
    new_ids: set[str] = set()
    seen_ids: set[str] = set()
    nhi_finding_n = 0
    nhi_gap_n = 0
    discovered_by_vendor: dict[str, list[dict]] = {}
    probe_failed: set[str] = set()

    from .collect import collect_all

    works = collect_all(vendors, cfg, portfolio, controls)
    for work in works:
        slug = work.slug
        vendor = work.vendor
        print(f"  - {vendor.get('vendor', slug)}: {work.log_line}", flush=True)
        for note in work.notes:
            print(f"      ! {note}", file=sys.stderr)
        all_triages.extend(work.all_triages)
        all_probes.append(work.probe_row or {
            "vendor": slug, "ran": False, "mode": "none", "tenant": {},
            "ai_components": [], "nhis": [], "reconciliation": [],
            "error": work.error, "provider": None, "pages_fetched": 0,
            "resource_counts": {}, "truncated": False,
        })
        if work.parse_row:
            all_parses.append(work.parse_row)
        discovered_by_vendor[slug] = work.discovered
        if work.probe_failed or work.error:
            probe_failed.add(slug)

        for assessment in work.findings + work.gaps:
            evidence: list[dict] = []
            for fld in assessment.observed:
                evidence.extend(work.evidence_by_field.get(fld.replace("contract.", ""), []))
            for meta in assessment.provenance.values():
                evidence.append({
                    "source": meta["provenance"], "excerpt": meta["evidence"],
                    "change_type": "deterministic_observation", "confidence": 1.0,
                })
            seen_ev, uniq = set(), []
            for e in evidence:
                key = (e["source"], e["excerpt"][:80])
                if key not in seen_ev:
                    seen_ev.add(key)
                    uniq.append(e)

            record = ev.to_record(assessment, evidence=uniq)
            record = analyst.enrich(record, cfg)
            stored, is_new = store.upsert(record)
            stored["poam"] = analyst.build_poam(stored)
            seen_ids.add(stored["id"])
            if is_new:
                new_ids.add(stored["id"])
            (all_findings if assessment.kind == "finding" else all_gaps).append(stored)

        if work.snaps:
            update_vendor_state(
                vendor,
                hashes={s.source: s.sha256 for s in work.snaps if not s.error},
                cfg=cfg,
            )

    # -- NHI evaluate after every plane has been collected ------------------
    link_cross_plane(discovered_by_vendor)
    for vendor in vendors:
        slug = vendor["slug"]
        discovered = discovered_by_vendor.get(slug) or []
        if slug in probe_failed:
            stored_nhis = inventory.for_vendor(slug)
            all_nhis.extend(stored_nhis)
            for rec in store.findings.values():
                if rec.get("vendor") == slug and rec.get("family") == "nhi" and rec.get("state") != "closed":
                    seen_ids.add(rec["id"])
            continue
        stored_nhis, entitlement_events = inventory.upsert_many(slug, discovered)
        all_nhis.extend(stored_nhis)
        for change_ev in entitlement_events:
            store.record_event(change_ev)
            if change_ev.get("gained_write_scope"):
                print(
                    f"\n      ! entitlement change {change_ev.get('nhi_name')}: "
                    f"gained write scope(s) {', '.join(change_ev.get('added_scopes') or [])}",
                    file=sys.stderr,
                )
        nhi_findings_a, nhi_gaps_a = evaluate_nhis(vendor, discovered, nhi_controls)
        nhi_f_recs, nhi_g_recs = assessments_to_records(
            nhi_findings_a,
            nhi_gaps_a,
            evidence_by_subject={
                str(n.get("principal") or n.get("id") or ""): (
                    [{"source": "in_tenant_probe", "excerpt": n.get("evidence") or "",
                      "change_type": "nhi_observation", "confidence": 1.0}]
                    if n.get("evidence") else []
                )
                for n in discovered
            },
        )
        nhi_finding_n += len(nhi_f_recs)
        nhi_gap_n += len(nhi_g_recs)
        for rec in nhi_f_recs + nhi_g_recs:
            rec = analyst.enrich(rec, cfg)
            stored, is_new = store.upsert(rec)
            stored["poam"] = analyst.build_poam(stored)
            seen_ids.add(stored["id"])
            if is_new:
                new_ids.add(stored["id"])
            (all_findings if rec["kind"] == "finding" else all_gaps).append(stored)

    # -- Phase 7: lifecycle reconciliation ---------------------------------
    closed = store.reconcile(seen_ids, {v["slug"] for v in vendors}, cfg)

    from .portfolio import build_portfolio

    ctx = {
        "vendors": vendors, "findings": all_findings, "gaps": all_gaps,
        "triages": all_triages, "probes": all_probes, "parses": all_parses,
        "nhis": all_nhis, "new_ids": new_ids, "closed": closed, "store": store,
        "backend": backend_name, "events": store.events,
        "portfolio": build_portfolio(inventory, store),
    }

    text = rp.build_report(ctx, cfg)
    path = rp.write_report(text, ctx, cfg)
    store.save(cfg)
    inventory.save(cfg)

    # -- console summary ----------------------------------------------------
    open_findings = [f for f in all_findings if f.get("state") not in ("closed",)]
    crit = [f for f in open_findings if f["severity"] == "critical"]
    high = [f for f in open_findings if f["severity"] == "high"]
    ai_changes = [t for t in all_triages if t.get("ai_relevant")]

    print()
    print("=" * 68)
    print(f"  Vendors assessed     : {len(vendors)}")
    print(f"  NHIs inventoried     : {len(all_nhis)}")
    print(f"  AI-relevant changes  : {len(ai_changes)}")
    print(f"  Open findings        : {len(open_findings)}  "
          f"(critical {len(crit)}, high {len(high)})")
    print(f"  New this run         : {len(new_ids)}")
    print(f"  Information gaps     : {len(all_gaps)}")
    print(f"  NHI findings / gaps  : {nhi_finding_n} / {nhi_gap_n}")
    print(f"  Closed this run      : {len(closed)}")
    print(f"  Report               : {path if path else '(dry-run, not written)'}")
    print("=" * 68)
    for f in sorted(crit, key=lambda x: x["vendor"]):
        marker = "NEW " if f["id"] in new_ids else "    "
        print(f"  {marker}CRITICAL {f['control_id']}  {f['vendor_name']} — {f['feature']}")
    print()

    result.exit_code = 1 if (crit and cfg.fail_on_critical) else 0
    result.vendor_count = len(vendors)
    result.feature_count = sum(len(v.get("ai_surface") or []) for v in vendors)
    result.nhi_count = len(all_nhis)
    result.changed_sources = len([t for t in all_triages if t.get("changed")])
    result.ai_relevant = len(ai_changes)
    result.open_findings = len(open_findings)
    result.critical = len(crit)
    result.new_findings = len(new_ids)
    result.gaps = len(all_gaps)
    result.nhi_findings = nhi_finding_n
    result.nhi_gaps = nhi_gap_n
    result.closed = len(closed)
    result.backend = backend_name
    result.report_path = str(path) if path else None
    result.vendors = [v["slug"] for v in vendors]
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = RunConfig(
        snapshot_version=args.snapshot_version,
        offline=args.offline,
        dry_run=args.dry_run,
        out_dir=args.out,
        vendors=args.vendors,
        no_probe=args.no_probe,
        fail_on_critical=not args.no_fail,
        allow_env_creds=args.allow_env_creds,
    )
    if args.model:
        cfg.model = args.model
    try:
        return run(cfg)
    except Exception as exc:
        print(f"vra: run failed: {exc}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
