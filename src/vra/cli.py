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
from pathlib import Path

from .config import DEFAULT_OUT_DIR, RunConfig
from . import analyst, evaluate as ev, report as rp
from .llm import get_backend, probe_ollama
from .observe import observe_vendor
from .probe import run_probe
from .register import FindingStore, load_vendors, update_vendor_state
from .triage import triage_diff, write_pending_review
from .watch import watch_vendor


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
    p.add_argument("--model", default=None, help="Ollama model tag (default: $VRA_MODEL or llama3.1:8b)")
    p.add_argument("--offline", action="store_true",
                   help="no network at all: use the deterministic heuristic backend instead of Ollama")
    p.add_argument("--dry-run", action="store_true",
                   help="assess and print, but persist nothing (no snapshots, findings, or report files)")
    p.add_argument("--no-probe", action="store_true", help="skip all in-tenant probes")
    p.add_argument("--no-fail", action="store_true",
                   help="always exit 0, even with open critical findings")
    return p


def run(cfg: RunConfig) -> int:
    vendors = load_vendors(cfg)
    if not vendors:
        print("No vendors matched. Check vendors/ and --vendor filters.", file=sys.stderr)
        return 2

    controls = ev.load_controls()
    store = FindingStore()

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

    print(f"vra: assessing {len(vendors)} vendor(s), snapshot set '{cfg.snapshot_version}', "
          f"backend '{backend_name}'{' [dry-run]' if cfg.dry_run else ''}")

    all_findings: list[dict] = []
    all_gaps: list[dict] = []
    all_triages: list[dict] = []
    all_probes: list[dict] = []
    new_ids: set[str] = set()
    seen_ids: set[str] = set()

    for vendor in vendors:
        slug = vendor["slug"]
        print(f"  - {vendor['vendor']}: ", end="", flush=True)

        # -- Phase 2: watch ------------------------------------------------
        snaps, diffs = watch_vendor(vendor, cfg)
        for snap in snaps:
            if snap.error:
                print(f"\n      ! {snap.source}: {snap.error}", file=sys.stderr)

        # -- Phase 3: triage -----------------------------------------------
        triage_results = []
        evidence_by_field: dict[str, list[dict]] = {}
        for diff in diffs:
            if not diff.changed:
                all_triages.append({
                    "vendor": slug, "vendor_name": vendor["vendor"], "source": diff.source,
                    "changed": False, "is_baseline": diff.is_baseline, "ai_relevant": False,
                    "change_type": "none", "summary": "", "confidence": 0.0,
                    "old_hash": diff.old_hash, "new_hash": diff.new_hash,
                    "added": 0, "removed": 0, "evidence_excerpt": "",
                    "affected_fields": [], "proposed_surface_update": {},
                })
                continue

            tr = triage_diff(vendor, diff, cfg)
            triage_results.append(tr)
            all_triages.append({
                "vendor": slug, "vendor_name": vendor["vendor"], "source": tr.source,
                "changed": True, "is_baseline": False, "ai_relevant": tr.ai_relevant,
                "change_type": tr.change_type, "summary": tr.summary, "confidence": tr.confidence,
                "old_hash": diff.old_hash, "new_hash": diff.new_hash,
                "added": len(diff.added_lines), "removed": len(diff.removed_lines),
                "evidence_excerpt": tr.evidence_excerpt,
                "affected_fields": tr.affected_fields,
                "proposed_surface_update": tr.proposed_surface_update,
                "error": tr.error,
            })
            if tr.ai_relevant:
                for fld in tr.affected_fields or ["_general"]:
                    evidence_by_field.setdefault(fld, []).append(
                        {"source": tr.source, "excerpt": tr.evidence_excerpt,
                         "change_type": tr.change_type, "confidence": tr.confidence}
                    )

        pending = write_pending_review(vendor, triage_results, cfg)

        # -- Phase 4: probe -------------------------------------------------
        pres = run_probe(vendor, cfg)
        all_probes.append({
            "vendor": slug, "ran": pres.ran, "mode": pres.mode, "tenant": pres.tenant,
            "ai_components": pres.ai_components, "reconciliation": pres.reconciliation,
            "error": pres.error,
        })
        for r in pres.reconciliation:
            evidence_by_field.setdefault(r["surface_field"], []).append(
                {"source": "in_tenant_probe", "excerpt": r["detail"], "change_type": r["type"],
                 "confidence": 1.0}
            )

        # -- Deterministic observation overlay ------------------------------
        # Structured fact parsed from artifacts and the tenant API. Unlike model
        # proposals, these can drive findings because they are quotable.
        observed = observe_vendor(vendor, snaps, pres)
        for sp in observed.uncovered_ai_subprocessors:
            evidence_by_field.setdefault("subprocessor", []).append(
                {"source": "subprocessors", "excerpt": sp.raw_line,
                 "change_type": "uncovered_ai_subprocessor", "confidence": 1.0}
            )

        # -- Phase 5: deterministic control evaluation ----------------------
        findings, gaps = ev.evaluate_vendor(vendor, controls, observed)

        for assessment in findings + gaps:
            evidence: list[dict] = []
            for fld in assessment.observed:
                evidence.extend(evidence_by_field.get(fld.replace("contract.", ""), []))
            for meta in assessment.provenance.values():
                evidence.append({
                    "source": meta["provenance"], "excerpt": meta["evidence"],
                    "change_type": "deterministic_observation", "confidence": 1.0,
                })
            # de-duplicate by (source, excerpt)
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

        update_vendor_state(vendor, hashes={s.source: s.sha256 for s in snaps if not s.error}, cfg=cfg)

        changed_n = len([d for d in diffs if d.changed])
        relevant_n = len([t for t in triage_results if t.ai_relevant])
        print(f"{changed_n} source(s) changed, {relevant_n} AI-relevant, "
              f"{len(findings)} finding(s), {len(gaps)} gap(s)"
              + (f", proposals -> {pending.name}" if pending else ""))

    # -- Phase 7: lifecycle reconciliation ---------------------------------
    closed = store.reconcile(seen_ids, {v["slug"] for v in vendors}, cfg)

    ctx = {
        "vendors": vendors, "findings": all_findings, "gaps": all_gaps,
        "triages": all_triages, "probes": all_probes, "new_ids": new_ids,
        "closed": closed, "store": store, "backend": backend_name,
    }

    text = rp.build_report(ctx, cfg)
    path = rp.write_report(text, ctx, cfg)
    store.save(cfg)

    # -- console summary ----------------------------------------------------
    open_findings = [f for f in all_findings if f.get("state") not in ("closed",)]
    crit = [f for f in open_findings if f["severity"] == "critical"]
    high = [f for f in open_findings if f["severity"] == "high"]
    ai_changes = [t for t in all_triages if t.get("ai_relevant")]

    print()
    print("=" * 68)
    print(f"  Vendors assessed     : {len(vendors)}")
    print(f"  AI-relevant changes  : {len(ai_changes)}")
    print(f"  Open findings        : {len(open_findings)}  "
          f"(critical {len(crit)}, high {len(high)})")
    print(f"  New this run         : {len(new_ids)}")
    print(f"  Information gaps     : {len(all_gaps)}")
    print(f"  Closed this run      : {len(closed)}")
    print(f"  Report               : {path if path else '(dry-run, not written)'}")
    print("=" * 68)
    for f in sorted(crit, key=lambda x: x["vendor"]):
        marker = "NEW " if f["id"] in new_ids else "    "
        print(f"  {marker}CRITICAL {f['control_id']}  {f['vendor_name']} — {f['feature']}")
    print()

    if crit and cfg.fail_on_critical:
        return 1
    return 0


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
