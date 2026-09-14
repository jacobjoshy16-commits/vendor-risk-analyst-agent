"""Per-vendor collect with a bounded worker pool and failure isolation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import evaluate as ev
from .config import RunConfig
from .nhi import discover_nhis
from .observe import observe_vendor
from .pool import map_isolated, worker_count
from .probe import run_probe
from .triage import triage_diff, write_pending_review
from .watch import watch_vendor


@dataclass
class VendorWork:
    """Per-vendor collect result. Errors stay on the item — they do not abort the cycle."""

    slug: str
    vendor: dict
    error: str | None = None
    probe_failed: bool = False
    probe_error: str | None = None
    snaps: list = field(default_factory=list)
    diffs: list = field(default_factory=list)
    triage_results: list = field(default_factory=list)
    all_triages: list = field(default_factory=list)
    evidence_by_field: dict = field(default_factory=dict)
    pending: Any = None
    pres: Any = None
    probe_row: dict = field(default_factory=dict)
    observed: Any = None
    parse_row: dict = field(default_factory=dict)
    discovered: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    log_line: str = ""
    notes: list[str] = field(default_factory=list)


def evidence_from_triage(tr) -> tuple[list[tuple[str, dict]], str | None]:
    """Evidence rows a triage result may contribute, and any note to log.

    A finding's evidence block is quoted material: lines from the vendor's own
    artifact or fields from the tenant API. A model excerpt earns a place there
    only by being checked against the diff it was drawn from — otherwise it is
    the model's prose wearing the artifact's name, which is how a fabricated
    quote ends up displacing a real one under a heading promising verbatim.
    """
    if not tr.ai_relevant:
        return [], None
    if not tr.excerpt_verified:
        return [], (
            f"{tr.source}: model evidence_excerpt is not a line in the diff; "
            "dropped from evidence (the text is kept in pending_review/)"
        )
    row = {
        "source": tr.source,
        "excerpt": tr.evidence_excerpt,
        "change_type": tr.change_type,
        "confidence": tr.confidence,
        "quoted": True,
    }
    return [(fld, dict(row)) for fld in (tr.affected_fields or ["_general"])], None


def collect_vendor(vendor: dict, cfg: RunConfig, portfolio: list[dict], controls) -> VendorWork:
    """Watch + triage + probe + evaluate AIV-* for one vendor. Never raises."""
    slug = vendor["slug"]
    work = VendorWork(slug=slug, vendor=vendor)
    try:
        snaps, diffs = watch_vendor(vendor, cfg)
        work.snaps, work.diffs = snaps, diffs
        for snap in snaps:
            if snap.error:
                work.notes.append(f"{snap.source}: {snap.error}")

        triage_results = []
        evidence_by_field: dict[str, list[dict]] = {}
        for diff in diffs:
            if not diff.changed:
                work.all_triages.append({
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
            work.all_triages.append({
                "vendor": slug, "vendor_name": vendor["vendor"], "source": tr.source,
                "changed": True, "is_baseline": False, "ai_relevant": tr.ai_relevant,
                "change_type": tr.change_type, "summary": tr.summary, "confidence": tr.confidence,
                "old_hash": diff.old_hash, "new_hash": diff.new_hash,
                "added": len(diff.added_lines), "removed": len(diff.removed_lines),
                "evidence_excerpt": tr.evidence_excerpt,
                "excerpt_verified": tr.excerpt_verified,
                "affected_fields": tr.affected_fields,
                "proposed_surface_update": tr.proposed_surface_update,
                "error": tr.error,
            })
            rows, note = evidence_from_triage(tr)
            if note:
                work.notes.append(note)
            for fld, row in rows:
                evidence_by_field.setdefault(fld, []).append(row)
        work.triage_results = triage_results
        work.evidence_by_field = evidence_by_field
        work.pending = write_pending_review(vendor, triage_results, cfg)

        pres = run_probe(vendor, cfg)
        work.pres = pres
        work.probe_row = {
            "vendor": slug, "ran": pres.ran, "mode": pres.mode, "tenant": pres.tenant,
            "ai_components": pres.ai_components, "nhis": pres.nhis,
            "reconciliation": pres.reconciliation, "error": pres.error,
            "provider": pres.provider, "pages_fetched": pres.pages_fetched,
            "resource_counts": pres.resource_counts, "truncated": pres.truncated,
        }
        for r in pres.reconciliation:
            evidence_by_field.setdefault(r["surface_field"], []).append(
                {"source": "in_tenant_probe", "excerpt": r["detail"], "change_type": r["type"],
                 "confidence": 1.0}
            )

        observed = observe_vendor(vendor, snaps, pres)
        work.observed = observed
        ps = observed.subprocessor_parse
        work.parse_row = {
            "vendor": slug, "vendor_name": vendor["vendor"],
            "source": "subprocessors",
            "status": ps.status if ps is not None else "not_attempted",
            "platform": ps.platform if ps is not None else None,
            "rows": ps.rows if ps is not None else 0,
            "reason": ps.reason if ps is not None else "",
        }
        if ps is not None and not ps.assessable:
            work.notes.append(
                f"AIV-03 not assessable for {slug}: subprocessor parse [{ps.status}] — {ps.reason}"
            )
        for sp in observed.uncovered_ai_subprocessors:
            evidence_by_field.setdefault("subprocessor", []).append(
                {"source": "subprocessors", "excerpt": sp.raw_line,
                 "change_type": "uncovered_ai_subprocessor", "confidence": 1.0}
            )

        discovered = discover_nhis(vendor, pres, portfolio=portfolio)
        work.discovered = discovered
        if (vendor.get("probe") or {}).get("enabled") and not pres.ran:
            work.probe_failed = True
            work.probe_error = pres.error or "the configured tenant probe did not run"
            work.notes.append(f"probe did not run: {work.probe_error}")

        findings, gaps = ev.evaluate_vendor(vendor, controls, observed)
        work.findings, work.gaps = findings, gaps
        changed_n = len([d for d in diffs if d.changed])
        relevant_n = len([t for t in triage_results if t.ai_relevant])
        work.log_line = (
            f"{changed_n} source(s) changed, {relevant_n} AI-relevant, "
            f"{len(findings)} finding(s), {len(gaps)} gap(s), "
            f"{len(discovered)} NHI(s)"
            + (f", proposals -> {work.pending.name}" if work.pending else "")
        )
    except Exception as exc:
        work.error = f"{type(exc).__name__}: {exc}"
        work.probe_failed = True
        work.log_line = f"FAILED — {work.error}"
        work.notes.append(work.error)
    return work


def collect_all(vendors: list[dict], cfg: RunConfig, portfolio: list[dict], controls) -> list[VendorWork]:
    """Poll every vendor with a bounded worker pool. One failure does not abort the rest."""
    workers = worker_count(cfg)
    return map_isolated(
        lambda v: collect_vendor(v, cfg, portfolio, controls),
        vendors,
        workers=workers,
        on_error=lambda v, exc: VendorWork(
            slug=v.get("slug") or "?",
            vendor=v,
            error=f"{type(exc).__name__}: {exc}",
            probe_failed=True,
            log_line=f"FAILED — {type(exc).__name__}: {exc}",
            notes=[f"{type(exc).__name__}: {exc}"],
        ),
    )
