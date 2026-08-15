"""Portfolio view — one page for ~20 vendors / ~60 NHIs.

Per-vendor markdown does not scan at this size. This rollup is counts
only: it does not invent findings or severities.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .config import DATA_DIR, FINDINGS_FILE, NHI_FILE, SEVERITIES
from .nhi import NHIInventory
from .register import FindingStore


def build_portfolio(
    inventory: NHIInventory | None = None,
    store: FindingStore | None = None,
) -> dict[str, Any]:
    inventory = inventory or NHIInventory()
    store = store or FindingStore()
    rows = inventory.all()
    by_vendor: dict[str, dict[str, Any]] = {}
    kinds: Counter[str] = Counter()
    write_n = 0
    orphan_n = 0
    for row in rows:
        slug = row.get("vendor") or "?"
        slot = by_vendor.setdefault(slug, {
            "vendor": slug,
            "vendor_name": row.get("vendor_name") or slug,
            "count": 0,
            "write": 0,
            "orphans": 0,
            "kinds": Counter(),
        })
        slot["count"] += 1
        kind = row.get("kind") or row.get("type") or "?"
        slot["kinds"][kind] += 1
        kinds[kind] += 1
        if row.get("write_scopes"):
            slot["write"] += 1
            write_n += 1
        if row.get("orphan"):
            slot["orphans"] += 1
            orphan_n += 1

    open_findings = [
        f for f in store.findings.values()
        if f.get("kind") != "gap" and f.get("state") not in ("closed",)
    ]
    gaps = [
        f for f in store.findings.values()
        if f.get("kind") == "gap" and f.get("state") != "closed"
    ]
    by_sev = {s: 0 for s in SEVERITIES}
    for rec in open_findings:
        sev = rec.get("severity") or "low"
        if sev in by_sev:
            by_sev[sev] += 1

    now_keys = {r["key"] for r in rows}
    prev_keys = set(inventory.meta.get("previous_keys") or inventory.meta.get("keys") or now_keys)
    new_nhis = sorted(now_keys - prev_keys)
    gone_nhis = sorted(prev_keys - now_keys)
    events = [e for e in (store.events or []) if e.get("kind") == "entitlement_change"]
    gained = [e for e in events if e.get("gained_write_scope")]

    return {
        "vendors": len(by_vendor),
        "nhis": len(rows),
        "write": write_n,
        "orphans": orphan_n,
        "kinds": dict(kinds),
        "by_vendor": [
            {
                **{k: v for k, v in slot.items() if k != "kinds"},
                "kinds": dict(slot["kinds"]),
            }
            for slot in sorted(by_vendor.values(), key=lambda s: (-s["count"], s["vendor"]))
        ],
        "open_findings": len(open_findings),
        "by_severity": by_sev,
        "gaps": len(gaps),
        "new_since_last": new_nhis,
        "gone_since_last": gone_nhis,
        "entitlement_changes": len(events),
        "gained_write_scope": len(gained),
    }


def format_portfolio(blob: dict[str, Any]) -> list[str]:
    lines = [
        "Portfolio",
        f"  Vendors    : {blob.get('vendors', 0)}",
        f"  NHIs       : {blob.get('nhis', 0)}  "
        f"(write {blob.get('write', 0)}, orphan {blob.get('orphans', 0)})",
        f"  Findings   : {blob.get('open_findings', 0)}  "
        + ", ".join(f"{s} {blob.get('by_severity', {}).get(s, 0)}" for s in SEVERITIES),
        f"  Gaps       : {blob.get('gaps', 0)}",
    ]
    new_n = len(blob.get("new_since_last") or [])
    gone_n = len(blob.get("gone_since_last") or [])
    lines.append(
        f"  Changed    : +{new_n} new  -{gone_n} gone  "
        f"{blob.get('entitlement_changes', 0)} entitlement"
        + (f"  ({blob.get('gained_write_scope')} gained write)" if blob.get("gained_write_scope") else "")
    )
    vendors = blob.get("by_vendor") or []
    if vendors:
        lines.append("")
        lines.append(f"  {'Vendor':<28} {'NHIs':>5} {'Write':>6} {'Orphan':>7}  Kinds")
        lines.append("  " + "-" * 72)
        for slot in vendors:
            kinds = ", ".join(f"{k}={v}" for k, v in sorted((slot.get("kinds") or {}).items()))
            lines.append(
                f"  {(slot.get('vendor_name') or slot.get('vendor') or ''):<28} "
                f"{slot.get('count', 0):>5} {slot.get('write', 0):>6} "
                f"{slot.get('orphans', 0):>7}  {kinds}"
            )
    return lines


def portfolio_main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="vra portfolio",
        description="Aggregate NHI summary across every connected vendor.",
    )
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = p.parse_args(argv)
    blob = build_portfolio()
    if args.json:
        print(json.dumps(blob, indent=2, default=str))
        return 0
    print()
    for line in format_portfolio(blob):
        print(line)
    print()
    return 0


def load_from_paths(*, nhi_path: Path | None = None, findings_path: Path | None = None) -> dict[str, Any]:
    inv = NHIInventory(path=nhi_path or NHI_FILE)
    store = FindingStore(path=findings_path or FINDINGS_FILE)
    # FindingStore defaults to FINDINGS_FILE; honour a test path.
    if findings_path is not None and findings_path != FINDINGS_FILE:
        store = FindingStore(path=findings_path)
    _ = DATA_DIR
    return build_portfolio(inv, store)
