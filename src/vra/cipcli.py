"""`vra.py cip` — run the NERC CIP assessment over the simulated estate.

    python3 vra.py cip                    assess and print the summary
    python3 vra.py cip --evidence         also write the audit evidence pack
    python3 vra.py cip --substations 25   smaller estate for a screen demo
    python3 vra.py cip build-fixtures     regenerate keys, packages, firmware

Exit codes match the rest of the tool: 0 clean, 1 open critical, 2 run error.
A critical exception is a non-zero exit so this can gate a pipeline rather than
only inform a human.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import date
from pathlib import Path

from .cip import (assess_estate, cip_citation, citation_status, citations_verified,
                  load_cip_controls, rollup)
from .config import CIP_CONTROLS_FILE, DEFAULT_OUT_DIR, GRID_DIR, GRID_SUBSTATIONS
from .grid import load_estate

BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
DIM = "\033[2m"
OFF = "\033[0m"


def _c(text: str, colour: str, enabled: bool) -> str:
    return f"{colour}{text}{OFF}" if enabled else text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra.py cip",
        description="NERC CIP assessment over the simulated substation estate",
    )
    p.add_argument("action", nargs="?", default="run",
                   choices=["run", "build-fixtures", "onboard"])
    p.add_argument("--vendor", default=None, help="onboard: vendor name")
    p.add_argument("--docs", type=Path, default=None,
                   help="onboard: directory of vendor contract documents")
    p.add_argument("--impact", default="high", choices=["high", "medium", "low"],
                   help="onboard: impact rating of the systems this vendor supplies")
    p.add_argument("--offline", action="store_true",
                   help="onboard: use the deterministic extractor, no model")
    p.add_argument("--substations", type=int, default=GRID_SUBSTATIONS,
                   help=f"estate size (default {GRID_SUBSTATIONS})")
    p.add_argument("--grid-dir", type=Path, default=GRID_DIR)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR / "cip")
    p.add_argument("--evidence", action="store_true", help="write the audit evidence pack")
    p.add_argument("--controls", type=Path, default=CIP_CONTROLS_FILE)
    p.add_argument("--seed", type=int, default=20260920)
    p.add_argument("--date", dest="as_of", default=None,
                   help="assessment date (YYYY-MM-DD), for reproducible runs")
    p.add_argument("--no-fail", action="store_true", help="always exit 0")
    p.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    colour = sys.stdout.isatty() and not args.no_color
    when = date.fromisoformat(args.as_of) if args.as_of else date.today()

    if args.action == "onboard":
        return _onboard(args, colour, when)

    if args.action == "build-fixtures":
        from .gridbuild import build

        from .gridbuild import build_onboarding

        # Deliberately not `when`: `when` defaults to today, and fixtures are
        # committed files that must not change because the calendar did.
        # Passing --date explicitly still overrides.
        fixture_date = date.fromisoformat(args.as_of) if args.as_of else None
        result = build(args.grid_dir, today=fixture_date)
        print(f"{_c('✓', GREEN, colour)} regenerated sandbox estate in {args.grid_dir}")
        for k, v in result.items():
            print(f"    {k:20} {v}")
        onboarding_dir = args.grid_dir.parent / "procurement" / "kestrel-grid"
        if onboarding_dir.is_dir():
            extra = build_onboarding(onboarding_dir, today=fixture_date)
            print(f"{_c('✓', GREEN, colour)} regenerated onboarding fixtures in {onboarding_dir}")
            for k, v in extra.items():
                print(f"    {k:20} {v}")
        return 0

    try:
        controls = load_cip_controls(args.controls)
    except (ValueError, OSError) as exc:
        print(f"{_c('control set error:', RED, colour)} {exc}", file=sys.stderr)
        return 2

    started = time.time()
    estate = load_estate(args.grid_dir, substations=args.substations, seed=args.seed, today=when)
    if not estate.packages:
        print(
            f"{_c('no firmware packages found', RED, colour)} in {args.grid_dir}. "
            f"Run: python3 vra.py cip build-fixtures",
            file=sys.stderr,
        )
        return 2

    findings, gaps, verified, coverage = assess_estate(estate, controls, when=when)
    elapsed = time.time() - started
    summary = estate.summary()
    roll = rollup(findings, gaps)

    print()
    print(f"{_c('NERC CIP assessment', BOLD, colour)}  ·  {when.isoformat()}")
    print(_c("  synthetic estate — not connected to any real OT network", DIM, colour))
    print()
    print(f"  {summary['substations']:,} substations · {summary['devices']:,} cyber assets · "
          f"{summary['firmware_deployments']:,} firmware deployments")
    low_vendor_access = sum(
        1 for a in estate.access_sessions
        if a.get("impact_rating") == "low" and a.get("allows_vendor_electronic_remote_access")
    )
    print(f"  {summary['in_cip013_scope']:,} substations at high/medium impact "
          f"{_c('— CIP-013, CIP-010 R1.6 and CIP-005 R2 scope', DIM, colour)}")
    print(f"  {low_vendor_access:,} low impact assets allow vendor electronic remote access "
          f"{_c('— CIP-003-9 Attachment 1 Section 6 scope', DIM, colour)}")
    print(_c("  low impact assets with no vendor access path are out of scope, not passing",
             DIM, colour))
    print(f"  {summary['distinct_packages']} distinct packages cryptographically verified "
          f"in {elapsed:.2f}s")
    print()

    failing = [
        r for r in verified.values()
        if r.integrity_verified is not True or r.source_identity_verified is not True
    ]
    for r in failing:
        print(f"  {_c('FIRMWARE VERIFICATION FAILED', RED, colour)}  {r.package_id}")
        for line in r.evidence:
            print(f"      {_c(line, DIM, colour)}")
        print()

    sev = roll["by_severity"]
    crit = sev.get("critical", 0)
    tag = _c(f"{crit} critical", RED, colour) if crit else _c("0 critical", GREEN, colour)
    print(f"  {roll['findings']:,} exceptions ({tag}, {sev.get('high', 0)} high, "
          f"{sev.get('medium', 0)} medium) · {roll['gaps']:,} information gaps")
    print(f"  by standard: " + "  ".join(f"{k} {v}" for k, v in roll["by_standard"].items()))
    print()

    print(f"  {_c('Requirement coverage', BOLD, colour)}")
    print(f"    {'control':8} {'citation':38} {'appl':>7} {'pass':>7} {'fail':>6} {'gap':>5}")
    for cid, cov in sorted(coverage.items(), key=lambda kv: int(kv[0].split("-")[1])):
        if not cov.applicable:
            continue
        mark = RED if cov.failed else (YELLOW if cov.gapped else GREEN)
        line = (f"    {cid:8} {cov.citation[:38]:38} {cov.applicable:7,} "
                f"{cov.passed:7,} {cov.failed:6,} {cov.gapped:5,}")
        print(_c(line, mark, colour) if (cov.failed or cov.gapped) else line)
    print()

    cites = citation_status(controls, when)
    if cites.verified:
        print(f"  {_c('✓', GREEN, colour)} {cites.verified} of {cites.total} NERC citations "
              f"verified against the enforceable standards")
    if cites.unverified:
        print(_c(
            f"  ⚠ {cites.unverified} of {cites.total} NERC citations not yet verified. "
            f"Confirm against nerc.com and set citation_verified: true in "
            f"{args.controls.name}.", YELLOW, colour))
    for entry in cites.expired:
        print(_c(
            f"  ✗ {entry['control_id']} cites {entry['citation']}, which stopped being "
            f"enforceable on {entry['enforceable_until']}. Re-cite to "
            f"{entry['superseded_by']}.", RED, colour))
    for entry in cites.expiring:
        print(_c(
            f"  ⚠ {entry['control_id']} cites {entry['citation']}, enforceable until "
            f"{entry['enforceable_until']} ({entry['days']} days), then superseded by "
            f"{entry['superseded_by']}.", YELLOW, colour))
    print()

    if args.evidence:
        from .evidence import build_pack, write_findings, write_pack

        pack = build_pack(estate, controls, findings, gaps, verified, coverage, when=when)
        paths = write_pack(pack, args.out)
        fpath = write_findings(findings, gaps, args.out)
        print(f"  {_c('evidence pack', BOLD, colour)}")
        for label, path in paths.items():
            print(f"    {label:9} {path}")
        print(f"    {'findings':9} {fpath}")
        print()

    if args.no_fail:
        return 0
    return 1 if crit else 0


def _onboard(args, colour: bool, when) -> int:
    """Walk a new vendor from contract documents to a scored record."""
    from .config import RunConfig
    from .onboard_cip import onboard_vendor

    if not args.vendor or not args.docs:
        print("onboard needs --vendor and --docs", file=sys.stderr)
        return 2
    if not args.docs.is_dir() and not args.docs.is_file():
        print(f"no such documents path: {args.docs}", file=sys.stderr)
        return 2

    try:
        controls = load_cip_controls(args.controls)
    except (ValueError, OSError) as exc:
        print(f"{_c('control set error:', RED, colour)} {exc}", file=sys.stderr)
        return 2

    cfg = RunConfig(offline=args.offline)
    if not args.offline:
        # No local model reachable means the heuristic extractor, labelled as
        # such -- not a silent downgrade.
        from .llm import probe_ollama

        cfg.llm_unavailable = not probe_ollama(cfg)

    result = onboard_vendor(
        args.vendor, args.docs, cfg,
        impact_rating=args.impact, controls=controls, when=when,
    )
    if result.errors:
        for err in result.errors:
            print(f"{_c('error:', RED, colour)} {err}", file=sys.stderr)
        return 2

    ex = result.extraction
    backend = ex.backend or "unknown"
    print()
    print(f"{_c('VENDOR ONBOARDING', BOLD, colour)}  ·  {result.vendor}  ·  {when.isoformat()}")
    print(_c("  synthetic vendor and documents — not a real supplier", DIM, colour))
    print()

    # --- step 1-2 --------------------------------------------------------
    print(f"{_c('1. Documents read', BOLD, colour)}  ({backend})")
    for name in ex.documents:
        print(f"     {name}")
    for name in ex.unreadable_documents:
        print(f"     {_c(name + '  (no extractable text)', YELLOW, colour)}")
    print()

    if ex.footprint is not None:
        print(f"{_c('2. Reading order (prioritised from the asset inventory)', BOLD, colour)}")
        print(f"     {_c(ex.footprint.as_prompt_context(), DIM, colour)}")
        print()

    print(f"{_c('3. Procurement obligations detected', BOLD, colour)}")
    # Two clause targets can cite the same requirement (R1.2.5 covers both the
    # integrity method and key rotation notice), so the obligation is named as
    # well as the citation -- otherwise the table shows two identical rows.
    print(f"     {'#':>2}  {'CIP-013':16} {'obligation':32} {'clause':7} {'quote':10} {'applied':8} source")
    for claim in ex.claims:
        found = "found" if claim.present else "-"
        quoted = "verified" if claim.quote_verified else ("UNVERIFIED" if claim.quote else "-")
        applied = "yes" if claim.tier == "extracted" else "held"
        obligation = claim.field.split(".", 1)[-1]
        line = (f"     {claim.read_rank:2}  {claim.requirement:16} {obligation:32} "
                f"{found:7} {quoted:10} {applied:8} {claim.source_document}")
        if claim.tier == "extracted":
            print(_c(line, GREEN, colour))
        elif claim.present:
            print(_c(line, YELLOW, colour))
        else:
            print(line)
    print()

    # --- step 3 ----------------------------------------------------------
    print(f"{_c('4. What the code refused to let the model decide', BOLD, colour)}")
    if not ex.withheld:
        print("     nothing withheld")
    for claim in ex.withheld:
        print(f"     {_c(claim.requirement, YELLOW, colour)}  {claim.field}")
        print(f"       {_c(claim.withheld_reason, DIM, colour)}")
    if result.pending_review_path:
        print(f"     queued for ratification: {result.pending_review_path}")
    print()

    # --- step 4-5 --------------------------------------------------------
    keys = result.key_registry.all()
    print(f"{_c('5. Vendor signing key registered', BOLD, colour)}")
    for key in keys:
        confirmed = key.fingerprint_confirmed_out_of_band
        mark = "confirmed out of band" if confirmed else _c("NOT confirmed out of band", YELLOW, colour)
        print(f"     {key.key_id}  fingerprint {key.fingerprint}  [{key.status}]  {mark}")
    if not keys:
        print(_c("     none published — CIP-010 R1.6.1 will be unevaluable", YELLOW, colour))
    print()

    print(f"{_c('6. Firmware verification (SHA-256, then Ed25519)', BOLD, colour)}")
    for package_id in sorted(result.verified):
        r = result.verified[package_id]
        ok = r.integrity_verified is True and r.source_identity_verified is True
        head = _c("ACCEPTED", GREEN, colour) if ok else _c("REJECTED", RED, colour)
        print(f"     {head}  {package_id}")
        for line in r.evidence:
            print(f"        {_c(line, DIM, colour)}")
    print()

    # --- step 6 ----------------------------------------------------------
    crit = sum(1 for f in result.findings if f.control.severity == "critical")
    print(f"{_c('7. Controls scored', BOLD, colour)}")
    print(f"     {'control':8} {'citation':26} {'appl':>5} {'pass':>5} {'fail':>5} {'gap':>4}")
    for cid, cov in sorted(result.coverage.items()):
        if not cov.applicable:
            continue
        mark = RED if cov.failed else (YELLOW if cov.gapped else GREEN)
        line = (f"     {cid:8} {cov.citation[:26]:26} {cov.applicable:5} "
                f"{cov.passed:5} {cov.failed:5} {cov.gapped:4}")
        print(_c(line, mark, colour) if (cov.failed or cov.gapped) else line)
    print()
    tag = _c(f"{crit} critical", RED, colour) if crit else _c("0 critical", GREEN, colour)
    print(f"  {len(result.findings)} exceptions ({tag}) · {len(result.gaps)} information gaps")
    print()

    if args.no_fail:
        return 0
    return 1 if crit else 0
