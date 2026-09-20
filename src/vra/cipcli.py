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

from .cip import assess_estate, cip_citation, citations_verified, load_cip_controls, rollup
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
    p.add_argument("action", nargs="?", default="run", choices=["run", "build-fixtures"])
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

    if args.action == "build-fixtures":
        from .gridbuild import build

        result = build(args.grid_dir, today=when)
        print(f"{_c('✓', GREEN, colour)} regenerated sandbox estate in {args.grid_dir}")
        for k, v in result.items():
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
    print(f"  {summary['in_cip013_scope']:,} substations at high/medium impact "
          f"{_c('(CIP-002 scoping — the rest are out of scope, not passing)', DIM, colour)}")
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
    print(f"    {'control':8} {'citation':26} {'appl':>7} {'pass':>7} {'fail':>6} {'gap':>5}")
    for cid, cov in sorted(coverage.items()):
        if not cov.applicable:
            continue
        mark = RED if cov.failed else (YELLOW if cov.gapped else GREEN)
        line = (f"    {cid:8} {cov.citation[:26]:26} {cov.applicable:7,} "
                f"{cov.passed:7,} {cov.failed:6,} {cov.gapped:5,}")
        print(_c(line, mark, colour) if (cov.failed or cov.gapped) else line)
    print()

    ok, total = citations_verified(controls)
    if ok < total:
        print(_c(
            f"  ⚠ {total - ok} of {total} NERC citations have not been verified against the "
            f"enforceable standards.\n"
            f"    Confirm each against nerc.com and set citation_verified: true in "
            f"{args.controls.name}.", YELLOW, colour))
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
