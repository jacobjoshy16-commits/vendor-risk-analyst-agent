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
import os
import sys
import time
from datetime import date
from pathlib import Path

from .cip import (assess_estate, cip_citation, citation_status, citations_verified,
                  load_cip_controls, rollup)
from .cipcrypto import utc_now_iso
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
                   choices=["run", "build-fixtures", "onboard", "monitor", "gate",
                            "alerts", "commission"])
    p.add_argument("--plant", default=None, help="commission: plant name")
    p.add_argument("--batch", type=Path, default=None,
                   help="commission: directory of the vendor firmware batch")
    p.add_argument("--interval", default="15m",
                   help="monitor: seconds, or 30s / 15m / 1h")
    p.add_argument("--once", action="store_true",
                   help="monitor: one cycle then exit (for cron)")
    p.add_argument("--package", default=None, help="gate: package id to verify")
    p.add_argument("--limit", type=int, default=20, help="alerts: how many to show")
    p.add_argument("--decision", default="both", choices=["code", "model", "both"],
                   help="who decides the disposition (default: both, stricter wins)")
    p.add_argument("--model", default=None,
                   help="model tag for Ollama, e.g. gemma3:4b (default: $VRA_MODEL)")
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

    if args.action == "monitor":
        return _monitor(args, colour, when)

    if args.action == "gate":
        return _gate(args, colour, when)

    if args.action == "commission":
        return _commission(args, colour, when)

    if args.action == "alerts":
        return _alerts(args, colour)

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
        batch_dir = args.grid_dir.parent / "commissioning" / "cypress-bend"
        if batch_dir.is_dir():
            from .gridbuild import build_commissioning

            batch = build_commissioning(batch_dir, today=fixture_date)
            print(f"{_c('✓', GREEN, colour)} regenerated commissioning batch in {batch_dir}")
            for k, v in batch.items():
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


# ---------------------------------------------------------------------------
# Continuous monitoring
# ---------------------------------------------------------------------------
def _parse_interval(raw: str) -> int:
    """Accept 900, 30s, 15m or 1h."""
    text = str(raw).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600}
    if text and text[-1] in units:
        try:
            return max(10, int(float(text[:-1]) * units[text[-1]]))
        except ValueError:
            pass
    try:
        return max(10, int(float(text)))
    except ValueError:
        return 900


def _cycle(args, colour: bool, when, store, *, quiet: bool = False,
           baseline: bool = False) -> tuple[int, dict]:
    """One assessment pass: assess, reconcile against memory, alert on changes.

    `baseline` is the cold-start case. On the very first run every open finding
    is technically "new", and alerting on all of them means the first thing the
    security team ever sees from this tool is a hundred-line dump they did not
    ask for. That is how a channel gets muted on day one. So the first cycle
    records the state, reports a summary, and alerts nothing. Everything after
    it alerts on transitions.
    """
    from . import cipalert
    from .evaluate import to_record
    from .grid import load_estate

    controls = load_cip_controls(args.controls)
    estate = load_estate(args.grid_dir, substations=args.substations,
                         seed=args.seed, today=when)
    findings, gaps, verified, coverage = assess_estate(estate, controls, when=when)
    records = [to_record(a) for a in findings] + [to_record(a) for a in gaps]

    delta = store.reconcile(records, when)

    if baseline:
        store.mark_alerted(delta.new)
        store.save()
        if not quiet:
            by_sev: dict[str, int] = {}
            for f in delta.new:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            print(f"  {_c('baseline established', BOLD, colour)} — "
                  f"{len(delta.new)} open finding(s) recorded, no alerts sent")
            print(f"    {'  '.join(f'{k} {v}' for k, v in sorted(by_sev.items()))}")
            print(_c("    from here, only changes are announced", DIM, colour))
        return 0, delta.summary()

    alerts = cipalert.group_new([f for f in delta.new if not f.alerted_new], when)
    alerts += cipalert.group_new(delta.reopened, when)
    alerts += [cipalert.for_overdue(f, when) for f in delta.newly_overdue]
    alerts += cipalert.group_resolved(delta.resolved, when)

    if alerts:
        store.mark_alerted([f for f in delta.new + delta.reopened])
        store.mark_alerted(delta.newly_overdue, overdue=True)
        path = cipalert.append(alerts)
        url = cipalert.webhook_url()
        if url:
            code, detail = cipalert.post_webhook(alerts, url)
            if not quiet:
                ok = 200 <= code < 300
                print(f"    webhook {url}: {_c(str(code) or 'failed', GREEN if ok else YELLOW, colour)} {detail}")
        if not quiet:
            print(f"    logged {len(alerts)} alert(s) to {path}")
    store.save()

    if not quiet:
        _print_alerts(alerts, colour)

    return len(alerts), delta.summary()


def _print_alerts(alerts, colour: bool) -> None:
    for alert in alerts:
        tint = {"critical": RED, "high": RED, "medium": YELLOW}.get(alert.severity, DIM)
        if alert.kind == "resolved":
            tint = GREEN
        head = alert.kind.replace("_", " ").upper()
        print(f"  {_c(head, tint, colour)}  [{alert.severity}] -> {alert.route_to}")
        print(f"    {alert.message}")


def _monitor(args, colour: bool, when) -> int:
    """Re-assess on a timer and alert on what changed.

    This is what makes it a monitor rather than a report generator: the estate
    is re-verified every cycle, the result is diffed against what was already
    known, and only transitions are announced.
    """
    import time

    from .cipstate import CIP_FINDINGS_FILE, FindingStore

    interval = _parse_interval(args.interval)
    lock = args.grid_dir.parent.parent / "data" / "cip_monitor.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Two monitors would each reconcile against a store the other is
        # rewriting, producing duplicate alerts and a corrupted lifecycle.
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
    except FileExistsError:
        print(f"{_c('a CIP monitor is already running', RED, colour)} ({lock}). "
              f"Remove the lock if that is wrong.", file=sys.stderr)
        return 2

    store = FindingStore().load()
    cold_start = not store.all()
    print()
    print(f"{_c('NERC CIP monitor', BOLD, colour)}  ·  every {interval}s  ·  "
          f"{len(store.open_findings())} finding(s) already open")
    print(_c(f"  state {CIP_FINDINGS_FILE}", DIM, colour))
    print(_c("  ctrl-c to stop", DIM, colour))
    cycles = 0
    try:
        while True:
            cycles += 1
            stamp = utc_now_iso()
            print()
            print(f"{_c(f'cycle {cycles}', BOLD, colour)}  {stamp}")
            count, summary = _cycle(args, colour, when, store,
                                    baseline=(cold_start and cycles == 1))
            parts = "  ".join(f"{k} {v}" for k, v in summary.items() if v)
            print(f"  {parts or _c('no change', DIM, colour)}")
            if args.once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        try:
            lock.unlink()
        except OSError:
            pass
    return 0


# ---------------------------------------------------------------------------
# Deployment gate
# ---------------------------------------------------------------------------
def _runconfig(args):
    """RunConfig for the reasoning layer, honouring --model and --offline."""
    from .config import RunConfig

    cfg = RunConfig(offline=getattr(args, "offline", False))
    if getattr(args, "model", None):
        cfg.model = args.model
    if not cfg.offline:
        from .llm import probe_ollama

        # No reachable model means the deterministic stand-in, labelled as such,
        # not a silent downgrade.
        cfg.llm_unavailable = not probe_ollama(cfg)
    return cfg


def _print_judgment(decision, colour: bool) -> None:
    from .analyst_cip import DECIDE_BOTH

    j = decision.judgment
    tint = {"block": RED, "escalate": YELLOW, "allow": GREEN}.get(j.disposition, DIM)
    print(f"  {_c('ANALYST JUDGEMENT', BOLD, colour)}  ({j.backend or 'unavailable'}"
          f"{'/' + j.model if j.model else ''})")
    print(f"    disposition  {_c(j.disposition.upper(), tint, colour)}   "
          f"risk {j.risk}   confidence {j.confidence:.2f}")
    print(f"    {j.reasoning}")
    if j.pattern:
        print(f"    pattern: {_c(j.pattern, YELLOW, colour)}")
    for action in j.recommended_actions:
        print(f"      → {action}")
    for question in j.questions_for_vendor:
        print(f"      ? {question}")
    if decision.disagreement:
        print(f"    {_c('DISAGREEMENT', YELLOW, colour)} — rule engine says "
              f"{decision.deterministic.upper()}, model says "
              f"{decision.model_disposition.upper()}")
    print()


def _write_audit_report(package_id, result, decision, out_dir, when) -> Path:
    """The per-package audit record that goes out with the block."""
    import json

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"blocked-{package_id}-{when.isoformat()}.json"
    path.write_text(json.dumps({
        "package_id": package_id,
        "assessed_on": when.isoformat(),
        "generated_at": utc_now_iso(),
        "disposition": decision.disposition,
        "decided_by": decision.decided_by,
        "rule_engine_verdict": decision.deterministic,
        "model_disposition": decision.model_disposition,
        "disagreement": decision.disagreement,
        "citation": "NERC CIP-010-4 R1 Part 1.6",
        "verification": result.as_fields(),
        "verification_log": result.evidence,
        "analyst_judgment": decision.judgment.as_dict(),
        "note": ("Synthetic demonstration data. This record states what was checked "
                 "and what was decided; it does not assert compliance."),
    }, indent=2, default=str), encoding="utf-8")
    return path


def _gate(args, colour: bool, when) -> int:
    """A vendor package arrives. Verify it, reason about it, decide, record, route.

    The full path the tool exists for:

        verify (code)  ->  reason (model, over everything the code found)
        ->  decide  ->  write the audit report  ->  alert the security team
        ->  exit non-zero so a pipeline cannot deploy it

    CIP-010 R1.6 requires verification prior to a change that deviates from
    baseline, so blocking the deployment is the requirement itself.

    Exit 0 = safe to deploy. Exit 1 = do not deploy.
    """
    from . import cipalert
    from .analyst_cip import build_brief, decide, judge
    from .cipstate import FindingStore
    from .grid import load_estate

    if not args.package:
        print("gate needs --package <package_id>", file=sys.stderr)
        return 2

    estate = load_estate(args.grid_dir, substations=args.substations,
                         seed=args.seed, today=when)
    package = estate.packages.get(args.package)
    if package is None:
        print(f"{_c('unknown package:', RED, colour)} {args.package}", file=sys.stderr)
        print(f"  known: {', '.join(sorted(estate.packages))}", file=sys.stderr)
        return 2

    # 1. Code verifies.
    result = estate.verify_all(when=when)[args.package]

    print()
    print(f"{_c('CIP-010 R1.6 DEPLOYMENT GATE', BOLD, colour)}  ·  {args.package}")
    print(_c("  synthetic package — not a real supplier", DIM, colour))
    print()
    print(f"  {_c('CRYPTOGRAPHIC VERIFICATION', BOLD, colour)}")
    for line in result.evidence:
        print(f"    {_c(line, DIM, colour)}")
    print()

    # 2. Model reasons over what the code found, plus history and blast radius.
    cfg = _runconfig(args)
    brief = build_brief(package, result, estate=estate,
                        store=FindingStore().load())
    judgment = judge(brief, cfg)
    decision = decide(brief, judgment, mode=args.decision)
    _print_judgment(decision, colour)

    print(f"  {_c('DECISION', BOLD, colour)}  ({decision.decided_by})")
    if not decision.blocks:
        print(f"    {_c('PASS — safe to deploy', GREEN, colour)}")
        print(f"    source identity verified (R1.6.1), integrity verified (R1.6.2)")
        return 0

    # 3. Block, record, route.
    report = _write_audit_report(args.package, result, decision, args.out, when)
    alert = cipalert.for_rejected_firmware(result, package_id=args.package)
    alert.context["analyst_judgment"] = decision.judgment.as_dict()
    alert.context["decided_by"] = decision.decided_by
    alert.context["audit_report"] = str(report)
    log = cipalert.append([alert])

    verb = "BLOCKED — do not deploy" if decision.disposition == "block" else \
           "HELD — human review required before deploy"
    print(f"    {_c(verb, RED, colour)}")
    print(f"    audit report  {report}")
    print(f"    routed to     {alert.route_to}")
    print(f"    alert log     {log}")
    return 1


# ---------------------------------------------------------------------------
# Alert log
# ---------------------------------------------------------------------------
def _alerts(args, colour: bool) -> int:
    import json

    from .cipalert import CIP_ALERT_LOG

    if not CIP_ALERT_LOG.is_file():
        print(f"no alerts yet ({CIP_ALERT_LOG})")
        return 0
    lines = CIP_ALERT_LOG.read_text(encoding="utf-8").splitlines()
    print()
    print(f"{_c('CIP alerts', BOLD, colour)}  ·  {len(lines)} total  ·  {CIP_ALERT_LOG}")
    print()
    for raw in lines[-args.limit:]:
        try:
            a = json.loads(raw)
        except json.JSONDecodeError:
            continue
        tint = {"critical": RED, "high": RED, "medium": YELLOW}.get(a.get("severity"), DIM)
        if a.get("kind") == "resolved":
            tint = GREEN
        print(f"  {a.get('raised_at', '')}  {_c(a.get('kind', '').upper(), tint, colour)}"
              f"  -> {a.get('route_to', '')}")
        print(f"    {a.get('message', '')}")
    return 0


# ---------------------------------------------------------------------------
# Commissioning gate
# ---------------------------------------------------------------------------
def _commission(args, colour: bool, when) -> int:
    """Verify an entire commissioning batch before a new plant is energised.

    The estate assessment is steady-state: equipment already in service, one bad
    build found among it. Commissioning is the other shape and the riskier one.
    A plant's firmware arrives as a batch, from several vendors, against a
    schedule, and the pressure at that moment is to energise rather than to
    check.

    Same verification as everywhere else -- this only changes the unit of work
    from one package to a delivery, and the exit code from one device to a
    whole plant.

    Exit 0 = every package verified. Exit 1 = do not energise.
    """
    from . import cipalert
    from .grid import load_estate

    if not args.batch:
        print("commission needs --batch <directory>", file=sys.stderr)
        return 2
    if not args.batch.is_dir():
        print(f"no such batch directory: {args.batch}", file=sys.stderr)
        return 2

    plant = args.plant or args.batch.name
    estate = load_estate(args.batch, substations=1, seed=args.seed, today=when)
    if not estate.packages:
        print(f"{_c('no releases found in', RED, colour)} {args.batch}", file=sys.stderr)
        return 2

    results = estate.verify_all(when=when)
    blocked = []

    print()
    print(f"{_c('COMMISSIONING FIRMWARE VERIFICATION', BOLD, colour)}  ·  {plant}")
    print(_c("  synthetic batch — not a real plant or a real supplier", DIM, colour))
    print()
    print(f"  {len(results)} packages from "
          f"{len({p.get('vendor') for p in estate.packages.values()})} vendors, "
          f"assessed {when.isoformat()}")
    print()
    print(f"    {'package':26} {'vendor':30} {'sha-256':9} {'signature':10} verdict")
    for package_id in sorted(results):
        result = results[package_id]
        vendor = str(estate.packages[package_id].get("vendor", ""))[:30]
        ok = result.integrity_verified is True and result.source_identity_verified is True
        if not ok:
            blocked.append((package_id, result))
        hashed = "MATCH" if result.hash_match else "MISMATCH"
        signed = "VALID" if result.signature_verified else "INVALID"
        verdict = "accepted" if ok else "BLOCKED"
        line = f"    {package_id:26} {vendor:30} {hashed:9} {signed:10} {verdict}"
        print(_c(line, GREEN, colour) if ok else _c(line, RED, colour))
    print()

    if not blocked:
        print(f"  {_c('BATCH ACCEPTED', GREEN, colour)} — all {len(results)} packages "
              f"verified against CIP-010-4 R1 Part 1.6")
        return 0

    headline = f"ENERGISATION BLOCKED — {len(blocked)} of {len(results)} packages failed"
    print(f"  {_c(headline, RED, colour)}")
    print()
    for package_id, result in blocked:
        print(f"    {_c(package_id, RED, colour)}  ({estate.packages[package_id].get('vendor')})")
        for line in result.evidence:
            print(f"      {_c(line, DIM, colour)}")
        print()

    alerts = [cipalert.for_rejected_firmware(r, package_id=p, target=plant)
              for p, r in blocked]
    path = cipalert.append(alerts)
    print(f"    routed to {alerts[0].route_to}; logged to {path}")
    if args.no_fail:
        return 0
    return 1
