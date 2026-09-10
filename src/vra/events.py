"""``vra events`` — inspect, roll, and destroy the entitlement-change log.

An entitlement change is the only permanent record that a permission ever
moved: ``data/nhis.json`` holds current state, not history. So the default is
to archive rather than delete, and destroying anything needs saying so out
loud.

    python3 vra.py events                 counts, sizes, oldest record
    python3 vra.py events show --limit 20 most recent changes
    python3 vra.py events prune           roll aged events out of the hot store
    python3 vra.py events purge --before 2025-01-01 --yes   destroy them
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .config import (
    EVENT_HOT_MAX,
    EVENT_RETENTION_DAYS,
    EVENTS_ARCHIVE_DIR,
    FINDINGS_FILE,
    RunConfig,
)
from .register import FindingStore


def _human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GB"


def _archive_files(archive_dir: Path) -> list[Path]:
    return sorted(archive_dir.glob("events-*.jsonl")) if archive_dir.is_dir() else []


def status(
    archive_dir: Path = EVENTS_ARCHIVE_DIR,
    findings_path: Path = FINDINGS_FILE,
) -> int:
    store = FindingStore(findings_path)
    archived = FindingStore.archived_events(archive_dir)
    files = _archive_files(archive_dir)

    hot_bytes = findings_path.stat().st_size if findings_path.exists() else 0
    archive_bytes = sum(f.stat().st_size for f in files)

    print("Entitlement-change log")
    print(f"  Retention window   : {EVENT_RETENTION_DAYS} days "
          f"(VRA_EVENT_RETENTION_DAYS)")
    print(f"  Hot store ceiling  : {EVENT_HOT_MAX:,} events (VRA_EVENT_HOT_MAX)")
    print()
    print(f"  Hot (findings.json): {len(store.events):,} events   "
          f"[{_human(hot_bytes)} total file]")
    print(f"  Archived           : {len(archived):,} events in {len(files)} file(s)   "
          f"[{_human(archive_bytes)}]")
    print(f"  Archived to date   : {int(store.meta.get('events_archived_total') or 0):,}")

    stamps = [str(e.get("timestamp") or "") for e in (archived + store.events)]
    stamps = sorted(s for s in stamps if s)
    if stamps:
        print(f"  Oldest record      : {stamps[0][:19]}")
        print(f"  Newest record      : {stamps[-1][:19]}")

    writes = len([e for e in store.events if e.get("gained_write_scope")])
    if writes:
        print(f"  Hot write-scope gains: {writes:,}")

    if files:
        print()
        print("  Archive files:")
        for path in files:
            lines = sum(1 for line in path.read_text(encoding="utf-8").splitlines()
                        if line.strip())
            print(f"    {path.name:<28} {lines:>8,} events  {_human(path.stat().st_size):>10}")

    aged = [e for e in store.events
            if FindingStore._event_age_days(e) > EVENT_RETENTION_DAYS]
    if aged:
        print()
        print(f"  {len(aged):,} hot event(s) are past the retention window. "
              "Run `python3 vra.py events prune`.")
    return 0


def show(
    limit: int,
    archive_dir: Path = EVENTS_ARCHIVE_DIR,
    findings_path: Path = FINDINGS_FILE,
) -> int:
    store = FindingStore(findings_path)
    rows = store.events + FindingStore.archived_events(archive_dir)
    rows.sort(key=lambda e: str(e.get("timestamp") or ""), reverse=True)
    if not rows:
        print("No entitlement changes recorded yet.")
        return 0

    print(f"{'When':<20} {'Vendor':<24} {'Identity':<28} {'Write?':<7} Change")
    print("-" * 130)
    for event in rows[:limit]:
        gained = ", ".join(event.get("added_scopes") or []) or "—"
        lost = ", ".join(event.get("removed_scopes") or [])
        change = f"+{gained}" + (f"  -{lost}" if lost else "")
        print(
            f"{str(event.get('timestamp') or '')[:19]:<20} "
            f"{str(event.get('vendor') or '')[:24]:<24} "
            f"{str(event.get('nhi_name') or event.get('nhi_id') or '')[:28]:<28} "
            f"{('YES' if event.get('gained_write_scope') else 'no'):<7} "
            f"{change[:60]}"
        )
    if len(rows) > limit:
        print(f"\n… {len(rows) - limit:,} more. Use --limit, or read "
              f"{archive_dir}/events-*.jsonl")
    return 0


def prune(
    cfg: RunConfig,
    archive_dir: Path = EVENTS_ARCHIVE_DIR,
    findings_path: Path = FINDINGS_FILE,
) -> int:
    store = FindingStore(findings_path)
    before = len(store.events)
    moved = store.roll_events(archive_dir=archive_dir)
    if moved:
        store.save(cfg)  # persists the trimmed hot store
        print(f"vra events: archived {moved:,} event(s) to {archive_dir}/")
        print(f"  hot store: {before:,} -> {len(store.events):,}")
    else:
        print(f"vra events: nothing to archive "
              f"({before:,} event(s) within the {EVENT_RETENTION_DAYS}-day window)")
    return 0


def purge(before: str, *, confirmed: bool, cfg: RunConfig,
          archive_dir: Path = EVENTS_ARCHIVE_DIR,
          findings_path: Path = FINDINGS_FILE) -> int:
    """Destroy events older than a date. Hot store and archive both."""
    try:
        cutoff = date.fromisoformat(before)
    except ValueError:
        print(f"vra events: --before must be YYYY-MM-DD, got {before!r}", file=sys.stderr)
        return 2

    store = FindingStore(findings_path)
    doomed_hot = [e for e in store.events if str(e.get("timestamp") or "")[:10] < before]
    archived = FindingStore.archived_events(archive_dir)
    doomed_archive = [e for e in archived if str(e.get("timestamp") or "")[:10] < before]
    total = len(doomed_hot) + len(doomed_archive)

    if not total:
        print(f"vra events: nothing recorded before {cutoff.isoformat()}")
        return 0

    if not confirmed:
        writes = len([e for e in doomed_hot + doomed_archive
                      if e.get("gained_write_scope")])
        print(f"vra events: this would PERMANENTLY DELETE {total:,} event(s) "
              f"recorded before {cutoff.isoformat()}.")
        print(f"  {len(doomed_hot):,} in findings.json, "
              f"{len(doomed_archive):,} in {archive_dir}/")
        if writes:
            print(f"  {writes:,} of them record an identity GAINING a write scope.")
        print()
        print("  This is the only record that those permissions ever changed —")
        print("  data/nhis.json holds current state, not history.")
        print("  Re-run with --yes to proceed.")
        return 1

    keep_hot = [e for e in store.events if str(e.get("timestamp") or "")[:10] >= before]
    store.events = keep_hot
    # Roll first with this archive dir, so save() cannot re-archive into the
    # default location while we are rewriting the archive below.
    store.roll_events(archive_dir=archive_dir)
    store.save(cfg)

    kept_archive = [e for e in archived if str(e.get("timestamp") or "")[:10] >= before]
    for path in _archive_files(archive_dir):
        path.unlink()
    by_month: dict[str, list[dict]] = {}
    for event in kept_archive:
        by_month.setdefault(FindingStore._event_month(event), []).append(event)
    for month, rows in by_month.items():
        target = archive_dir / f"events-{month}.jsonl"
        with target.open("a", encoding="utf-8") as fh:
            for event in rows:
                fh.write(json.dumps(event, default=str, ensure_ascii=False) + "\n")

    print(f"vra events: purged {total:,} event(s) recorded before {cutoff.isoformat()}")
    print(f"  remaining: {len(keep_hot):,} hot, {len(kept_archive):,} archived")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra events",
        description="Inspect, archive, or destroy the entitlement-change log.",
    )
    p.add_argument(
        "action", nargs="?", default="status",
        choices=("status", "show", "prune", "purge"),
        help="status (default), show, prune (archive aged events), purge (delete)",
    )
    p.add_argument("--limit", type=int, default=20, help="show: how many rows")
    p.add_argument("--before", default=None,
                   help="purge: delete events recorded before this YYYY-MM-DD")
    p.add_argument("--yes", action="store_true",
                   help="purge: confirm permanent deletion")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = RunConfig()
    if args.action == "status":
        return status()
    if args.action == "show":
        return show(max(1, args.limit))
    if args.action == "prune":
        return prune(cfg)
    if args.action == "purge":
        if not args.before:
            # Default to the retention window rather than guessing wider.
            args.before = (
                datetime.now(timezone.utc) - timedelta(days=EVENT_RETENTION_DAYS)
            ).date().isoformat()
            print(f"vra events: no --before given; using the retention window "
                  f"({args.before})")
        return purge(args.before, confirmed=args.yes, cfg=cfg)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
