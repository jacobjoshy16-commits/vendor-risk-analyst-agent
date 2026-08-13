"""Phase 2 — the watcher.

For each vendor and each watch source: fetch, normalize to text, hash, store
under data/snapshots/{vendor}/{timestamp}/. Diff against the previous snapshot
and emit a unified diff, not a boolean.

In sandbox mode the fetcher points at local files so diffs are reproducible and
offline. A `{version}` placeholder in a watch path selects the snapshot set,
which is how the v1 baseline / v2 change run works.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .config import REPO_ROOT, SNAPSHOT_DIR, RunConfig
from .normalize import normalize

SOURCE_KINDS = ("changelog", "trust_center", "subprocessors", "dpa")


@dataclass
class SourceSnapshot:
    vendor: str
    source: str
    origin: str
    text: str
    sha256: str
    fetched_at: str
    volatile_rules_fired: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class SourceDiff:
    vendor: str
    source: str
    origin: str
    changed: bool
    old_hash: str | None
    new_hash: str
    unified_diff: str
    added_lines: list[str] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)
    is_baseline: bool = False

    @property
    def churn(self) -> int:
        return len(self.added_lines) + len(self.removed_lines)


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _resolve(origin: str, version: str) -> str:
    return origin.replace("{version}", version)


def fetch(origin: str, cfg: RunConfig) -> tuple[str, str | None]:
    """Return (raw_text, error). Local paths in sandbox mode; HTTP otherwise."""
    if re.match(r"^https?://", origin):
        if cfg.offline:
            return "", f"offline mode: refused network fetch of {origin}"
        try:
            import requests  # imported lazily so --offline needs no network stack

            resp = requests.get(origin, timeout=30, headers={"User-Agent": "vra/1.0 (vendor-risk-analyst)"})
            resp.raise_for_status()
            return resp.text, None
        except Exception as exc:  # pragma: no cover - network path
            return "", f"fetch failed: {exc}"

    path = Path(origin)
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.exists():
        return "", f"missing local artifact: {path}"
    return path.read_text(encoding="utf-8"), None


def snapshot_vendor(vendor: dict, cfg: RunConfig) -> list[SourceSnapshot]:
    """Fetch and normalize every watch source for one vendor."""
    slug = vendor["slug"]
    snaps: list[SourceSnapshot] = []
    for source, origin_tpl in (vendor.get("watch") or {}).items():
        origin = _resolve(str(origin_tpl), cfg.snapshot_version)
        raw, err = fetch(origin, cfg)
        if err:
            snaps.append(
                SourceSnapshot(slug, source, origin, "", "", datetime.now(timezone.utc).isoformat(), error=err)
            )
            continue
        text, fired = normalize(raw)
        snaps.append(
            SourceSnapshot(
                vendor=slug,
                source=source,
                origin=origin,
                text=text,
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                fetched_at=datetime.now(timezone.utc).isoformat(),
                volatile_rules_fired=fired,
            )
        )
    return snaps


def _vendor_snapshot_root(slug: str) -> Path:
    return SNAPSHOT_DIR / slug


def previous_snapshot_dir(slug: str) -> Path | None:
    root = _vendor_snapshot_root(slug)
    if not root.exists():
        return None
    runs = sorted(p for p in root.iterdir() if p.is_dir())
    return runs[-1] if runs else None


def store_snapshot(slug: str, snaps: list[SourceSnapshot], cfg: RunConfig) -> Path:
    """Persist this run's snapshot set. Returns the directory written."""
    run_dir = _vendor_snapshot_root(slug) / _utc_stamp()
    if cfg.dry_run:
        return run_dir
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for snap in snaps:
        if snap.error:
            manifest[snap.source] = {"error": snap.error, "origin": snap.origin}
            continue
        (run_dir / f"{snap.source}.txt").write_text(snap.text, encoding="utf-8")
        manifest[snap.source] = {
            "sha256": snap.sha256,
            "origin": snap.origin,
            "fetched_at": snap.fetched_at,
            "volatile_rules_fired": snap.volatile_rules_fired,
        }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_dir


def diff_against_previous(
    slug: str, snaps: list[SourceSnapshot], prev_dir: Path | None
) -> list[SourceDiff]:
    """Unified diff per source against the previous stored snapshot."""
    diffs: list[SourceDiff] = []
    prev_manifest: dict = {}
    if prev_dir and (prev_dir / "manifest.json").exists():
        prev_manifest = json.loads((prev_dir / "manifest.json").read_text(encoding="utf-8"))

    for snap in snaps:
        if snap.error:
            continue
        prev_text = ""
        prev_hash = None
        if prev_dir:
            prev_file = prev_dir / f"{snap.source}.txt"
            if prev_file.exists():
                prev_text = prev_file.read_text(encoding="utf-8")
                prev_hash = (prev_manifest.get(snap.source) or {}).get("sha256")

        is_baseline = prev_hash is None
        changed = (not is_baseline) and prev_hash != snap.sha256

        udiff = ""
        added: list[str] = []
        removed: list[str] = []
        if changed:
            old_lines = prev_text.splitlines(keepends=True)
            new_lines = snap.text.splitlines(keepends=True)
            udiff = "".join(
                difflib.unified_diff(
                    old_lines,
                    new_lines,
                    fromfile=f"{snap.source}@previous",
                    tofile=f"{snap.source}@current",
                    n=2,
                )
            )
            for line in udiff.splitlines():
                if line.startswith("+") and not line.startswith("+++"):
                    added.append(line[1:].strip())
                elif line.startswith("-") and not line.startswith("---"):
                    removed.append(line[1:].strip())

        diffs.append(
            SourceDiff(
                vendor=slug,
                source=snap.source,
                origin=snap.origin,
                changed=changed,
                old_hash=prev_hash,
                new_hash=snap.sha256,
                unified_diff=udiff,
                added_lines=[l for l in added if l],
                removed_lines=[l for l in removed if l],
                is_baseline=is_baseline,
            )
        )
    return diffs


def watch_vendor(vendor: dict, cfg: RunConfig) -> tuple[list[SourceSnapshot], list[SourceDiff]]:
    slug = vendor["slug"]
    prev_dir = previous_snapshot_dir(slug)
    snaps = snapshot_vendor(vendor, cfg)
    diffs = diff_against_previous(slug, snaps, prev_dir)
    store_snapshot(slug, snaps, cfg)
    return snaps, diffs
