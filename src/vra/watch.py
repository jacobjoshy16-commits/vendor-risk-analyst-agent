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
from .extract import (
    decode_bytes,
    detect_trust_platform,
    extract_html_tables,
    extract_pdf_text,
    looks_like_html,
    looks_like_pdf,
)
from .normalize import normalize

SOURCE_KINDS = ("changelog", "trust_center", "subprocessors", "dpa")

# How the raw artifact was ingested. Determines which extraction path applies.
RAW_KINDS = ("html", "pdf", "text")


@dataclass
class SourceSnapshot:
    vendor: str
    source: str
    origin: str
    text: str
    sha256: str
    fetched_at: str
    raw_kind: str = "text"          # html | pdf | text
    tables: list = field(default_factory=list)      # extracted HTML tables
    platform: str | None = None     # safebase | whistic | vanta | generic | None
    portal_blocked: bool = False    # click-through / access gate detected
    portal_evidence: str = ""       # verbatim trigger for the audit trail
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


def fetch(origin: str, cfg: RunConfig) -> tuple[bytes, str | None, str | None]:
    """Return (raw_bytes, content_type, error). Local paths in sandbox mode; HTTP otherwise."""
    if re.match(r"^https?://", origin):
        if cfg.offline:
            return b"", None, f"offline mode: refused network fetch of {origin}"
        try:
            import requests  # imported lazily so --offline needs no network stack

            resp = requests.get(origin, timeout=30, headers={"User-Agent": "vra/1.0 (vendor-risk-analyst)"})
            resp.raise_for_status()
            return resp.content, resp.headers.get("Content-Type"), None
        except Exception as exc:  # pragma: no cover - network path
            return b"", None, f"fetch failed: {exc}"

    path = Path(origin)
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.exists():
        return b"", None, f"missing local artifact: {path}"
    return path.read_bytes(), None, None


def _ingest(raw: bytes, origin: str, content_type: str | None) -> tuple[SourceSnapshot, ...]:
    """Classify, decode, normalize and structurally extract one fetched artifact.

    Real-world trust centers publish HTML tables, PDFs, or sit behind branded
    portals. AIV-03 depends on the subprocessor parse, so ingestion must not
    silently degrade: PDFs without pypdf produce an explicit error snapshot, and
    portal-hosted pages are tagged ``portal_blocked`` with the platform name so
    the observation layer can raise a gap instead of passing quietly.
    """
    kind = "pdf" if looks_like_pdf(raw, origin, content_type) else \
        "html" if looks_like_html(raw) else "text"
    text, fired = "", []
    tables, platform, portal_blocked, portal_evidence = [], None, False, ""

    if kind == "pdf":
        text, pdf_err = extract_pdf_text(raw)
        if pdf_err:
            return (SourceSnapshot(
                vendor="", source="", origin=origin, text="", sha256="",
                fetched_at=datetime.now(timezone.utc).isoformat(),
                raw_kind="pdf", error=pdf_err,
            ),)
    else:
        decoded = decode_bytes(raw)
        if kind == "html":
            platform, portal_blocked, portal_evidence = detect_trust_platform(
                decoded, page_url=origin if origin.startswith(("http://", "https://")) else None
            )
            tables = extract_html_tables(decoded)
        text, fired = normalize(decoded, is_html=(kind == "html"))

    return (SourceSnapshot(
        vendor="", source="", origin=origin, text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        fetched_at=datetime.now(timezone.utc).isoformat(),
        raw_kind=kind, tables=tables, platform=platform,
        portal_blocked=portal_blocked, portal_evidence=portal_evidence,
        volatile_rules_fired=fired,
    ),)


def snapshot_vendor(vendor: dict, cfg: RunConfig) -> list[SourceSnapshot]:
    """Fetch and normalize every watch source for one vendor."""
    slug = vendor["slug"]
    snaps: list[SourceSnapshot] = []
    for source, origin_tpl in (vendor.get("watch") or {}).items():
        origin = _resolve(str(origin_tpl), cfg.snapshot_version)
        raw, ctype, err = fetch(origin, cfg)
        if err:
            snaps.append(
                SourceSnapshot(slug, source, origin, "", "", datetime.now(timezone.utc).isoformat(), error=err)
            )
            continue
        (ingested,) = _ingest(raw, origin, ctype)
        ingested.vendor, ingested.source = slug, source
        snaps.append(ingested)
    return snaps


def _vendor_snapshot_root(slug: str) -> Path:
    return SNAPSHOT_DIR / slug


def previous_snapshot_dir(slug: str) -> Path | None:
    root = _vendor_snapshot_root(slug)
    if not root.exists():
        return None
    runs = sorted(p for p in root.iterdir() if p.is_dir())
    return runs[-1] if runs else None


def snapshots_unchanged(snaps: list[SourceSnapshot], prev_dir: Path | None) -> bool:
    """True when every source hash matches the previous snapshot and none erred.

    The monitor daemon re-fetches on a timer. Writing a new timestamped
    directory for an identical fetch fills the disk and makes ``previous``
    a no-op. Skip the write; the last real snapshot stays authoritative.
    """
    if not prev_dir or not (prev_dir / "manifest.json").exists():
        return False
    prev = json.loads((prev_dir / "manifest.json").read_text(encoding="utf-8"))
    current = {s.source: s for s in snaps}
    if set(current) != set(prev):
        return False
    for source, snap in current.items():
        if snap.error:
            return False
        entry = prev.get(source) or {}
        if entry.get("error") or entry.get("sha256") != snap.sha256:
            return False
    return True


def store_snapshot(slug: str, snaps: list[SourceSnapshot], cfg: RunConfig) -> Path:
    """Persist this run's snapshot set. Returns the directory written."""
    prev = previous_snapshot_dir(slug)
    if snapshots_unchanged(snaps, prev):
        return prev  # type: ignore[return-value]
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
        entry = {
            "sha256": snap.sha256,
            "origin": snap.origin,
            "fetched_at": snap.fetched_at,
            "raw_kind": snap.raw_kind,
            "platform": snap.platform,
            "portal_blocked": snap.portal_blocked,
            "portal_evidence": snap.portal_evidence,
            "volatile_rules_fired": snap.volatile_rules_fired,
        }
        if snap.tables:
            (run_dir / f"{snap.source}.tables.json").write_text(
                json.dumps(snap.tables, ensure_ascii=False), encoding="utf-8"
            )
            entry["tables_file"] = f"{snap.source}.tables.json"
        manifest[snap.source] = entry
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
