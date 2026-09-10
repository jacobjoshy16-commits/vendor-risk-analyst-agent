"""Phase 1 / Phase 7 — the vendor register and persistent finding state.

The register is the analyst's case file. Vendor definitions are hand-authored
YAML the human owns; findings are machine-maintained JSON with lifecycle state.
Keeping them in separate files matters: the tool never rewrites the file a human
is responsible for.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import (
    FINDINGS_FILE,
    REGISTRY_STATE_FILE,
    SANDBOX_VENDORS_DIR,
    VENDORS_DIR,
    RunConfig,
)
from .evaluate import due_date_for

REQUIRED_KEYS = ("vendor", "slug", "tier")


def register_dirs() -> list[Path]:
    """Where registers are read from, lowest precedence first.

    The shipped demo registers and the ones a human writes live in separate
    directories so ``vra connect`` cannot collide with a fixture, and so a real
    portfolio is never committed to this repo.
    """
    return [SANDBOX_VENDORS_DIR, VENDORS_DIR]


def load_vendors(cfg: RunConfig) -> list[dict]:
    by_slug: dict[str, dict] = {}
    for directory in register_dirs():
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"{path} does not contain a mapping")
            missing = [k for k in REQUIRED_KEYS if k not in data]
            if missing:
                raise ValueError(f"{path} missing required keys: {missing}")
            data["_path"] = str(path)
            # A user register shadows a demo one with the same slug.
            by_slug[data["slug"]] = data

    vendors = [v for _, v in sorted(by_slug.items())]
    if cfg.vendors:
        vendors = [
            v for v in vendors
            if v["slug"] in cfg.vendors or v["vendor"] in cfg.vendors
        ]
    return vendors


class RegistryState:
    """Machine-owned per-vendor bookkeeping, kept out of the register.

    ``last_assessed`` and ``snapshot_hashes`` used to be written back into
    ``vendors/*.yaml`` after every run. Nothing ever read them, but the write
    round-tripped the file through ``yaml.safe_dump`` — stripping the comments
    of a file the README says the human owns, and leaving a dirty working tree
    after every cycle. It lives here instead.

    A legacy ``state:`` block still in a register is read once and carried
    forward, so upgrading loses nothing. The register itself is never rewritten.
    """

    VERSION = 1

    def __init__(self, path: Path = REGISTRY_STATE_FILE):
        self.path = path
        self.vendors: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            blob = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if blob.get("version") != self.VERSION:
            return
        vendors = blob.get("vendors")
        if isinstance(vendors, dict):
            self.vendors = {k: v for k, v in vendors.items() if isinstance(v, dict)}

    def adopt_legacy(self, vendors: list[dict]) -> None:
        """Carry a pre-split ``state:`` block forward, without touching the file."""
        for vendor in vendors:
            slug = vendor.get("slug")
            legacy = vendor.get("state")
            if not slug or slug in self.vendors or not isinstance(legacy, dict):
                continue
            if legacy.get("last_assessed") or legacy.get("snapshot_hashes"):
                self.vendors[slug] = {
                    "last_assessed": legacy.get("last_assessed"),
                    "snapshot_hashes": dict(legacy.get("snapshot_hashes") or {}),
                    "migrated_from_register": True,
                }
                self._dirty = True

    def get(self, slug: str) -> dict[str, Any]:
        return self.vendors.get(slug) or {}

    def record(self, slug: str, *, hashes: dict[str, str]) -> None:
        self.vendors[slug] = {
            "last_assessed": datetime.now(timezone.utc).isoformat(),
            "snapshot_hashes": dict(hashes),
        }
        self._dirty = True

    def save(self, cfg: RunConfig) -> None:
        if cfg.dry_run or not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"version": self.VERSION, "vendors": self.vendors}, indent=2, default=str
        )
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(self.path)
        self._dirty = False


# ---------------------------------------------------------------------------
# Finding store
# ---------------------------------------------------------------------------
class FindingStore:
    """Persistent findings with lifecycle state (Phase 7.1)."""

    def __init__(self, path: Path = FINDINGS_FILE):
        self.path = path
        self.findings: dict[str, dict] = {}
        self.events: list[dict] = []
        self.meta: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            blob = json.loads(self.path.read_text(encoding="utf-8"))
            self.findings = {f["id"]: f for f in blob.get("findings", [])}
            self.meta = blob.get("meta", {})
            self.events = list(blob.get("events") or [])
        else:
            self.events = []

    def save(self, cfg: RunConfig) -> None:
        if cfg.dry_run:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "meta": {**self.meta, "last_run": datetime.now(timezone.utc).isoformat()},
            "findings": sorted(self.findings.values(), key=lambda f: (f["vendor"], f.get("control_id") or "")),
            "events": self.events,
        }
        self.path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def record_event(self, event: dict) -> dict:
        """Append a structured event. Not a finding — no severity, no due date."""
        self.events.append(event)
        return event

    @property
    def last_run(self) -> str | None:
        return self.meta.get("last_run")

    def get(self, finding_id: str) -> dict | None:
        return self.findings.get(finding_id)

    def upsert(self, finding: dict) -> tuple[dict, bool]:
        """Insert or age an existing finding. Returns (stored, is_new)."""
        existing = self.findings.get(finding["id"])
        today = date.today().isoformat()
        if existing is None:
            finding["first_seen"] = today
            finding["last_seen"] = today
            finding["state"] = finding.get("state", "open")
            finding["state_history"] = [{"date": today, "state": finding["state"], "note": "raised"}]
            # Honour a deadline the caller supplied (a migration or an import
            # can carry real history); derive one only when it is absent. For a
            # finding straight out of to_record() these are the same date.
            if not finding.get("due_date"):
                finding["due_date"] = self._due_date(finding)
            self.findings[finding["id"]] = finding
            return finding, True

        # Preserve human-owned lifecycle fields; refresh observed detail.
        existing["last_seen"] = today
        # `due_date` is deliberately NOT refreshed. to_record() derives it from
        # date.today(), so copying it here pushed the deadline forward on every
        # cycle — with a 15-minute monitor a critical finding could never go
        # overdue and the escalation branch below was unreachable.
        for key in ("evidence", "observed", "narrative", "poam", "outreach", "severity",
                    "control_question", "frameworks", "feature", "remediation",
                    "compensating_control", "owner"):
            if key in finding:
                existing[key] = finding[key]
        existing["due_date"] = self._due_date(existing)
        return existing, False

    @staticmethod
    def _due_date(finding: dict) -> str:
        """Deadline measured from when the finding was first raised, not today.

        Re-derived rather than frozen so that editing a control's severity in
        YAML moves the deadline, while the clock still starts at first_seen.
        """
        try:
            raised = date.fromisoformat(finding["first_seen"])
        except (KeyError, TypeError, ValueError):
            return finding.get("due_date") or due_date_for(
                finding.get("severity") or "low", finding.get("kind") or "finding"
            )
        return due_date_for(
            finding.get("severity") or "low",
            finding.get("kind") or "finding",
            today=raised,
        )

    def age_days(self, finding: dict) -> int:
        try:
            first = date.fromisoformat(finding["first_seen"])
        except (KeyError, ValueError):
            return 0
        return (date.today() - first).days

    def is_overdue(self, finding: dict) -> bool:
        due = finding.get("due_date")
        if not due or finding.get("state") in ("closed", "accepted_risk"):
            return False
        try:
            return date.fromisoformat(due) < date.today()
        except ValueError:
            return False

    def reconcile(self, seen_ids: set[str], vendor_slugs: set[str], cfg: RunConfig) -> list[dict]:
        """Phase 7.2 — close findings the new snapshot resolves, escalate overdue.

        Only findings for vendors assessed in THIS run are eligible for auto
        close, so a filtered run cannot silently close the rest of the portfolio.
        """
        closed: list[dict] = []
        today = date.today().isoformat()
        for fid, finding in self.findings.items():
            if finding["vendor"] not in vendor_slugs:
                continue
            if finding.get("state") in ("closed", "accepted_risk"):
                continue
            if fid not in seen_ids:
                finding["state"] = "closed"
                finding["closed_date"] = today
                finding["closure_reason"] = "condition no longer observed in current assessment"
                finding.setdefault("state_history", []).append(
                    {"date": today, "state": "closed", "note": "auto-closed: condition resolved"}
                )
                closed.append(finding)
            elif self.is_overdue(finding) and not finding.get("escalated"):
                finding["escalated"] = True
                finding.setdefault("state_history", []).append(
                    {"date": today, "state": finding["state"], "note": "escalated: past due date"}
                )
        return closed
