"""Phase 1 / Phase 7 — the vendor register and persistent finding state.

The register is the analyst's case file. Vendor definitions are hand-authored
YAML the human owns; findings are machine-maintained JSON with lifecycle state.
Keeping them in separate files matters: the tool never rewrites the file a human
is responsible for.
"""

from __future__ import annotations

import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import (
    EVENT_HOT_MAX,
    EVENT_RETENTION_DAYS,
    EVENTS_ARCHIVE_DIR,
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
        self.rolled = 0
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
        # Every persist is the systemic point where the event log is bounded.
        # roll_events keeps the running total itself, so a prune done through
        # `vra events prune` is counted the same as one done by a cycle.
        self.rolled = self.roll_events()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "meta": {**self.meta, "last_run": datetime.now(timezone.utc).isoformat()},
            "findings": sorted(self.findings.values(), key=lambda f: (f["vendor"], f.get("control_id") or "")),
            "events": self.events,
        }
        self.path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    # -- event retention ----------------------------------------------------
    @staticmethod
    def _event_month(event: dict) -> str:
        """Archive bucket for an event. Unparseable stamps get their own file."""
        raw = str(event.get("timestamp") or "")[:7]
        try:
            datetime.strptime(raw, "%Y-%m")
        except ValueError:
            return "unknown"
        return raw

    @staticmethod
    def _event_age_days(event: dict) -> float:
        """Days since the event. An unparseable stamp counts as ancient."""
        raw = str(event.get("timestamp") or "")
        try:
            stamped = datetime.fromisoformat(raw)
        except ValueError:
            return float("inf")
        if stamped.tzinfo is None:
            stamped = stamped.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - stamped).total_seconds() / 86400

    def roll_events(
        self,
        *,
        retention_days: int | None = None,
        hot_max: int | None = None,
        archive_dir: Path | None = None,
    ) -> int:
        """Move aged events out of the hot store into a dated archive.

        Two bounds, because either alone can be defeated: anything older than
        the retention window rolls, and if a burst still leaves more than
        ``hot_max`` the oldest roll too.

        The archive is written BEFORE the hot store is trimmed. If the archive
        write fails the events stay hot — this is the only record that a
        permission ever changed, so it is never traded for a smaller file.
        Returns how many were archived.
        """
        # Resolved here, not bound as defaults, so the destination and the
        # thresholds can be redirected without reimporting the module.
        retention_days = EVENT_RETENTION_DAYS if retention_days is None else retention_days
        hot_max = EVENT_HOT_MAX if hot_max is None else hot_max
        archive_dir = archive_dir or EVENTS_ARCHIVE_DIR

        if not self.events:
            return 0

        ordered = sorted(self.events, key=self._event_age_days, reverse=True)
        aged = [e for e in ordered if self._event_age_days(e) > retention_days]
        keep = [e for e in ordered if self._event_age_days(e) <= retention_days]
        if len(keep) > hot_max:
            overflow = len(keep) - hot_max
            aged.extend(keep[:overflow])
            keep = keep[overflow:]
        if not aged:
            return 0

        by_month: dict[str, list[dict]] = {}
        for event in aged:
            by_month.setdefault(self._event_month(event), []).append(event)

        try:
            archive_dir.mkdir(parents=True, exist_ok=True)
            for month, rows in sorted(by_month.items()):
                target = archive_dir / f"events-{month}.jsonl"
                with target.open("a", encoding="utf-8") as fh:
                    for event in rows:
                        fh.write(json.dumps(event, default=str, ensure_ascii=False) + "\n")
        except OSError as exc:
            # Keep everything. A bounded file is not worth a lost audit record.
            print(
                f"vra: could not archive {len(aged)} event(s) ({exc}); "
                "keeping them in findings.json",
                file=sys.stderr,
            )
            return 0

        # Restore the caller's original ordering for whatever stays hot.
        kept = set(id(e) for e in keep)
        self.events = [e for e in self.events if id(e) in kept]
        self.meta["events_archived_total"] = (
            int(self.meta.get("events_archived_total") or 0) + len(aged)
        )
        return len(aged)

    @staticmethod
    def archived_events(
        archive_dir: Path | None = None,
        *,
        since: str | None = None,
    ) -> list[dict]:
        """Read events back out of the archive, oldest file first."""
        archive_dir = archive_dir or EVENTS_ARCHIVE_DIR
        rows: list[dict] = []
        if not archive_dir.is_dir():
            return rows
        for path in sorted(archive_dir.glob("events-*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if since and str(event.get("timestamp") or "") < since:
                    continue
                rows.append(event)
        return rows

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
        # Re-observing a closed finding means the condition came back. Leaving
        # it closed would hide a live failure behind a stale resolution — and a
        # finding auto-closed by a cycle that simply could not see the tenant
        # would never reopen once the tenant was reachable again.
        # accepted_risk is a human decision and is never overridden here.
        if existing.get("state") == "closed":
            existing["state"] = "open"
            existing["reopened_date"] = today
            existing.pop("closed_date", None)
            existing.pop("closure_reason", None)
            existing.setdefault("state_history", []).append(
                {"date": today, "state": "open",
                 "note": "reopened: condition observed again"}
            )
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
                # An auto-closure is a machine decision about a control failure.
                # Record it, so the trail shows why a critical stopped being
                # reported rather than it simply vanishing from the report.
                self.record_event({
                    "id": f"closure:{fid}:{today}",
                    "kind": "finding_auto_closed",
                    "family": finding.get("family") or "aiv",
                    "vendor": finding.get("vendor"),
                    "vendor_name": finding.get("vendor_name"),
                    "finding_id": fid,
                    "control_id": finding.get("control_id"),
                    "severity": finding.get("severity"),
                    "feature": finding.get("feature"),
                    "first_seen": finding.get("first_seen"),
                    "reason": finding["closure_reason"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                closed.append(finding)
            elif self.is_overdue(finding) and not finding.get("escalated"):
                finding["escalated"] = True
                finding.setdefault("state_history", []).append(
                    {"date": today, "state": finding["state"], "note": "escalated: past due date"}
                )
        return closed
