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

from .config import FINDINGS_FILE, VENDORS_DIR, RunConfig

REQUIRED_KEYS = ("vendor", "slug", "tier")


def load_vendors(cfg: RunConfig) -> list[dict]:
    vendors: list[dict] = []
    for path in sorted(VENDORS_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path} does not contain a mapping")
        missing = [k for k in REQUIRED_KEYS if k not in data]
        if missing:
            raise ValueError(f"{path} missing required keys: {missing}")
        data["_path"] = str(path)
        if cfg.vendors and data["slug"] not in cfg.vendors and data["vendor"] not in cfg.vendors:
            continue
        vendors.append(data)
    return vendors


def update_vendor_state(vendor: dict, *, hashes: dict[str, str], cfg: RunConfig) -> None:
    """Write back only the machine-owned `state:` block of the vendor YAML.

    Rewrites the file with yaml.safe_dump, so comments in the human-authored
    portion are not preserved. In dry-run this is skipped entirely.
    """
    if cfg.dry_run:
        return
    path = Path(vendor["_path"])
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    state = data.setdefault("state", {}) or {}
    state["last_assessed"] = datetime.now(timezone.utc).isoformat()
    state["snapshot_hashes"] = hashes
    data["state"] = state
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Finding store
# ---------------------------------------------------------------------------
class FindingStore:
    """Persistent findings with lifecycle state (Phase 7.1)."""

    def __init__(self, path: Path = FINDINGS_FILE):
        self.path = path
        self.findings: dict[str, dict] = {}
        self.meta: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            blob = json.loads(self.path.read_text(encoding="utf-8"))
            self.findings = {f["id"]: f for f in blob.get("findings", [])}
            self.meta = blob.get("meta", {})

    def save(self, cfg: RunConfig) -> None:
        if cfg.dry_run:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "meta": {**self.meta, "last_run": datetime.now(timezone.utc).isoformat()},
            "findings": sorted(self.findings.values(), key=lambda f: (f["vendor"], f["control_id"])),
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

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
            self.findings[finding["id"]] = finding
            return finding, True

        # Preserve human-owned lifecycle fields; refresh observed detail.
        existing["last_seen"] = today
        for key in ("evidence", "observed", "narrative", "poam", "outreach", "severity",
                    "control_question", "frameworks", "feature", "remediation",
                    "compensating_control", "due_date", "owner"):
            if key in finding:
                existing[key] = finding[key]
        return existing, False

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
