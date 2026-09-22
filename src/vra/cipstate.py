"""Finding lifecycle for the NERC path.

Without this the tool is a report generator: every run recomputes from scratch,
so it can say what is wrong right now but not what *changed*, not what is new,
and not what has been sitting open past its remediation deadline. "This
substation started failing yesterday" is the sentence a monitor exists to say,
and it needs memory to say it.

What is persisted, and what is not
----------------------------------
Only the finding lifecycle. The estate, the verification results and the
coverage tallies are all recomputed every cycle from the assets and the bytes
on disk, because those are facts about the world rather than decisions about
it. What is worth remembering is the human-facing state: when a finding was
FIRST raised, whether anyone has been told, and whether it has since cleared.

Due dates are anchored to first_seen
------------------------------------
A finding the monitor re-sees every fifteen minutes must still go overdue. If
the due date were recomputed each cycle from today, nothing would ever be late
and the deadline would be decorative. So the due date is set once, when the
finding is first raised, and survives re-detection. Re-rating a control in YAML
moves the deadline for findings raised after that point; it does not restart the
clock on existing ones.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import DATA_DIR

CIP_FINDINGS_FILE = DATA_DIR / "cip_findings.json"

STATE_OPEN = "open"
STATE_CLOSED = "closed"


@dataclass
class TrackedFinding:
    """One finding, across runs."""

    id: str
    kind: str                  # finding | gap
    control_id: str
    citation: str
    severity: str
    subject: str               # the asset / session / person / contract
    substation_id: str
    vendor: str
    question: str
    observed: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    first_seen: str = ""
    last_seen: str = ""
    due_date: str = ""
    state: str = STATE_OPEN
    closed_on: str | None = None
    # Alerting is idempotent: a finding the monitor re-sees every cycle must
    # not re-alert every cycle, or the channel becomes noise and people stop
    # reading it. These record what has already been announced.
    alerted_new: bool = False
    alerted_overdue: bool = False

    def is_overdue(self, when: date) -> bool:
        if self.state != STATE_OPEN or not self.due_date:
            return False
        try:
            return date.fromisoformat(self.due_date) < when
        except ValueError:
            return False

    def days_open(self, when: date) -> int:
        """Never negative.

        `when` is the assessment date, which can be pinned in the past for a
        reproducible run, while first_seen is real wall-clock time. That made
        "open -1d" reachable, and a negative age in an audit artifact reads as
        a broken tool rather than a pinned clock.
        """
        try:
            return max(0, (when - date.fromisoformat(self.first_seen[:10])).days)
        except (ValueError, IndexError):
            return 0


@dataclass
class ReconcileResult:
    """What changed this cycle."""

    new: list[TrackedFinding] = field(default_factory=list)
    reopened: list[TrackedFinding] = field(default_factory=list)
    still_open: list[TrackedFinding] = field(default_factory=list)
    resolved: list[TrackedFinding] = field(default_factory=list)
    newly_overdue: list[TrackedFinding] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.new or self.reopened or self.resolved or self.newly_overdue)

    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "reopened": len(self.reopened),
            "still_open": len(self.still_open),
            "resolved": len(self.resolved),
            "newly_overdue": len(self.newly_overdue),
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FindingStore:
    """The durable record of what has been found, and when."""

    def __init__(self, path: Path | None = None):
        self.path = path or CIP_FINDINGS_FILE
        self._by_id: dict[str, TrackedFinding] = {}

    def load(self) -> "FindingStore":
        if not self.path.is_file():
            return self
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt store must not take the monitor down. Losing history is
            # bad; refusing to assess anything at all is worse, and the next
            # save rewrites it cleanly.
            return self
        for item in raw.get("findings", []):
            known = {f.name for f in TrackedFinding.__dataclass_fields__.values()}
            self._by_id[item["id"]] = TrackedFinding(**{k: v for k, v in item.items() if k in known})
        return self

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {
                    "updated_at": _now(),
                    "findings": [asdict(f) for f in self._by_id.values()],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return self.path

    def open_findings(self) -> list[TrackedFinding]:
        return [f for f in self._by_id.values() if f.state == STATE_OPEN]

    def all(self) -> list[TrackedFinding]:
        return list(self._by_id.values())

    def get(self, finding_id: str) -> TrackedFinding | None:
        return self._by_id.get(finding_id)

    def reconcile(self, records: Iterable[dict], when: date | None = None) -> ReconcileResult:
        """Fold this cycle's assessment into the stored lifecycle.

        `records` are the finding records produced by `evaluate.to_record`, which
        already carry a stable id derived from vendor + subject + control + kind.
        That stability is what makes cross-run tracking possible at all: a
        finding must be the same finding next cycle or every run looks new.
        """
        when = when or date.today()
        stamp = _now()
        result = ReconcileResult()
        seen: set[str] = set()

        for record in records:
            fid = record["id"]
            seen.add(fid)
            existing = self._by_id.get(fid)

            if existing is None:
                tracked = TrackedFinding(
                    id=fid,
                    kind=record.get("kind", "finding"),
                    control_id=record.get("control_id", ""),
                    citation=record.get("citation", ""),
                    severity=record.get("severity", "info"),
                    subject=record.get("feature", ""),
                    substation_id=str((record.get("observed") or {}).get("substation_id", "")),
                    vendor=record.get("vendor_name", ""),
                    question=record.get("control_question", ""),
                    observed=record.get("observed", {}),
                    remediation=record.get("remediation", ""),
                    first_seen=stamp,
                    last_seen=stamp,
                    # Set once, here. Never recomputed.
                    due_date=record.get("due_date", ""),
                )
                self._by_id[fid] = tracked
                result.new.append(tracked)
                continue

            existing.last_seen = stamp
            # Refresh the descriptive fields -- the control's wording or
            # remediation may have been edited in YAML -- but never first_seen
            # or due_date.
            existing.question = record.get("control_question", existing.question)
            existing.remediation = record.get("remediation", existing.remediation)
            existing.observed = record.get("observed", existing.observed)
            existing.severity = record.get("severity", existing.severity)
            existing.citation = record.get("citation", existing.citation)

            if existing.state == STATE_CLOSED:
                # It came back. A reopened finding keeps its original first_seen
                # so the record shows how long this has really been a problem,
                # and is announced again because a recurrence is news.
                existing.state = STATE_OPEN
                existing.closed_on = None
                existing.alerted_new = False
                existing.alerted_overdue = False
                result.reopened.append(existing)
            else:
                result.still_open.append(existing)

            if existing.is_overdue(when) and not existing.alerted_overdue:
                result.newly_overdue.append(existing)

        # Anything tracked as open that this cycle did not re-see has cleared.
        for tracked in self._by_id.values():
            if tracked.state == STATE_OPEN and tracked.id not in seen:
                tracked.state = STATE_CLOSED
                tracked.closed_on = stamp
                tracked.last_seen = stamp
                result.resolved.append(tracked)

        return result

    def mark_alerted(self, findings: Iterable[TrackedFinding], *, overdue: bool = False) -> None:
        for finding in findings:
            if overdue:
                finding.alerted_overdue = True
            else:
                finding.alerted_new = True
