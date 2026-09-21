"""Alerts for the security team.

An exception sitting in a file nobody opens is not a monitored control. This is
the delivery half: when something becomes true that was not true last cycle,
somebody is told.

What is worth waking someone for
--------------------------------
Only transitions. A finding the monitor re-sees every fifteen minutes is not
news on the second cycle, and a channel that repeats it becomes a channel people
mute. So alerts fire on four state changes and nothing else:

    new_finding        it was not there last cycle
    overdue            it passed its remediation deadline
    resolved           it cleared, which is also worth knowing
    firmware_rejected  a package failed verification at the gate

`cipstate.TrackedFinding` carries the idempotency flags, so re-detection is
silent until the state actually moves again.

Who the alert names
-------------------
The obligation, not the vendor. CIP-003-9 Attachment 1 Section 6 obliges the
*Responsible Entity* to have a process for low impact assets that allow vendor
electronic remote access. The vendor is not the non-compliant party; the utility
is. An alert that reads "this vendor is not compliant with CIP-003-9" is wrong
on the facts and a compliance lead will say so, so the message names the asset
and the requirement, and mentions the vendor only as context.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import DATA_DIR
from .cipstate import TrackedFinding

CIP_ALERT_LOG = DATA_DIR / "cip_alerts.jsonl"

NEW = "new_finding"
OVERDUE = "overdue"
RESOLVED = "resolved"
FIRMWARE_REJECTED = "firmware_rejected"

# Who to route to, by severity. Deterministic policy, kept out of the model's
# reach for the same reason due dates are.
ROUTE_BY_SEVERITY = {
    "critical": "CIP Senior Manager / Security on-call",
    "high": "Compliance lead",
    "medium": "Vendor risk analyst",
    "low": "Vendor management",
    "info": "Vendor risk analyst",
}


@dataclass
class Alert:
    kind: str
    severity: str
    control_id: str
    citation: str
    asset: str
    message: str
    route_to: str
    raised_at: str
    finding_id: str = ""
    due_date: str = ""
    days_overdue: int = 0
    vendor: str = ""
    remediation: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    def as_line(self) -> str:
        return json.dumps(asdict(self), default=str)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _asset_of(finding: TrackedFinding) -> str:
    """Name the thing an engineer has to go look at."""
    if finding.substation_id and finding.substation_id not in ("", "None"):
        return f"{finding.substation_id} / {finding.subject}"
    return finding.subject or "(unidentified asset)"


def _problem(finding: TrackedFinding) -> str:
    """One clause saying what is actually wrong.

    The control's question is phrased as a question ("Is there a method to
    disable..."), which reads badly in an alert. The observed values say which
    way it was answered, so the alert states the failing condition rather than
    re-asking the question.
    """
    bad = [f"{k}={v}" for k, v in (finding.observed or {}).items()
           if k not in ("substation_id", "impact_rating")]
    detail = ", ".join(bad[:3])
    question = " ".join((finding.question or "").split()).rstrip("?")
    # An alert is read on a phone at 2am. The control's full question can run to
    # three lines, so it is cut at a clause boundary -- the citation and the
    # observed values carry the precision, the prose only has to orient.
    if len(question) > 95:
        cut = question[:95].rsplit(",", 1)[0].rsplit(" ", 1)[0]
        question = cut + "…"
    return f"{question} — observed {detail}" if detail else question


def for_new(finding: TrackedFinding, when: date) -> Alert:
    return Alert(
        kind=NEW,
        severity=finding.severity,
        control_id=finding.control_id,
        citation=finding.citation,
        asset=_asset_of(finding),
        vendor=finding.vendor,
        finding_id=finding.id,
        due_date=finding.due_date,
        remediation=finding.remediation,
        route_to=ROUTE_BY_SEVERITY.get(finding.severity, "Vendor risk analyst"),
        raised_at=_now(),
        context=dict(finding.observed or {}),
        message=(
            f"{_asset_of(finding)}: {_problem(finding)}. "
            f"{finding.citation}. Remediate by {finding.due_date}."
        ),
    )


def for_overdue(finding: TrackedFinding, when: date) -> Alert:
    try:
        days = (when - date.fromisoformat(finding.due_date)).days
    except ValueError:
        days = 0
    return Alert(
        kind=OVERDUE,
        severity=finding.severity,
        control_id=finding.control_id,
        citation=finding.citation,
        asset=_asset_of(finding),
        vendor=finding.vendor,
        finding_id=finding.id,
        due_date=finding.due_date,
        days_overdue=days,
        remediation=finding.remediation,
        route_to=ROUTE_BY_SEVERITY.get(finding.severity, "Vendor risk analyst"),
        raised_at=_now(),
        context=dict(finding.observed or {}),
        message=(
            f"OVERDUE {days}d — {_asset_of(finding)}: {_problem(finding)}. "
            f"{finding.citation}. Was due {finding.due_date}, open since "
            f"{finding.first_seen[:10]}."
        ),
    )


def group_key(finding: TrackedFinding) -> tuple:
    """What makes two findings the same problem.

    131 relays failing CIP-010 R1.6.2 is one substituted firmware package, not
    131 incidents. Paging someone 131 times for it guarantees they stop reading
    the channel, and the 132nd alert -- the one about something else -- is the
    one they miss. So findings are grouped by control and by the observed values
    that caused them, with the asset identity deliberately excluded from the key.
    """
    observed = tuple(sorted(
        (k, str(v)) for k, v in (finding.observed or {}).items()
        if k not in ("substation_id", "impact_rating")
    ))
    return (finding.control_id, finding.severity, observed)


def group_new(findings: list[TrackedFinding], when: date) -> list[Alert]:
    """One alert per distinct problem, naming how many assets it hits."""
    groups: dict[tuple, list[TrackedFinding]] = {}
    for finding in findings:
        groups.setdefault(group_key(finding), []).append(finding)

    alerts: list[Alert] = []
    for members in groups.values():
        first = members[0]
        alert = for_new(first, when)
        if len(members) == 1:
            alerts.append(alert)
            continue
        examples = ", ".join(_asset_of(m) for m in members[:3])
        more = len(members) - 3
        alert.asset = f"{len(members)} assets"
        alert.context["affected_count"] = len(members)
        alert.context["example_assets"] = [_asset_of(m) for m in members[:5]]
        alert.context["finding_ids"] = [m.id for m in members]
        alert.message = (
            f"{len(members)} assets: {_problem(first)}. {first.citation}. "
            f"e.g. {examples}{f', +{more} more' if more > 0 else ''}. "
            f"Remediate by {first.due_date}."
        )
        alerts.append(alert)
    return sorted(alerts, key=lambda a: (
        {"critical": 0, "high": 1, "medium": 2}.get(a.severity, 3),
        -int(a.context.get("affected_count", 1)),
    ))


def for_resolved(finding: TrackedFinding, when: date) -> Alert:
    return Alert(
        kind=RESOLVED,
        severity=finding.severity,
        control_id=finding.control_id,
        citation=finding.citation,
        asset=_asset_of(finding),
        vendor=finding.vendor,
        finding_id=finding.id,
        due_date=finding.due_date,
        route_to=ROUTE_BY_SEVERITY.get(finding.severity, "Vendor risk analyst"),
        raised_at=_now(),
        message=(
            f"CLEARED — {_asset_of(finding)}: {finding.control_id} no longer "
            f"failing ({finding.citation}), open {finding.days_open(when)}d."
        ),
    )


def group_resolved(findings: list[TrackedFinding], when: date) -> list[Alert]:
    """Clearing 51 findings is one remediation, not 51 pieces of good news."""
    groups: dict[tuple, list[TrackedFinding]] = {}
    for finding in findings:
        groups.setdefault(group_key(finding), []).append(finding)

    alerts: list[Alert] = []
    for members in groups.values():
        first = members[0]
        alert = for_resolved(first, when)
        if len(members) > 1:
            alert.asset = f"{len(members)} assets"
            alert.context["affected_count"] = len(members)
            alert.context["finding_ids"] = [m.id for m in members]
            alert.message = (
                f"CLEARED — {len(members)} assets: {first.control_id} no longer "
                f"failing ({first.citation}), open {first.days_open(when)}d."
            )
        alerts.append(alert)
    return alerts


def for_rejected_firmware(result, *, package_id: str, target: str = "") -> Alert:
    """The gate refused a package. This is the one alert that blocked an action."""
    return Alert(
        kind=FIRMWARE_REJECTED,
        severity="critical",
        control_id="CIP-01/CIP-02",
        citation="CIP-010-4 R1 Part 1.6",
        asset=target or package_id,
        route_to=ROUTE_BY_SEVERITY["critical"],
        raised_at=_now(),
        context={
            "package_id": package_id,
            "computed_sha256": result.computed_sha256,
            "published_sha256": result.published_sha256,
            "hash_match": result.hash_match,
            "signature_verified": result.signature_verified,
            "signing_key_status": result.signing_key_status,
            "evidence": result.evidence,
        },
        remediation=(
            "Do not deploy. Quarantine the binary, re-obtain from the vendor's "
            "authenticated distribution channel, and re-verify."
        ),
        message=(
            f"DEPLOYMENT BLOCKED — {package_id} failed CIP-010 R1.6 verification "
            f"(hash_match={result.hash_match}, "
            f"signature_verified={result.signature_verified}). Not flashed."
        ),
    )


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------
def append(alerts: Iterable[Alert], path: Path | None = None) -> Path:
    """Append to the alert log.

    JSONL, append-only, one alert per line. Chosen over a database because the
    thing a security team actually needs is something their existing log
    shipper can tail, and over an outbound integration because that would need
    credentials this tool deliberately does not hold.
    """
    path = path or CIP_ALERT_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(alert.as_line() + "\n")
    return path


def webhook_url() -> str | None:
    """Optional. Set VRA_CIP_WEBHOOK to POST alerts somewhere.

    Unset by default: the tool should be useful with no network and no
    credentials, and a demo that needs a webhook to show anything is a demo that
    fails on conference wifi.
    """
    return os.environ.get("VRA_CIP_WEBHOOK") or None


def post_webhook(alerts: list[Alert], url: str, *, timeout: int = 5) -> tuple[int, str]:
    """Best effort. A failed POST is reported, never fatal.

    An alerting channel that can take the monitor down converts a compliance
    finding into an outage, which is a worse failure than the one it was
    reporting.
    """
    if not alerts:
        return 0, "nothing to send"
    try:
        import requests

        response = requests.post(
            url, json={"alerts": [asdict(a) for a in alerts]}, timeout=timeout
        )
        return response.status_code, response.reason or ""
    except Exception as exc:  # noqa: BLE001
        return 0, f"webhook failed: {exc}"
