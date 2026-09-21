"""Sealed baselines and an agent action ledger.

The problem this solves
-----------------------
Verifying a firmware package once tells you it was authentic *then*. It says
nothing about the vendor's posture drifting afterwards: a signing key quietly
rotated, a release re-published under the same version, a package appearing that
nobody ordered, a contract clause changing. Those are the changes that matter,
because each one is either a legitimate vendor action nobody told you about, or
an attacker establishing a position.

So once a vendor's posture has been checked and accepted, it is **sealed**. From
that point every cycle compares the live posture against the seal, and anything
that moved is drift. Drift is reported and alerted on **unless it carries a
recorded approval** --- which is what "no changes until it is deliberate" means
in practice: not that change is forbidden, but that unannounced change is
indistinguishable from compromise and is treated as such until a human says
otherwise.

Why the agent's own actions are logged
--------------------------------------
Entergy's Item 1A names "threats fueled by artificial intelligence" and states
that it cannot anticipate or detect all threats. A tool that answers that by
putting an AI in the decision path had better be able to say what the AI did.

So every model invocation is appended to a ledger: what it was asked, a digest
of what it was shown, what it decided, with what confidence, on which model
build. That gives three things a security team actually needs --- a record of
whether the agent's behaviour changed over time, the ability to re-run a past
decision against the same inputs, and evidence for an auditor who asks what the
AI was allowed to do.

The ledger is append-only. Baselines carry a digest of their own contents, so a
baseline that has been edited no longer matches itself and says so.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import DATA_DIR

BASELINE_FILE = DATA_DIR / "cip_baselines.json"
AGENT_LOG = DATA_DIR / "cip_agent_actions.jsonl"
APPROVAL_LOG = DATA_DIR / "cip_approvals.jsonl"

# Drift kinds, ordered worst first. A key whose fingerprint moved is the most
# serious: a vendor re-keying without notice is indistinguishable from an
# attacker substituting a key, and it invalidates every signature check after it.
KEY_FINGERPRINT_CHANGED = "key_fingerprint_changed"
PACKAGE_HASH_CHANGED = "package_hash_changed"
PACKAGE_SIGNATURE_CHANGED = "package_signature_changed"
KEY_STATUS_CHANGED = "key_status_changed"
KEY_REMOVED = "key_removed"
PACKAGE_REMOVED = "package_removed"
KEY_ADDED = "key_added"
PACKAGE_ADDED = "package_added"
CLAUSE_CHANGED = "clause_changed"

SEVERITY = {
    KEY_FINGERPRINT_CHANGED: "critical",
    PACKAGE_HASH_CHANGED: "critical",
    PACKAGE_SIGNATURE_CHANGED: "critical",
    KEY_STATUS_CHANGED: "high",
    KEY_REMOVED: "high",
    PACKAGE_REMOVED: "medium",
    KEY_ADDED: "high",
    PACKAGE_ADDED: "medium",
    CLAUSE_CHANGED: "high",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()


# ---------------------------------------------------------------------------
# Posture and baselines
# ---------------------------------------------------------------------------
@dataclass
class VendorPosture:
    """Everything about a vendor that should not change without notice."""

    vendor: str
    packages: dict[str, dict] = field(default_factory=dict)
    keys: dict[str, dict] = field(default_factory=dict)
    clauses: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return {"vendor": self.vendor, "packages": self.packages,
                "keys": self.keys, "clauses": self.clauses}

    @property
    def digest(self) -> str:
        return _digest(self.as_payload())


def posture_from_estate(vendor: str, estate, verified: dict) -> VendorPosture:
    """Read a vendor's current posture out of the estate and the verification run."""
    low = vendor.strip().lower()
    posture = VendorPosture(vendor=vendor)

    for package_id, package in estate.packages.items():
        if str(package.get("vendor", "")).strip().lower() != low:
            continue
        result = verified.get(package_id)
        posture.packages[package_id] = {
            # The computed hash, not the published one: the question is whether
            # the bytes changed, and the published digest is attacker-controlled
            # in exactly the scenario this is watching for.
            "sha256": result.computed_sha256 if result else None,
            "signature": str(package.get("signature", ""))[:32],
            "signing_key_id": package.get("signing_key_id"),
            "version": package.get("version"),
        }

    for key in estate.registry.for_vendor(vendor):
        posture.keys[key.key_id] = {
            "fingerprint": key.fingerprint,
            "status": key.status,
            "valid_until": key.valid_until,
        }

    for record in estate.vendors:
        if str(record.get("vendor", "")).strip().lower() == low:
            posture.clauses = dict(record.get("contract") or {})

    return posture


@dataclass
class Drift:
    kind: str
    vendor: str
    subject: str
    before: Any
    after: Any
    severity: str = "high"
    deliberate: bool = False
    approval: dict | None = None

    @property
    def key(self) -> str:
        """Stable identity for an approval to attach to."""
        return f"{self.vendor}|{self.kind}|{self.subject}|{_digest(self.after)[:12]}"

    def describe(self) -> str:
        return (f"{self.vendor}: {self.kind.replace('_', ' ')} on {self.subject} "
                f"({self.before!r} -> {self.after!r})")


def detect_drift(current: VendorPosture, baseline: dict) -> list[Drift]:
    """Compare a live posture against its seal.

    Additions are drift too, not just changes. A package or a key appearing that
    was not in the sealed set is exactly what an attacker establishing a
    position looks like, and treating only modifications as drift would miss it.
    """
    drifts: list[Drift] = []
    vendor = current.vendor
    old_packages = baseline.get("packages", {}) or {}
    old_keys = baseline.get("keys", {}) or {}
    old_clauses = baseline.get("clauses", {}) or {}

    for package_id, now in current.packages.items():
        was = old_packages.get(package_id)
        if was is None:
            drifts.append(Drift(PACKAGE_ADDED, vendor, package_id, None,
                                now.get("version"), SEVERITY[PACKAGE_ADDED]))
            continue
        if was.get("sha256") != now.get("sha256"):
            drifts.append(Drift(PACKAGE_HASH_CHANGED, vendor, package_id,
                                was.get("sha256"), now.get("sha256"),
                                SEVERITY[PACKAGE_HASH_CHANGED]))
        if was.get("signature") != now.get("signature"):
            drifts.append(Drift(PACKAGE_SIGNATURE_CHANGED, vendor, package_id,
                                was.get("signature"), now.get("signature"),
                                SEVERITY[PACKAGE_SIGNATURE_CHANGED]))

    for package_id, was in old_packages.items():
        if package_id not in current.packages:
            drifts.append(Drift(PACKAGE_REMOVED, vendor, package_id,
                                was.get("version"), None, SEVERITY[PACKAGE_REMOVED]))

    for key_id, now in current.keys.items():
        was = old_keys.get(key_id)
        if was is None:
            drifts.append(Drift(KEY_ADDED, vendor, key_id, None,
                                now.get("fingerprint"), SEVERITY[KEY_ADDED]))
            continue
        if was.get("fingerprint") != now.get("fingerprint"):
            drifts.append(Drift(KEY_FINGERPRINT_CHANGED, vendor, key_id,
                                was.get("fingerprint"), now.get("fingerprint"),
                                SEVERITY[KEY_FINGERPRINT_CHANGED]))
        if was.get("status") != now.get("status"):
            drifts.append(Drift(KEY_STATUS_CHANGED, vendor, key_id,
                                was.get("status"), now.get("status"),
                                SEVERITY[KEY_STATUS_CHANGED]))

    for key_id, was in old_keys.items():
        if key_id not in current.keys:
            drifts.append(Drift(KEY_REMOVED, vendor, key_id,
                                was.get("fingerprint"), None, SEVERITY[KEY_REMOVED]))

    for clause, now in current.clauses.items():
        if clause in old_clauses and old_clauses[clause] != now:
            drifts.append(Drift(CLAUSE_CHANGED, vendor, clause,
                                old_clauses[clause], now, SEVERITY[CLAUSE_CHANGED]))

    order = list(SEVERITY)
    return sorted(drifts, key=lambda d: order.index(d.kind))


class BaselineStore:
    """Sealed vendor postures, with a digest so an edited seal reveals itself."""

    def __init__(self, path: Path | None = None):
        self.path = path or BASELINE_FILE
        self._by_vendor: dict[str, dict] = {}

    def load(self) -> "BaselineStore":
        if not self.path.is_file():
            return self
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return self
        self._by_vendor = raw.get("baselines", {}) or {}
        return self

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"updated_at": _now(), "baselines": self._by_vendor}, indent=2),
            encoding="utf-8")
        return self.path

    def get(self, vendor: str) -> dict | None:
        return self._by_vendor.get(vendor)

    def vendors(self) -> list[str]:
        return sorted(self._by_vendor)

    def seal(self, posture: VendorPosture, *, sealed_by: str, note: str = "") -> dict:
        payload = posture.as_payload()
        record = {
            **payload,
            "sealed_at": _now(),
            "sealed_by": sealed_by,
            "note": note,
            "seal_digest": posture.digest,
        }
        self._by_vendor[posture.vendor] = record
        return record

    def tampered(self, vendor: str) -> bool:
        """True when a stored baseline no longer matches its own digest.

        A seal is only worth something if editing it is detectable. This does
        not stop an attacker who can also recompute the digest -- it stops a
        silent edit, which is the realistic case.
        """
        record = self._by_vendor.get(vendor)
        if not record or "seal_digest" not in record:
            return False
        payload = {k: record.get(k) for k in ("vendor", "packages", "keys", "clauses")}
        return _digest(payload) != record["seal_digest"]


# ---------------------------------------------------------------------------
# Approvals — what makes a change deliberate
# ---------------------------------------------------------------------------
def approve(drift: Drift, *, who: str, why: str, path: Path | None = None) -> Path:
    """Record that a change was intended. Append-only."""
    path = path or APPROVAL_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "approved_at": _now(), "drift_key": drift.key, "kind": drift.kind,
            "vendor": drift.vendor, "subject": drift.subject,
            "before": drift.before, "after": drift.after,
            "approved_by": who, "reason": why,
        }, default=str) + "\n")
    return path


def load_approvals(path: Path | None = None) -> dict[str, dict]:
    path = path or APPROVAL_LOG
    if not path.is_file():
        return {}
    out: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        out[record.get("drift_key", "")] = record
    return out


def mark_deliberate(drifts: Iterable[Drift], approvals: dict[str, dict]) -> list[Drift]:
    """Attach approvals. An approval is keyed to the exact before/after pair, so
    approving one key rotation does not silently bless the next one."""
    out = []
    for drift in drifts:
        record = approvals.get(drift.key)
        if record:
            drift.deliberate = True
            drift.approval = record
        out.append(drift)
    return out


# ---------------------------------------------------------------------------
# Agent action ledger
# ---------------------------------------------------------------------------
@dataclass
class AgentAction:
    task: str
    backend: str
    model: str
    input_digest: str
    disposition: str = ""
    risk: str = ""
    confidence: float = 0.0
    reasoning: str = ""
    schema_ok: bool = True
    subject: str = ""
    at: str = field(default_factory=_now)


def record_action(action: AgentAction, path: Path | None = None) -> Path:
    """Append one model invocation to the ledger.

    Append-only and never rewritten, so the record of what the agent did cannot
    be quietly revised by a later run.
    """
    path = path or AGENT_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(action), default=str) + "\n")
    return path


def action_from_judgment(judgment, *, subject: str, brief=None) -> AgentAction:
    """Build a ledger entry from an analyst judgement.

    The brief is digested rather than stored. It is large, it is already
    reproducible from the estate and the bytes, and what matters for an audit is
    whether the agent saw the *same* inputs -- which a digest answers exactly.
    """
    return AgentAction(
        task="firmware_disposition",
        backend=judgment.backend or "unknown",
        model=judgment.model or "",
        input_digest=_digest(brief.as_prompt()) if brief is not None else "",
        disposition=judgment.disposition,
        risk=judgment.risk,
        confidence=judgment.confidence,
        reasoning=judgment.reasoning[:400],
        schema_ok=judgment.ok,
        subject=subject,
    )


def read_actions(path: Path | None = None, limit: int = 50) -> list[dict]:
    path = path or AGENT_LOG
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def agent_behaviour_summary(actions: list[dict]) -> dict[str, Any]:
    """Has the agent's behaviour changed over time?

    A model that starts allowing what it used to block --- because the model
    build changed, a prompt changed, or it is being steered --- is something a
    security team needs to see. Counting dispositions per model build is the
    cheapest useful version of that.
    """
    by_model: dict[str, dict[str, int]] = {}
    repeats: dict[str, set] = {}
    for action in actions:
        model = f"{action.get('backend', '?')}/{action.get('model', '')}".rstrip("/")
        bucket = by_model.setdefault(model, {})
        bucket[action.get("disposition", "?")] = bucket.get(action.get("disposition", "?"), 0) + 1
        digest = action.get("input_digest")
        if digest:
            repeats.setdefault(digest, set()).add(action.get("disposition", "?"))
    # Same inputs, different answer: either the model is non-deterministic or
    # something about it changed. Either way it is worth surfacing.
    inconsistent = [d for d, seen in repeats.items() if len(seen) > 1]
    return {
        "actions": len(actions),
        "by_model": by_model,
        "schema_failures": sum(1 for a in actions if not a.get("schema_ok", True)),
        "inconsistent_repeats": len(inconsistent),
    }
