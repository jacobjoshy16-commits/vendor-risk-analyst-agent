"""Phase 5 — deterministic control assessment.

No model involvement whatsoever. Controls come from controls.yaml, conditions
are evaluated in code, severity is copied from config. This is the part that has
to survive an auditor asking "why did this fail?", and the answer is always a
condition in a YAML file plus a field in the register.

Central distinction (Phase 5.3): a field of `unknown` produces an INFORMATION
GAP, not a failure. Gaps drive vendor outreach; failures drive remediation. They
are tracked separately all the way through the report.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

import yaml

from .config import (
    CONTROLS_FILE,
    DUE_DAYS_BY_SEVERITY,
    GAP_RESPONSE_DAYS,
    OWNER_BY_SEVERITY,
    UNKNOWN_TOKENS,
)


@dataclass
class Control:
    id: str
    question: str
    frameworks: list[dict]
    severity: str
    fails_when: list[dict] = field(default_factory=list)
    gap_when: list[dict] = field(default_factory=list)
    applies_when: list[dict] = field(default_factory=list)
    remediation: str = ""
    compensating_control: str = ""

    @property
    def citation(self) -> str:
        return "; ".join(f"{f['name']} {f['id']}" for f in self.frameworks)


@dataclass
class Assessment:
    kind: str  # "finding" | "gap"
    vendor: str
    vendor_name: str
    feature: str
    control: Control
    observed: dict[str, Any]
    reason: str
    subject: str = ""          # disambiguator, e.g. a specific subprocessor
    provenance: dict[str, dict] = field(default_factory=dict)

    @property
    def id(self) -> str:
        raw = f"{self.vendor}|{self.feature}|{self.subject}|{self.control.id}|{self.kind}"
        return f"{self.control.id}-{hashlib.sha1(raw.encode()).hexdigest()[:8]}"


def load_controls(path=CONTROLS_FILE) -> list[Control]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    controls = []
    for item in raw:
        controls.append(
            Control(
                id=item["id"],
                question=" ".join(item["question"].split()),
                frameworks=item.get("frameworks", []),
                severity=item["severity"],
                fails_when=item.get("fails_when", []),
                gap_when=item.get("gap_when", []),
                applies_when=item.get("applies_when", []),
                remediation=" ".join((item.get("remediation") or "").split()),
                compensating_control=" ".join((item.get("compensating_control") or "").split()),
            )
        )
    ids = [c.id for c in controls]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate control ids in controls.yaml: {sorted(dupes)}")
    return controls


# ---------------------------------------------------------------------------
# Field resolution and condition operators
# ---------------------------------------------------------------------------
MISSING = object()


def resolve_field(feature: dict, vendor: dict, path: str):
    if path.startswith("contract."):
        return (vendor.get("contract") or {}).get(path.split(".", 1)[1], MISSING)
    if path in feature:
        return feature[path]
    return MISSING


def is_unknown(value) -> bool:
    if value is MISSING:
        return True
    if isinstance(value, str):
        return value.strip().lower() in UNKNOWN_TOKENS
    return value in (None, "")


def _baa_scope_violation(value, vendor: dict) -> bool:
    """Model provider named but not on the vendor's BAA-covered subprocessor list."""
    if is_unknown(value):
        return False  # unknown is a gap on AIV-01, not a BAA failure here
    covered = {c.strip().lower() for c in (vendor.get("contract") or {}).get("baa_covered_subprocessors", [])}
    provider = str(value).strip().lower()
    if not covered:
        return False
    if "in-house" in provider or "in house" in provider:
        return False  # first-party processing is covered by the vendor's own BAA
    return not any(provider in c or c in provider for c in covered)


def evaluate_condition(cond: dict, feature: dict, vendor: dict) -> bool | None:
    """Return True/False, or None when the field is unknown and the operator
    cannot be meaningfully applied (which routes to gap handling)."""
    value = resolve_field(feature, vendor, cond["field"])

    if "is_unknown" in cond:
        return is_unknown(value) == bool(cond["is_unknown"])

    if "not_in_baa_scope" in cond:
        return _baa_scope_violation(value, vendor) == bool(cond["not_in_baa_scope"])

    if is_unknown(value):
        return None

    if "equals" in cond:
        return value == cond["equals"]
    if "not_equals" in cond:
        return value != cond["not_equals"]
    if "in" in cond:
        return value in cond["in"]
    if "not_in" in cond:
        return value not in cond["not_in"]
    if "contains_any" in cond:
        seq = value if isinstance(value, (list, tuple, set)) else [value]
        return any(item in seq for item in cond["contains_any"])
    if "gt" in cond:
        try:
            return float(value) > float(cond["gt"])
        except (TypeError, ValueError):
            return None
    if "lt" in cond:
        try:
            return float(value) < float(cond["lt"])
        except (TypeError, ValueError):
            return None
    if "truthy" in cond:
        return bool(value) == bool(cond["truthy"])
    if "falsy" in cond:
        return (not value) == bool(cond["falsy"])

    raise ValueError(f"unsupported condition: {cond}")


def _observed(conds: list[dict], feature: dict, vendor: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for cond in conds:
        val = resolve_field(feature, vendor, cond["field"])
        out[cond["field"]] = "<not recorded>" if val is MISSING else val
    return out


def evaluate_vendor(
    vendor: dict, controls: list[Control], observed: "ObservedState | None" = None
) -> tuple[list[Assessment], list[Assessment]]:
    """Run every control against every AI feature. Returns (findings, gaps).

    `observed` is the deterministic overlay from observe.py: structured facts
    parsed from vendor artifacts and the tenant API. Overlay values take
    precedence over the register for evaluation, and their provenance is
    recorded on the assessment so the report can show the finding rests on an
    observation rather than on a human-entered field.
    """
    from .observe import ObservedState, effective_feature

    observed = observed or ObservedState(vendor=vendor["slug"])
    findings: list[Assessment] = []
    gaps: list[Assessment] = []

    for raw_feature in vendor.get("ai_surface") or []:
        if raw_feature.get("status") == "disabled":
            continue
        feature, applied = effective_feature(raw_feature, observed)
        for control in controls:
            # applies_when scopes a control to relevant features only.
            if control.applies_when:
                applies = [evaluate_condition(c, feature, vendor) for c in control.applies_when]
                if not all(a is True for a in applies):
                    continue

            fail_results = [evaluate_condition(c, feature, vendor) for c in control.fails_when]
            fails = bool(fail_results) and all(r is True for r in fail_results)

            if fails:
                touched = {c["field"] for c in control.fails_when}
                findings.append(
                    Assessment(
                        kind="finding",
                        vendor=vendor["slug"],
                        vendor_name=vendor["vendor"],
                        feature=feature.get("feature", "(unnamed feature)"),
                        control=control,
                        observed=_observed(control.fails_when, feature, vendor),
                        reason="all failure conditions met",
                        provenance={k: v for k, v in applied.items() if k in touched},
                    )
                )
                continue

            gap_results = [evaluate_condition(c, feature, vendor) for c in control.gap_when]
            unknown_blocks_eval = any(r is None for r in fail_results)
            if any(r is True for r in gap_results) or unknown_blocks_eval:
                conds = control.gap_when or control.fails_when
                gaps.append(
                    Assessment(
                        kind="gap",
                        vendor=vendor["slug"],
                        vendor_name=vendor["vendor"],
                        feature=feature.get("feature", "(unnamed feature)"),
                        control=control,
                        observed=_observed(conds, feature, vendor),
                        reason="required field is unknown; cannot evaluate control",
                    )
                )

    findings.extend(_evaluate_observed_subprocessors(vendor, controls, observed))
    return findings, gaps


def _evaluate_observed_subprocessors(
    vendor: dict, controls: list[Control], observed: "ObservedState"
) -> list[Assessment]:
    """AIV-03 evaluated against the vendor's published subprocessor table.

    This is the buried-row case. The register records one model provider per
    feature, but a vendor can add an AI subprocessor without touching any field
    a human has transcribed. Parsing the table means the finding does not wait
    for the register to catch up — and because the row is structured data, the
    finding is still deterministic and quotable.
    """
    control = next((c for c in controls if c.id == "AIV-03"), None)
    if control is None:
        return []

    surface = vendor.get("ai_surface") or []
    feature_name = surface[0].get("feature", "(vendor AI surface)") if surface else "(vendor AI surface)"
    known = {str((f or {}).get("model_provider", "")).strip().lower() for f in surface}

    out: list[Assessment] = []
    for sp in observed.uncovered_ai_subprocessors:
        low = sp.name.lower()
        already = any(k and (k in low or low in k) for k in known)
        marker = sp.baa_marker.strip().lower()
        # Skip only if the register already names this provider AND the page
        # does not actively contradict its coverage.
        if already and marker not in ("pending", "no", "in progress", "tbd"):
            continue
        out.append(
            Assessment(
                kind="finding",
                vendor=vendor["slug"],
                vendor_name=vendor["vendor"],
                feature=feature_name,
                control=control,
                observed={
                    "subprocessor": sp.name,
                    "purpose": sp.purpose,
                    "baa_status_published": sp.baa_marker or "(not stated)",
                    "region": sp.region,
                },
                reason=(
                    "AI-related subprocessor published by the vendor without executed BAA coverage"
                ),
                subject=sp.name,
                provenance={
                    "subprocessor": {
                        "value": sp.name,
                        "provenance": f"parsed_artifact:{sp.source}",
                        "evidence": sp.raw_line,
                    }
                },
            )
        )
    return out


# ---------------------------------------------------------------------------
# Deterministic due dates and owners (Phase 6.3)
# ---------------------------------------------------------------------------
def due_date_for(severity: str, kind: str = "finding", today: date | None = None) -> str:
    today = today or date.today()
    days = GAP_RESPONSE_DAYS if kind == "gap" else DUE_DAYS_BY_SEVERITY.get(severity, 90)
    return (today + timedelta(days=days)).isoformat()


def owner_for(severity: str, kind: str = "finding") -> str:
    if kind == "gap":
        return "Vendor Risk Analyst"
    return OWNER_BY_SEVERITY.get(severity, "Vendor Management")


def to_record(a: Assessment, *, evidence: list[dict] | None = None) -> dict:
    """Convert an assessment into the persisted finding record shape."""
    return {
        "id": a.id,
        "kind": a.kind,
        "vendor": a.vendor,
        "vendor_name": a.vendor_name,
        "feature": a.feature,
        "control_id": a.control.id,
        "control_question": a.control.question,
        "frameworks": a.control.frameworks,
        "citation": a.control.citation,
        "severity": a.control.severity if a.kind == "finding" else "info",
        "observed": a.observed,
        "reason": a.reason,
        "provenance": a.provenance,
        "subject": a.subject,
        "remediation": a.control.remediation,
        "compensating_control": a.control.compensating_control,
        "due_date": due_date_for(a.control.severity, a.kind),
        "owner": owner_for(a.control.severity, a.kind),
        "evidence": evidence or [],
        "state": "open",
    }
