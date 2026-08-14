"""Non-human identity inventory and compliance.

An NHI is a service account, OAuth app, agent principal, bot, or workload
identity that a vendor (or a vendor's agent) runs as inside a tenant. The
AI-feature controls in ``controls.yaml`` ask "what can this copilot do?".
These controls ask "what identity is it doing it *as*, and is that identity
owned, rotated, logged, and least-privileged?"

Three-tier state still applies:

  register  — human-authored ``nhis:`` block on a vendor YAML. Authoritative.
  observed  — extracted from a tenant probe (applications + OAuth grants).
              Overlays the register; can drive a finding because every field
              quotes an API object.
  proposed  — unused here. The model does not invent identities.

Cross-vendor identities (Loop's provisioning principal living in Aegis's
tenant) are first-class: observed on the tenant vendor, declared on the
home vendor, and NHI-06 fires only when the declaration is missing.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .config import NHI_CONTROLS_FILE, NHI_FILE, UNKNOWN_TOKENS, RunConfig
from .evaluate import (
    Assessment,
    Control,
    evaluate_condition,
    load_controls,
    to_record,
)

NHI_KINDS = (
    "agent_principal",
    "service_account",
    "oauth_app",
    "api_key",
    "workload",
    "bot",
)


def load_nhi_controls(path: Path | None = None) -> list[Control]:
    return load_controls(path or NHI_CONTROLS_FILE)


def _unknown(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in UNKNOWN_TOKENS
    return value in (None, "")


def _age_days(value: Any) -> int | str:
    if _unknown(value):
        return "unknown"
    try:
        stamped = date.fromisoformat(str(value)[:10])
    except ValueError:
        return "unknown"
    return (date.today() - stamped).days


def identity_key(vendor_slug: str, nhi: dict) -> str:
    """Stable inventory key. Prefer app_id, then principal, then name."""
    token = (
        nhi.get("app_id")
        or nhi.get("id")
        or nhi.get("principal")
        or nhi.get("name")
        or "unnamed"
    )
    return f"{vendor_slug}|{token}"


def same_identity(a: dict, b: dict) -> bool:
    """True when two NHI records describe the same principal."""
    for key in ("app_id",):
        av, bv = str(a.get(key) or "").lower(), str(b.get(key) or "").lower()
        if av and bv and av == bv:
            return True
    for key in ("id", "principal"):
        av, bv = str(a.get(key) or "").lower(), str(b.get(key) or "").lower()
        if av and bv and av == bv:
            return True
    an, bn = str(a.get("name") or "").lower(), str(b.get("name") or "").lower()
    return bool(an and bn and an == bn)


def _tokens_for(vendor: dict) -> list[str]:
    tokens = [vendor.get("slug") or "", (vendor.get("vendor") or "").lower()]
    slug = vendor.get("slug") or ""
    if "-" in slug:
        tokens.append(slug.split("-", 1)[0])
    return [t for t in tokens if t and len(t) >= 4]


def tag_cross_vendor(nhi: dict, vendor: dict, portfolio: list[dict] | None) -> dict:
    """Mark identities that belong to a different vendor than the tenant."""
    slug = vendor["slug"]
    principal = (nhi.get("principal") or nhi.get("name") or "").lower()
    resides = nhi.get("resides_in")
    home = nhi.get("home_vendor")

    if resides and resides != slug:
        home = resides

    if not home and portfolio:
        for other in portfolio:
            if other.get("slug") == slug:
                continue
            if any(tok in principal for tok in _tokens_for(other)):
                home = other["slug"]
                break

    nhi["home_vendor"] = home
    nhi["cross_vendor"] = bool((home and home != slug) or (resides and resides != slug))

    declared = not nhi.get("orphan") and nhi.get("source") in (
        "register",
        "register+observed",
    )
    if portfolio:
        for other in portfolio:
            for entry in other.get("nhis") or []:
                if same_identity(entry, nhi):
                    declared = True
                    if not home and other.get("slug") != slug:
                        home = other["slug"]
                        nhi["home_vendor"] = home
                        nhi["cross_vendor"] = True
    nhi["declared"] = bool(declared)
    return nhi


def _as_feature(nhi: dict) -> dict:
    """Shape an NHI so evaluate_condition can resolve fields against it."""
    feature = dict(nhi)
    feature.setdefault("feature", nhi.get("name") or nhi.get("principal") or nhi.get("id") or "(unnamed NHI)")
    if "days_since_rotated" not in feature:
        feature["days_since_rotated"] = _age_days(nhi.get("last_rotated"))
    return feature


def _overlay(register: dict, observed: dict) -> dict:
    """Register values overlaid with tenant-observed ones. Observed wins."""
    out = dict(register)
    out["source"] = "register+observed"
    out["orphan"] = False
    provenance: dict[str, dict] = {}
    overlay_keys = (
        "scopes",
        "write_scopes",
        "status",
        "principal",
        "name",
        "created",
        "app_id",
        "autonomy",
        "human_in_loop",
    )
    for key in overlay_keys:
        if key not in observed:
            continue
        value = observed[key]
        if value in (None, ""):
            continue
        if out.get(key) != value:
            provenance[key] = {
                "value": value,
                "provenance": "in_tenant_probe",
                "evidence": observed.get("evidence") or "",
            }
        out[key] = value
    if observed.get("last_rotated") and _unknown(out.get("last_rotated")):
        out["last_rotated"] = observed["last_rotated"]
    out["provenance"] = provenance
    out["evidence"] = observed.get("evidence") or register.get("evidence") or ""
    out["days_since_rotated"] = _age_days(out.get("last_rotated"))
    return out


def normalize_register_nhi(raw: dict, vendor: dict) -> dict:
    nhi = dict(raw)
    nhi.setdefault("id", raw.get("app_id") or raw.get("principal") or raw.get("name"))
    nhi.setdefault("kind", "service_account")
    nhi.setdefault("status", "active")
    nhi.setdefault("scopes", [])
    nhi.setdefault("write_scopes", [])
    nhi.setdefault("source", "register")
    nhi.setdefault("orphan", False)
    nhi["vendor"] = vendor["slug"]
    nhi["vendor_name"] = vendor.get("vendor") or vendor["slug"]
    nhi["days_since_rotated"] = _age_days(nhi.get("last_rotated"))
    return nhi


def discover_nhis(
    vendor: dict,
    probe_result,
    portfolio: list[dict] | None = None,
) -> list[dict]:
    """Merge register NHIs with identities observed in the tenant probe."""
    register = [normalize_register_nhi(n, vendor) for n in (vendor.get("nhis") or [])]
    observed: list[dict] = []
    if probe_result is not None and getattr(probe_result, "ran", False):
        for item in getattr(probe_result, "nhis", None) or []:
            row = dict(item)
            row["vendor"] = vendor["slug"]
            row["vendor_name"] = vendor.get("vendor") or vendor["slug"]
            row.setdefault("source", "observed")
            row.setdefault("days_since_rotated", _age_days(row.get("last_rotated")))
            observed.append(row)

    merged: list[dict] = []
    matched: set[int] = set()
    for reg in register:
        hit = next((o for o in observed if same_identity(reg, o)), None)
        if hit is not None:
            item = _overlay(reg, hit)
            matched.add(id(hit))
        else:
            item = dict(reg)
        merged.append(tag_cross_vendor(item, vendor, portfolio))

    for obs in observed:
        if id(obs) in matched:
            continue
        item = dict(obs)
        item["source"] = "observed"
        item["orphan"] = True
        item["vendor"] = vendor["slug"]
        item["vendor_name"] = vendor.get("vendor") or vendor["slug"]
        item = tag_cross_vendor(item, vendor, portfolio)
        # Declared on another vendor's register: not an orphan, just visiting.
        if item.get("declared"):
            item["orphan"] = False
        merged.append(item)

    return merged


def evaluate_nhis(
    vendor: dict, nhis: list[dict], controls: list[Control]
) -> tuple[list[Assessment], list[Assessment]]:
    """Run NHI-* controls against every identity. Returns (findings, gaps)."""
    findings: list[Assessment] = []
    gaps: list[Assessment] = []
    orphan_control = next((c for c in controls if c.id == "NHI-04"), None)

    for nhi in nhis:
        feature = _as_feature(nhi)
        name = feature.get("feature") or "(unnamed NHI)"
        subject = str(nhi.get("principal") or nhi.get("id") or name)
        applied = nhi.get("provenance") or {}

        if nhi.get("orphan") and orphan_control is not None:
            findings.append(
                Assessment(
                    kind="finding",
                    vendor=vendor["slug"],
                    vendor_name=vendor.get("vendor") or vendor["slug"],
                    feature=name,
                    control=orphan_control,
                    observed={
                        "principal": nhi.get("principal"),
                        "app_id": nhi.get("app_id") or nhi.get("id"),
                        "kind": nhi.get("kind"),
                        "source": "observed",
                    },
                    reason="identity observed in the tenant is not in any vendor NHI register",
                    subject=subject,
                    provenance={
                        "orphan": {
                            "value": True,
                            "provenance": "in_tenant_probe",
                            "evidence": nhi.get("evidence") or "",
                        }
                    },
                )
            )

        status = str(nhi.get("status") or "active").lower()
        runnable = [c for c in controls if c.id != "NHI-04"]
        if status in ("disabled", "inactive"):
            runnable = [c for c in runnable if c.id == "NHI-07"]

        for control in runnable:
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
                        vendor_name=vendor.get("vendor") or vendor["slug"],
                        feature=name,
                        control=control,
                        observed=_observed(control.fails_when, feature, vendor),
                        reason="all failure conditions met",
                        subject=subject,
                        provenance={k: v for k, v in applied.items() if k in touched},
                    )
                )
                continue

            gap_results = [evaluate_condition(c, feature, vendor) for c in control.gap_when]
            unknown_blocks = any(r is None for r in fail_results)
            if any(r is True for r in gap_results) or (unknown_blocks and control.gap_when):
                conds = control.gap_when or control.fails_when
                gaps.append(
                    Assessment(
                        kind="gap",
                        vendor=vendor["slug"],
                        vendor_name=vendor.get("vendor") or vendor["slug"],
                        feature=name,
                        control=control,
                        observed=_observed(conds, feature, vendor),
                        reason="required field is unknown; cannot evaluate NHI control",
                        subject=subject,
                    )
                )

    return findings, gaps


def _observed(conds: list[dict], feature: dict, vendor: dict) -> dict[str, Any]:
    from .evaluate import MISSING, resolve_field

    out: dict[str, Any] = {}
    for cond in conds:
        val = resolve_field(feature, vendor, cond["field"])
        out[cond["field"]] = "<not recorded>" if val is MISSING else val
    return out


# ---------------------------------------------------------------------------
# Persistent inventory
# ---------------------------------------------------------------------------
class NHIInventory:
    """Portfolio-wide NHI store. Machine-owned; lives next to findings.json."""

    def __init__(self, path: Path = NHI_FILE):
        self.path = path
        self.identities: dict[str, dict] = {}
        self.meta: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            blob = json.loads(self.path.read_text(encoding="utf-8"))
            self.identities = {i["key"]: i for i in blob.get("identities", [])}
            self.meta = blob.get("meta", {})

    def save(self, cfg: RunConfig) -> None:
        if cfg.dry_run:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "meta": {**self.meta, "last_run": datetime.now(timezone.utc).isoformat()},
            "identities": sorted(self.identities.values(), key=lambda i: i["key"]),
        }
        self.path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def upsert(self, vendor_slug: str, nhi: dict) -> dict:
        key = identity_key(vendor_slug, nhi)
        today = date.today().isoformat()
        existing = self.identities.get(key)
        record = {
            "key": key,
            "vendor": vendor_slug,
            "vendor_name": nhi.get("vendor_name") or vendor_slug,
            "id": nhi.get("id"),
            "app_id": nhi.get("app_id") or nhi.get("id"),
            "name": nhi.get("name"),
            "kind": nhi.get("kind"),
            "status": nhi.get("status"),
            "principal": nhi.get("principal"),
            "scopes": nhi.get("scopes") or [],
            "write_scopes": nhi.get("write_scopes") or [],
            "owner": nhi.get("owner"),
            "last_rotated": nhi.get("last_rotated"),
            "days_since_rotated": nhi.get("days_since_rotated"),
            "human_in_loop": nhi.get("human_in_loop"),
            "autonomy": nhi.get("autonomy"),
            "output_logged": nhi.get("output_logged"),
            "feature": nhi.get("feature"),
            "source": nhi.get("source"),
            "orphan": bool(nhi.get("orphan")),
            "cross_vendor": bool(nhi.get("cross_vendor")),
            "declared": bool(nhi.get("declared")),
            "home_vendor": nhi.get("home_vendor"),
            "resides_in": nhi.get("resides_in"),
            "evidence": nhi.get("evidence") or "",
            "last_seen": today,
        }
        if existing is None:
            record["first_seen"] = today
            self.identities[key] = record
            return record
        existing.update({k: v for k, v in record.items() if k != "first_seen"})
        return existing

    def upsert_many(self, vendor_slug: str, nhis: list[dict]) -> list[dict]:
        return [self.upsert(vendor_slug, n) for n in nhis]

    def all(self) -> list[dict]:
        return sorted(self.identities.values(), key=lambda i: i["key"])

    def for_vendor(self, slug: str) -> list[dict]:
        return [i for i in self.all() if i["vendor"] == slug]


def assessments_to_records(
    findings: list[Assessment],
    gaps: list[Assessment],
    *,
    evidence_by_subject: dict[str, list[dict]] | None = None,
) -> tuple[list[dict], list[dict]]:
    """Convert NHI assessments into the persisted finding-record shape."""
    evidence_by_subject = evidence_by_subject or {}
    out_f, out_g = [], []
    for a in findings:
        ev = list(evidence_by_subject.get(a.subject, []))
        for meta in a.provenance.values():
            ev.append(
                {
                    "source": meta.get("provenance", "nhi"),
                    "excerpt": meta.get("evidence", ""),
                    "change_type": "nhi_observation",
                    "confidence": 1.0,
                }
            )
        rec = to_record(a, evidence=ev)
        rec["family"] = "nhi"
        out_f.append(rec)
    for a in gaps:
        rec = to_record(a, evidence=evidence_by_subject.get(a.subject, []))
        rec["family"] = "nhi"
        out_g.append(rec)
    return out_f, out_g
