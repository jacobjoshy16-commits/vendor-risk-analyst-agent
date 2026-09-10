"""Non-human identity inventory and compliance.

An NHI is a service account, OAuth app, agent principal, bot, or workload
identity that a vendor (or a vendor's agent) runs as inside a tenant. The
AI-feature controls in ``controls.yaml`` ask "what can this copilot do?".
These controls ask "what identity is it doing it *as*, and is that identity
owned, rotated, logged, and least-privileged?"

Three-tier state still applies:

  register  — optional human overlay on a vendor YAML (owner, last_rotated,
              resides_in). Not the inventory. A human does not type 100 apps.
  observed  — pulled from the IdP management API (Okta / Auth0), paginated,
              via ``vra.py discover`` / the monitor probe. Can drive a finding
              because every field quotes an API object.
  proposed  — unused here. The model does not invent identities.

Cross-vendor identities (Loop's provisioning principal living in Aegis's
tenant) are first-class: observed on the tenant vendor, declared on the
home vendor, and NHI-06 fires only when the declaration is missing.
"""

from __future__ import annotations

import hashlib
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


def entitlement_hash(scopes: list[str] | None) -> str:
    """Stable hash of the granted-scope set. Order-independent."""
    canon = json.dumps(sorted({str(s) for s in (scopes or []) if s}), separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def entitlement_diff(old_scopes: list[str] | None, new_scopes: list[str] | None) -> dict[str, list[str]]:
    old, new = set(old_scopes or []), set(new_scopes or [])
    return {
        "added_scopes": sorted(new - old),
        "removed_scopes": sorted(old - new),
    }


_UNKEYED = {"", "unnamed", "unknown", "none"}


def immutable_id(nhi: dict) -> str | None:
    """Quotable immutable identifier. Never a display name."""
    for key in ("id", "app_id", "client_id"):
        value = str(nhi.get(key) or "").strip()
        if value and value.lower() not in _UNKEYED:
            return value
    return None


def identity_key(vendor_slug: str, nhi: dict) -> str:
    """Stable inventory key. Immutable id only — a rename must not fork history."""
    token = immutable_id(nhi)
    if token:
        return f"{vendor_slug}|{token}"
    # Last resort: hash the principal (not the display name). A rename of
    # the label keeps the same key; a principal change is a different identity.
    principal = str(nhi.get("principal") or "").strip()
    if principal and principal.lower() not in _UNKEYED:
        digest = hashlib.sha256(principal.encode("utf-8")).hexdigest()[:16]
        return f"{vendor_slug}|prin:{digest}"
    return f"{vendor_slug}|unkeyed"


def _id_tokens(nhi: dict) -> set[str]:
    """Quotable identifiers long enough to be a real client/app id."""
    out: set[str] = set()
    for key in ("client_id", "app_id", "id"):
        value = str(nhi.get(key) or "").strip().lower()
        if len(value) >= 6 and value not in {"unnamed", "unknown", "none"}:
            out.add(value)
    return out


def match_keys(nhi: dict) -> set[tuple[str, str]]:
    """Every quotable token this identity can be matched on.

    Two records describe the same principal exactly when these sets intersect,
    which is what makes ``same_identity`` an equality test rather than a
    similarity score — and therefore what lets the linker use an index instead
    of comparing every identity against every other one.
    """
    keys: set[tuple[str, str]] = {("id", token) for token in _id_tokens(nhi)}
    principal = str(nhi.get("principal") or "").lower()
    if len(principal) >= 4:
        keys.add(("principal", principal))
    name = str(nhi.get("name") or "").lower()
    if len(name) >= 5:
        keys.add(("name", name))
    return keys


def same_identity(a: dict, b: dict) -> bool:
    """True when two NHI records describe the same principal.

    Matches only quotable identifiers: client/app id (any side, any plane),
    principal, or an exact name of at least 5 characters. Does not fuzzy-match.
    """
    return bool(match_keys(a) & match_keys(b))


IDP_PLANES = {"okta", "auth0"}


def _link_pair(left: dict, right: dict, slug_a: str, slug_b: str) -> None:
    """Record that ``left`` (on ``slug_a``) and ``right`` (on ``slug_b``) are one principal."""
    left["cross_plane"] = True
    right["cross_plane"] = True
    left.setdefault("also_seen_on", [])
    right.setdefault("also_seen_on", [])
    if slug_b not in left["also_seen_on"]:
        left["also_seen_on"].append(slug_b)
    if slug_a not in right["also_seen_on"]:
        right["also_seen_on"].append(slug_a)
    plane_a = (left.get("idp") or "").lower()
    plane_b = (right.get("idp") or "").lower()
    # Product-plane observation counts as a declaration.
    if plane_a in IDP_PLANES and plane_b not in IDP_PLANES:
        left["declared"] = True
        left["home_vendor"] = left.get("home_vendor") or slug_b
        left["cross_vendor"] = True
    elif plane_b in IDP_PLANES and plane_a not in IDP_PLANES:
        right["declared"] = True
        right["home_vendor"] = right.get("home_vendor") or slug_a
        right["cross_vendor"] = True
    else:
        left["declared"] = True
        right["declared"] = True


def link_cross_plane(by_vendor: dict[str, list[dict]]) -> None:
    """Mark the same principal seen on two vendors / two planes.

    Does not collapse inventory rows. Each plane keeps its quotable id.
    If the home (product) plane also observed it, NHI-06 is satisfied
    without a YAML declaration.

    Matching is exact-token equality (see ``match_keys``), so candidates come
    from an inverted index rather than from comparing every identity against
    every other one. The pairwise form was O(V^2 * N^2): ~1s at 20 vendors x 60
    identities, ~18s at 50 x 100, and unusable beyond that.
    """
    slugs = list(by_vendor)
    index: dict[tuple[str, str], list[tuple[int, int, dict]]] = {}
    for vi, slug in enumerate(slugs):
        for ni, nhi in enumerate(by_vendor[slug]):
            for key in match_keys(nhi):
                index.setdefault(key, []).append((vi, ni, nhi))

    for vi, slug_a in enumerate(slugs):
        for left in by_vendor[slug_a]:
            # Only later vendors: a pair is visited once, and two identities
            # inside one vendor are never linked to each other.
            candidates: dict[tuple[int, int], tuple[int, int, dict]] = {}
            for key in match_keys(left):
                for cand in index.get(key, ()):
                    if cand[0] > vi:
                        candidates[(cand[0], cand[1])] = cand
            # Sorted so home_vendor's first-write-wins picks the same vendor
            # the nested loops did.
            for cand_vi, _, right in sorted(candidates.values(), key=lambda c: (c[0], c[1])):
                _link_pair(left, right, slug_a, slugs[cand_vi])


def _tokens_for(vendor: dict) -> list[str]:
    tokens = [vendor.get("slug") or "", (vendor.get("vendor") or "").lower()]
    slug = vendor.get("slug") or ""
    if "-" in slug:
        tokens.append(slug.split("-", 1)[0])
    return [t for t in tokens if t and len(t) >= 4]


class PortfolioIndex:
    """Register NHIs and vendor name-tokens, indexed once instead of per identity.

    ``tag_cross_vendor`` runs for every discovered identity and used to walk the
    whole portfolio (and every register NHI on it) each time, which made the
    declaration check O(identities * vendors * register entries).
    """

    __slots__ = ("tokens", "by_key", "empty")

    def __init__(self, portfolio: list[dict] | None):
        # Portfolio order is preserved: both lookups below are first-match-wins.
        self.tokens: list[tuple[str, tuple[str, ...]]] = []
        self.by_key: dict[tuple[str, str], list[tuple[int, int, str]]] = {}
        self.empty = not portfolio
        for pi, other in enumerate(portfolio or ()):
            slug = other.get("slug") or ""
            toks = tuple(_tokens_for(other))
            if toks:
                self.tokens.append((slug, toks))
            for ei, entry in enumerate(other.get("nhis") or []):
                for key in match_keys(entry):
                    self.by_key.setdefault(key, []).append((pi, ei, slug))

    def home_by_name(self, principal: str, exclude: str) -> str | None:
        """First portfolio vendor whose name tokens appear in this principal."""
        for slug, toks in self.tokens:
            if slug == exclude:
                continue
            if any(tok in principal for tok in toks):
                return slug
        return None

    def declaring_slugs(self, nhi: dict) -> list[str]:
        """Slugs whose register declares this identity, in portfolio order."""
        hits: dict[tuple[int, int], tuple[int, int, str]] = {}
        for key in match_keys(nhi):
            for row in self.by_key.get(key, ()):
                hits[(row[0], row[1])] = row
        return [slug for _, _, slug in sorted(hits.values(), key=lambda r: (r[0], r[1]))]


def tag_cross_vendor(
    nhi: dict,
    vendor: dict,
    portfolio: list[dict] | None,
    index: PortfolioIndex | None = None,
) -> dict:
    """Mark identities that belong to a different vendor than the tenant.

    Pass ``index`` to reuse one build across a whole vendor's identities;
    without it the index is built per call, which is only sane for a one-off.
    """
    index = index if index is not None else PortfolioIndex(portfolio)
    slug = vendor["slug"]
    principal = (nhi.get("principal") or nhi.get("name") or "").lower()
    resides = nhi.get("resides_in")
    home = nhi.get("home_vendor")

    if resides and resides != slug:
        home = resides

    if not home and not index.empty:
        home = index.home_by_name(principal, exclude=slug) or home

    nhi["home_vendor"] = home
    nhi["cross_vendor"] = bool((home and home != slug) or (resides and resides != slug))

    declared = not nhi.get("orphan") and nhi.get("source") in (
        "register",
        "register+observed",
    )
    if not index.empty:
        for other_slug in index.declaring_slugs(nhi):
            declared = True
            if not home and other_slug != slug:
                home = other_slug
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

    # One index for this vendor's whole identity set, not one per identity.
    index = PortfolioIndex(portfolio)

    # Observed identities indexed by match key, so pairing the register overlay
    # against them is a lookup rather than a scan per register row.
    observed_by_key: dict[tuple[str, str], list[int]] = {}
    for oi, obs in enumerate(observed):
        for key in match_keys(obs):
            observed_by_key.setdefault(key, []).append(oi)

    merged: list[dict] = []
    matched: set[int] = set()
    for reg in register:
        # Lowest index wins, matching the original left-to-right scan.
        hit_idx = min(
            (oi for key in match_keys(reg) for oi in observed_by_key.get(key, ())),
            default=None,
        )
        if hit_idx is not None:
            hit = observed[hit_idx]
            item = _overlay(reg, hit)
            matched.add(id(hit))
        else:
            item = dict(reg)
        merged.append(tag_cross_vendor(item, vendor, portfolio, index))

    for obs in observed:
        if id(obs) in matched:
            continue
        item = dict(obs)
        item["source"] = "observed"
        item["orphan"] = True
        item["vendor"] = vendor["slug"]
        item["vendor_name"] = vendor.get("vendor") or vendor["slug"]
        item = tag_cross_vendor(item, vendor, portfolio, index)
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
        current_keys = sorted(self.identities)
        previous = self.meta.get("keys")
        if previous is not None and list(previous) != current_keys:
            self.meta["previous_keys"] = previous
        elif "previous_keys" not in self.meta:
            self.meta["previous_keys"] = current_keys
        self.meta["keys"] = current_keys
        payload = {
            "meta": {**self.meta, "last_run": datetime.now(timezone.utc).isoformat()},
            "identities": sorted(self.identities.values(), key=lambda i: i["key"]),
        }
        self.path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    def upsert(self, vendor_slug: str, nhi: dict) -> tuple[dict, dict | None]:
        key = identity_key(vendor_slug, nhi)
        today = date.today().isoformat()
        now = datetime.now(timezone.utc).isoformat()
        existing = self.identities.get(key)
        scopes = list(nhi.get("scopes") or [])
        ehash = entitlement_hash(scopes)
        cred_age = nhi.get("credential_age")
        if cred_age is None:
            cred_age = _age_days(nhi.get("last_rotated") or nhi.get("created"))
        record = {
            "key": key,
            "vendor": vendor_slug,
            "vendor_name": nhi.get("vendor_name") or vendor_slug,
            "id": nhi.get("id"),
            "app_id": nhi.get("app_id") or nhi.get("id"),
            "client_id": nhi.get("client_id"),
            "name": nhi.get("name"),
            "display_name": nhi.get("display_name") or nhi.get("name") or nhi.get("principal"),
            "type": nhi.get("type") or nhi.get("kind"),
            "kind": nhi.get("kind"),
            "status": nhi.get("status"),
            "principal": nhi.get("principal"),
            "scopes": scopes,
            "write_scopes": nhi.get("write_scopes") or [],
            "entitlement_hash": ehash,
            "owner": nhi.get("owner"),
            "last_rotated": nhi.get("last_rotated"),
            "days_since_rotated": nhi.get("days_since_rotated"),
            "credential_age": cred_age,
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
            "idp": nhi.get("idp"),
            "discovered_via": nhi.get("discovered_via"),
            "cross_plane": bool(nhi.get("cross_plane")),
            "also_seen_on": list(nhi.get("also_seen_on") or []),
            "tenant": nhi.get("tenant") or vendor_slug,
            "evidence": nhi.get("evidence") or "",
            "last_seen": today,
        }
        change = None
        if existing is None:
            record["first_seen"] = today
            self.identities[key] = record
            return record, None
        prev_hash = existing.get("entitlement_hash")
        prev_scopes = list(existing.get("scopes") or [])
        existing.update({k: v for k, v in record.items() if k != "first_seen"})
        if prev_hash and prev_hash != ehash:
            delta = entitlement_diff(prev_scopes, scopes)
            from .probe import _is_write_scope
            change = {
                "id": f"entitlement:{key}:{ehash[:12]}",
                "kind": "entitlement_change",
                "family": "nhi",
                "vendor": vendor_slug,
                "vendor_name": record.get("vendor_name"),
                "nhi_id": record.get("id") or record.get("app_id"),
                "nhi_name": record.get("display_name"),
                "added_scopes": delta["added_scopes"],
                "removed_scopes": delta["removed_scopes"],
                "gained_write_scope": any(_is_write_scope(s) for s in delta["added_scopes"]),
                "previous_hash": prev_hash,
                "current_hash": ehash,
                "timestamp": now,
            }
        return existing, change

    def upsert_many(self, vendor_slug: str, nhis: list[dict]) -> tuple[list[dict], list[dict]]:
        rows: list[dict] = []
        events: list[dict] = []
        for n in nhis:
            rec, ev = self.upsert(vendor_slug, n)
            rows.append(rec)
            if ev:
                events.append(ev)
        return rows, events

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
