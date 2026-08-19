"""Phase 4 — in-tenant probe.

Public artifacts tell you what the vendor ships. The probe tells you what is
actually turned on in your tenant. Built for one vendor (the identity provider)
and kept behind a per-vendor `probe:` config block — most vendors will never
have one and the tool must work without it.

The highest-value output, per Phase 4.3: a feature the register carries as
`available` (or as lower-autonomy) is actually enabled in the tenant with write
scope, and nobody assessed it.

Two modes:
  fixture — read a saved API response set from the sandbox. Offline, reproducible.
            A recorded *page set* (``pages:``) is walked by the same IdP client
            as live HTTP. A legacy single-blob fixture (``applications`` +
            ``oauth_grants``) is accepted as already-normalised.
  live    — page the real Okta / Auth0 management API (src/vra/idp.py).
            Tokens come from os.environ only; they are never stored in the
            register or written to any output file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import REPO_ROOT, RunConfig

# Scopes that let an AI component change state rather than just read it.
WRITE_SCOPE_MARKERS = ("manage", "write", "revoke", "delete", "create", "update", "admin")


@dataclass
class ProbeResult:
    vendor: str
    ran: bool
    mode: str
    tenant: dict[str, Any] = field(default_factory=dict)
    ai_components: list[dict] = field(default_factory=list)
    nhis: list[dict] = field(default_factory=list)
    reconciliation: list[dict] = field(default_factory=list)
    error: str | None = None
    provider: str | None = None
    pages_fetched: int = 0
    resource_counts: dict[str, int] = field(default_factory=dict)
    truncated: bool = False


def _is_write_scope(scope: str) -> bool:
    return any(marker in scope.lower() for marker in WRITE_SCOPE_MARKERS)


def _load_fixture(vendor: dict, cfg: RunConfig) -> tuple[dict, str | None]:
    """Load a saved API response set.

    The fixture path may contain {version} so the sandbox can model tenant state
    before and after the vendor shipped a change, in step with the artifact
    snapshots. A real deployment uses mode: live and never touches this.

    If the file is a recorded page set (``pages``), it is walked by the same
    IdP client as live HTTP so pagination is exercised offline.
    """
    cfg_block = vendor.get("probe") or {}
    path = Path(str(cfg_block.get("fixture", "")).replace("{version}", cfg.snapshot_version))
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.exists():
        return {}, f"probe fixture not found: {path}"
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and data.get("pages"):
        from .idp import discover_from_recorded

        estate, err = discover_from_recorded(data, vendor)
        if err:
            return {}, err
        return estate.to_probe_blob(), None
    return data, None


def _load_live(vendor: dict, cfg: RunConfig) -> tuple[dict, str | None]:
    """Page the real Okta / Auth0 management API. One unpaginated GET is not discovery."""
    from .idp import discover_from_vendor

    if cfg.offline:
        return {}, "offline mode: skipped live tenant probe"
    estate, err = discover_from_vendor(vendor, cfg)
    if err:
        return {}, err
    assert estate is not None
    return estate.to_probe_blob(), None


def _extract_nhis(data: dict) -> list[dict]:
    """Every application + OAuth grant + API token + service account is an NHI.

    Kind is classified from quotable API fields (``src/vra/idp.classify_kind``).
    We do not invent ``agent_principal`` from a name like "Copilot".
    Agent-mode tenant settings overlay autonomy / human-in-the-loop on an
    AI component so NHI-01 can fire from the same API fields as AIV-07.
    """
    from .idp import classify_kind

    grants_by_app: dict[Any, list] = {}
    for grant in data.get("oauth_grants", []):
        grants_by_app.setdefault(grant.get("app_id"), []).append(grant)

    copilot = ((data.get("settings") or {}).get("copilot") or {})
    agent_mode = copilot.get("agent_mode") or {}
    discovery = data.get("_discovery") or {}
    idp = discovery.get("provider")

    nhis: list[dict] = []
    seen_apps: set[Any] = set()
    for app in data.get("applications", []):
        seen_apps.add(app.get("id"))
        grants = grants_by_app.get(app.get("id"), [])
        scopes: list[str] = []
        principals: list[str] = []
        issued = None
        for grant in grants:
            scopes.extend(grant.get("scopes") or [])
            principals.append(grant.get("client_name") or grant.get("principal") or "")
            issued = issued or grant.get("issued")
        scopes = sorted(set(scopes))
        write = sorted({s for s in scopes if _is_write_scope(s)})
        provider = app.get("idp") or idp or "unknown"
        kind = classify_kind(app, provider)
        principal = next((p for p in principals if p), None) or app.get("label")
        oauth_client = ((app.get("credentials") or {}).get("oauthClient") or {})
        client_id = app.get("client_id") or oauth_client.get("client_id") or app.get("id")
        nhi = {
            "id": app.get("id"),
            "app_id": app.get("id"),
            "client_id": client_id,
            "name": app.get("label"),
            "kind": kind,
            "status": "active" if app.get("status") == "ACTIVE" else "disabled",
            "principal": principal,
            "scopes": scopes,
            "write_scopes": write,
            "created": app.get("created"),
            "last_rotated": issued,
            "ai_component": bool(app.get("ai_component")),
            "source": "observed",
            "idp": provider,
            "discovered_via": app.get("discovered_via") or "tenant_applications",
            "evidence": (
                f"tenant application {app.get('id')} ({app.get('label')}) "
                f"principal={principal} scopes={', '.join(scopes) or 'none'}"
            ),
        }
        if app.get("ai_component") and agent_mode.get("enabled"):
            nhi["autonomy"] = "acts"
            nhi["human_in_loop"] = bool(agent_mode.get("per_action_approval"))
        nhis.append(nhi)

    # Grants whose app_id is not in the applications list still count.
    for app_id, grants in grants_by_app.items():
        if app_id in seen_apps:
            continue
        scopes = sorted({s for g in grants for s in (g.get("scopes") or [])})
        principal = next((g.get("client_name") or g.get("principal") for g in grants), None)
        issued = next((g.get("issued") for g in grants if g.get("issued")), None)
        nhis.append(
            {
                "id": app_id,
                "app_id": app_id,
                "name": principal or str(app_id),
                "kind": "oauth_app",
                "status": "active",
                "principal": principal,
                "scopes": scopes,
                "write_scopes": sorted({s for s in scopes if _is_write_scope(s)}),
                "last_rotated": issued,
                "ai_component": False,
                "source": "observed",
                "idp": idp,
                "discovered_via": "tenant_oauth_grants",
                "evidence": f"tenant oauth grant app_id={app_id} principal={principal}",
            }
        )

    for token in data.get("api_tokens") or []:
        token_id = token.get("id")
        if not token_id or token_id in seen_apps:
            continue
        name = token.get("name") or str(token_id)
        nhis.append(
            {
                "id": token_id,
                "app_id": token_id,
                "name": name,
                "kind": "api_key",
                "status": "active",
                "principal": name,
                "scopes": [],
                "write_scopes": [],
                "created": token.get("created"),
                "ai_component": False,
                "source": "observed",
                "idp": token.get("idp") or idp,
                "discovered_via": token.get("discovered_via") or "okta_api_tokens",
                "evidence": (
                    f"idp api-token {token_id} ({name}) "
                    f"created={token.get('created') or 'unknown'}"
                ),
            }
        )

    for svc in data.get("service_accounts") or []:
        svc_id = svc.get("id")
        if not svc_id or svc_id in seen_apps:
            continue
        name = svc.get("name") or str(svc_id)
        status = str(svc.get("status") or "ACTIVE").upper()
        nhis.append(
            {
                "id": svc_id,
                "app_id": svc_id,
                "name": name,
                "kind": "service_account",
                "status": "active" if status == "ACTIVE" else "disabled",
                "principal": name,
                "scopes": [],
                "write_scopes": [],
                "created": svc.get("created"),
                "ai_component": False,
                "source": "observed",
                "idp": svc.get("idp") or idp,
                "discovered_via": svc.get("discovered_via") or "okta_users",
                "evidence": f"idp service-account user {svc_id} ({name})",
            }
        )
    return nhis


def run_probe(vendor: dict, cfg: RunConfig) -> ProbeResult:
    block = vendor.get("probe") or {}
    slug = vendor["slug"]

    if not block or not block.get("enabled") or cfg.no_probe:
        return ProbeResult(vendor=slug, ran=False, mode="none",
                           error=None if not block else "probe disabled for this run")

    mode = block.get("mode", "fixture")
    data, err = _load_fixture(vendor, cfg) if mode == "fixture" else _load_live(vendor, cfg)
    if err:
        return ProbeResult(vendor=slug, ran=False, mode=mode, error=err)

    # --- extract: which AI features are enabled, and what scopes they hold ---
    ai_components: list[dict] = []
    grants_by_app = {}
    for grant in data.get("oauth_grants", []):
        grants_by_app.setdefault(grant.get("app_id"), []).append(grant)

    for app in data.get("applications", []):
        if not app.get("ai_component"):
            continue
        scopes: list[str] = []
        principals: list[str] = []
        for grant in grants_by_app.get(app.get("id"), []):
            scopes.extend(grant.get("scopes", []))
            principals.append(grant.get("client_name", ""))
        ai_components.append(
            {
                "app_id": app.get("id"),
                "label": app.get("label"),
                "status": app.get("status"),
                "enabled": app.get("status") == "ACTIVE",
                "principals": principals,
                "scopes": sorted(set(scopes)),
                "write_scopes": sorted({s for s in scopes if _is_write_scope(s)}),
                "created": app.get("created"),
            }
        )

    nhis = _extract_nhis(data)

    copilot = ((data.get("settings") or {}).get("copilot") or {})
    agent_mode = copilot.get("agent_mode") or {}

    discovery = data.get("_discovery") or {}
    tenant = {
        "org": data.get("org", {}),
        "copilot_enabled": copilot.get("enabled"),
        "agent_mode_enabled": agent_mode.get("enabled"),
        "agent_mode_enabled_by": agent_mode.get("enabled_by"),
        "per_action_approval": agent_mode.get("per_action_approval"),
        "prompt_retention_days": copilot.get("prompt_retention_days"),
        "application_count": len(data.get("applications", [])),
        "idp_provider": discovery.get("provider"),
        "idp_pages_fetched": discovery.get("pages_fetched"),
        "idp_truncated": discovery.get("truncated"),
        "idp_counts": discovery.get("counts") or {},
    }

    # --- reconcile against the register -----------------------------------
    recon: list[dict] = []
    surface = vendor.get("ai_surface") or []
    primary = surface[0] if surface else {}
    feature_name = primary.get("feature", "(unnamed)")

    if tenant["agent_mode_enabled"] and primary.get("autonomy") != "acts":
        recon.append(
            {
                "type": "autonomy_drift",
                "severity_hint": "critical",
                "feature": feature_name,
                "register_says": f"autonomy={primary.get('autonomy')}",
                "tenant_says": "agent mode enabled with per_action_approval="
                f"{tenant['per_action_approval']}",
                "detail": (
                    "Agent mode is live in the tenant "
                    f"(enabled by {tenant['agent_mode_enabled_by']}) but the register still records "
                    f"autonomy={primary.get('autonomy')}. The capability was never assessed at its "
                    "current autonomy level."
                ),
                "surface_field": "autonomy",
                "proposed_value": "acts",
            }
        )

    if tenant["agent_mode_enabled"] and tenant["per_action_approval"] is False and primary.get("human_in_loop"):
        recon.append(
            {
                "type": "human_in_loop_drift",
                "severity_hint": "critical",
                "feature": feature_name,
                "register_says": "human_in_loop=true",
                "tenant_says": "per_action_approval=false",
                "detail": (
                    "The register records a human in the loop, but the tenant has agent mode enabled "
                    "with per-action approval unavailable."
                ),
                "surface_field": "human_in_loop",
                "proposed_value": False,
            }
        )

    for comp in ai_components:
        if comp["write_scopes"] and primary.get("autonomy") != "acts":
            recon.append(
                {
                    "type": "unassessed_write_scope",
                    "severity_hint": "critical",
                    "feature": comp["label"],
                    "register_says": f"autonomy={primary.get('autonomy')}",
                    "tenant_says": "holds write scopes " + ", ".join(comp["write_scopes"]),
                    "detail": (
                        f"AI component '{comp['label']}' is ACTIVE in the tenant and holds directory "
                        f"write scopes ({', '.join(comp['write_scopes'])}) under principal(s) "
                        f"{', '.join(comp['principals']) or 'unknown'}. The register does not reflect "
                        "an acting agent for this vendor."
                    ),
                    "surface_field": "autonomy",
                    "proposed_value": "acts",
                }
            )
        if comp["enabled"] and primary.get("status") == "available":
            recon.append(
                {
                    "type": "status_drift",
                    "severity_hint": "high",
                    "feature": comp["label"],
                    "register_says": "status=available",
                    "tenant_says": "status=ACTIVE (enabled)",
                    "detail": (
                        "A feature the register marks as merely available is actually enabled in the "
                        "tenant and has not been assessed in its enabled state."
                    ),
                    "surface_field": "status",
                    "proposed_value": "enabled",
                }
            )

    if tenant["prompt_retention_days"] is None and copilot.get("enabled"):
        recon.append(
            {
                "type": "retention_unset",
                "severity_hint": "medium",
                "feature": feature_name,
                "register_says": f"retention_days={primary.get('retention_days')}",
                "tenant_says": "prompt_retention_days is null in tenant settings",
                "detail": "Tenant reports no configured prompt retention period; the vendor has not exposed one.",
                "surface_field": "retention_days",
                "proposed_value": None,
            }
        )

    return ProbeResult(
        vendor=slug, ran=True, mode=mode, tenant=tenant,
        ai_components=ai_components, nhis=nhis, reconciliation=recon,
        provider=discovery.get("provider"),
        pages_fetched=int(discovery.get("pages_fetched") or 0),
        resource_counts=dict(discovery.get("counts") or {}),
        truncated=bool(discovery.get("truncated")),
    )
