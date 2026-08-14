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
  live    — call the vendor management API with a token from the environment.
            The token is read from os.environ only; it is never stored in the
            register or written to any output file.
"""

from __future__ import annotations

import json
import os
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


def _is_write_scope(scope: str) -> bool:
    return any(marker in scope.lower() for marker in WRITE_SCOPE_MARKERS)


def _load_fixture(vendor: dict, cfg: RunConfig) -> tuple[dict, str | None]:
    """Load a saved API response set.

    The fixture path may contain {version} so the sandbox can model tenant state
    before and after the vendor shipped a change, in step with the artifact
    snapshots. A real deployment uses mode: live and never touches this.
    """
    cfg_block = vendor.get("probe") or {}
    path = Path(str(cfg_block.get("fixture", "")).replace("{version}", cfg.snapshot_version))
    if not path.is_absolute():
        path = REPO_ROOT / path
    if not path.exists():
        return {}, f"probe fixture not found: {path}"
    return json.loads(path.read_text(encoding="utf-8")), None


def _load_live(vendor: dict, cfg: RunConfig) -> tuple[dict, str | None]:
    block = vendor.get("probe") or {}
    if cfg.offline:
        return {}, "offline mode: skipped live tenant probe"
    token = os.environ.get(block.get("token_env", ""), "")
    if not token:
        return {}, f"no API token in ${block.get('token_env')}; skipping live probe"
    try:
        import requests

        base = block["base_url"].rstrip("/")
        headers = {"Authorization": f"SSWS {token}", "Accept": "application/json"}
        apps = requests.get(f"{base}/api/v1/apps", headers=headers, timeout=30)
        apps.raise_for_status()
        grants = requests.get(f"{base}/api/v1/apps/grants", headers=headers, timeout=30)
        settings = requests.get(f"{base}/api/v1/org/settings", headers=headers, timeout=30)
        return (
            {
                "org": {"subdomain": base},
                "applications": apps.json(),
                "oauth_grants": grants.json() if grants.ok else [],
                "settings": settings.json() if settings.ok else {},
            },
            None,
        )
    except Exception as exc:  # pragma: no cover - network path
        return {}, f"live probe failed: {exc}"


def _extract_nhis(data: dict) -> list[dict]:
    """Every application + OAuth grant becomes an observed NHI.

    AI components are tagged ``agent_principal``; everything else is an
    ``oauth_app`` (SSO integrations, provisioning clients, workload ids).
    Agent-mode tenant settings overlay autonomy / human-in-the-loop on the
    AI component so NHI-01 can fire from the same quotable API fields as
    AIV-07, against the *identity* rather than the feature.
    """
    grants_by_app: dict[Any, list] = {}
    for grant in data.get("oauth_grants", []):
        grants_by_app.setdefault(grant.get("app_id"), []).append(grant)

    copilot = ((data.get("settings") or {}).get("copilot") or {})
    agent_mode = copilot.get("agent_mode") or {}

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
        kind = "agent_principal" if app.get("ai_component") else "oauth_app"
        principal = next((p for p in principals if p), None) or app.get("label")
        nhi = {
            "id": app.get("id"),
            "app_id": app.get("id"),
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
                "evidence": f"tenant oauth grant app_id={app_id} principal={principal}",
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

    tenant = {
        "org": data.get("org", {}),
        "copilot_enabled": copilot.get("enabled"),
        "agent_mode_enabled": agent_mode.get("enabled"),
        "agent_mode_enabled_by": agent_mode.get("enabled_by"),
        "per_action_approval": agent_mode.get("per_action_approval"),
        "prompt_retention_days": copilot.get("prompt_retention_days"),
        "application_count": len(data.get("applications", [])),
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
    )
