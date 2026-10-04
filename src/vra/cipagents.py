"""Follow third-party agents through the utility's identity provider.

A vendor's software agent that can call your EMS integration API is vendor
remote access. CIP-005 R2.4 and R2.5 say so in as many words: the methods to
determine and disable vendor remote access cover "system-to-system remote
access" as well as people. The vendor_access subject models people in
sessions. This module supplies the other half, from the one place that can
list it: the directory that issued the agent its identity.

What the IdP can and cannot say
-------------------------------
It can quote who owns an identity (Entra: the service principal's
``appOwnerOrganizationId``), and which resource principal each of its
permissions is held on (``appRoleAssignment.resourceId``). Those two facts
decide CIP scope: a principal owned by another tenant, holding a role on a
resource listed in ``agents.yaml`` as ESP-facing, is vendor system-to-system
access into the ESP.

It cannot say whether that identity is an AI. No directory field reliably
does, and nothing here guesses from a display name. The obligation is the
same either way, so a third party's identity with a path to the ESP is
followed whether or not anyone has called it an agent; ``ai: true`` in the
register is a label a human supplies.

It also cannot say what the agent *did*. That is in the resource's own logs.
Following through the IdP means: who exists, what they can reach, and what
changed since the last look.

Every cycle
-----------
    pull     walk the IdP (recorded page set, or live Graph) with idp.py
    scope    keep declared agents, and third-party identities reaching the ESP
    follow   fold into data/cip_agents.json: first seen, permission changes, gone
    assess   the vendor_agent controls in cip_controls.yaml (CIP-35, CIP-36)

If the IdP cannot be read, or the listing is truncated, the agent controls
are reported unassessed and their open findings are carried forward. An
unreachable directory is not evidence that an agent went away.

The model is not on this path. Which identities exist and what they hold is
read from an API; there is nothing for a model to add but error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .config import DATA_DIR, RunConfig
from .evaluate import Control

AGENTS_FILE = "agents.yaml"
CIP_AGENTS_FILE = DATA_DIR / "cip_agents.json"
SUBJECT = "vendor_agent"

# The ledger reuses the NHI inventory, which keys rows by vendor slug. One
# constant slug means a vendor being named later does not fork an agent's history.
LEDGER_SLUG = "idp"

_IMPACT_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Sighting:
    """One read of the IdP, scoped to what CIP cares about."""

    configured: bool = False
    observed: bool = False
    provider: str = ""
    mode: str = ""
    source: str = ""
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    pages_fetched: int = 0
    truncated: bool = False
    agents: list[dict] = field(default_factory=list)
    out_of_scope: int = 0

    @property
    def complete(self) -> bool:
        """Safe to treat an agent missing from this read as gone."""
        return self.configured and self.observed and not self.truncated


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
def load_register(grid_dir: Path) -> dict | None:
    path = grid_dir / AGENTS_FILE
    if not path.is_file():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


# ---------------------------------------------------------------------------
# Pull
# ---------------------------------------------------------------------------
def _pull(
    register: dict,
    grid_dir: Path,
    *,
    fixture: Path | None,
    cfg: RunConfig,
    transport=None,
):
    """Walk the IdP. Returns (estate, error, mode, source)."""
    from .idp import discover_from_recorded, discover_from_vendor

    block = dict(register.get("idp") or {})
    mode = "fixture" if fixture else str(block.get("mode") or "fixture")
    if mode == "fixture":
        path = fixture
        if path is None:
            raw = block.get("fixture")
            if not raw:
                return None, "agents.yaml idp block has no fixture", mode, ""
            path = Path(str(raw))
            if not path.is_absolute():
                path = grid_dir / path
        if not path.is_file():
            return None, f"IdP page set not found: {path}", mode, str(path)
        estate, err = discover_from_recorded(path, {"probe": block})
        return estate, err, mode, str(path)
    # Live: the same walker, the same keychain credential as `vra.py discover`.
    vendor = {"slug": "utility-idp", "probe": block}
    estate, err = discover_from_vendor(vendor, cfg, transport=transport)
    return estate, err, mode, str(block.get("base_url") or "")


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
def _declared_index(register: dict) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for entry in register.get("agents") or []:
        for key in ("client_id", "object_id"):
            value = str(entry.get(key) or "").strip().lower()
            if value:
                index[value] = entry
    return index


def build_subjects(nhis: list[dict], register: dict) -> tuple[list[dict], int]:
    """Turn IdP identities into vendor_agent subjects.

    Returns (subjects, out_of_scope) where out_of_scope counts third-party
    identities that hold permissions, none of them on an ESP-facing resource.
    Those are another team's question; CIP does not reach them. Third-party
    principals holding nothing (Microsoft's own resource principals, mostly)
    are not counted at all, or the number would be noise.
    """
    from .probe import _is_write_scope

    tenant = str((register.get("idp") or {}).get("tenant_id") or "").strip().lower()
    esp = {
        str(r.get("resource_id")): r
        for r in register.get("esp_resources") or []
        if r.get("resource_id")
    }
    declared = _declared_index(register)

    subjects: list[dict] = []
    out_of_scope = 0
    for nhi in nhis:
        agent_id = str(nhi.get("client_id") or nhi.get("id") or "")
        if not agent_id:
            continue
        decl = declared.get(agent_id.lower()) or declared.get(str(nhi.get("id") or "").lower())

        owner_org = str(nhi.get("app_owner_org") or "").strip().lower()
        third_party = (owner_org != tenant) if (owner_org and tenant) else None

        esp_grants = [
            g for g in nhi.get("resource_grants") or []
            if str(g.get("resource_id")) in esp
        ]
        reaches = bool(esp_grants)

        if decl is None and not (third_party and reaches):
            if third_party and nhi.get("scopes"):
                out_of_scope += 1
            continue

        esp_perms = sorted({str(g["permission"]) for g in esp_grants})
        systems = sorted({str(esp[str(g["resource_id"])].get("system") or g["resource_id"])
                          for g in esp_grants})
        impacts = [str(esp[str(g["resource_id"])].get("impact_rating") or "") for g in esp_grants]
        impact = max(impacts, key=lambda i: _IMPACT_ORDER.get(i, 0)) if impacts else "none"

        # Compared by permission value. Entra app-role values are namespaced by
        # convention (EMS.Read.All, Historian.Read.All); two ESP-facing APIs
        # publishing an identical value would be indistinguishable here.
        approved = None
        unapproved = None
        if decl is not None and "approved_permissions" in decl:
            approved = sorted(str(p) for p in decl.get("approved_permissions") or [])
            unapproved = sorted(set(esp_perms) - set(approved))

        name = str(nhi.get("name") or nhi.get("principal") or agent_id)
        vendor = (decl or {}).get("vendor") or (f"tenant {owner_org}" if owner_org else "")
        held = "; ".join(
            f"{g['permission']} on {g.get('resource_name') or g['resource_id']}"
            for g in esp_grants
        )
        subjects.append(
            {
                "agent_id": agent_id,
                "object_id": nhi.get("id"),
                "agent": name,
                "name": name,
                "vendor": vendor,
                "vendor_slug": str((decl or {}).get("vendor_slug") or ""),
                "registered": decl is not None,
                "ai_agent": (decl or {}).get("ai"),
                "owner": (decl or {}).get("owner"),
                "third_party": third_party,
                "app_owner_org": owner_org or None,
                "status": nhi.get("status") or "active",
                "permissions": list(nhi.get("scopes") or []),
                "esp_systems": systems,
                "esp_permissions": esp_perms,
                "reaches_esp": reaches,
                "impact_rating": impact,
                "write_on_esp": any(_is_write_scope(p) for p in esp_perms),
                "approved_permissions": approved,
                "unapproved_esp_permissions": unapproved,
                "idp": nhi.get("idp"),
                "evidence": (
                    f"{nhi.get('idp') or 'idp'} principal {nhi.get('id')} ({name}), "
                    f"owning tenant {owner_org or 'not reported'}"
                    + (f": {held}" if held else "")
                ),
            }
        )
    subjects.sort(key=lambda s: (s["vendor"], s["name"]))
    return subjects, out_of_scope


def sight(
    grid_dir: Path,
    *,
    fixture: Path | None = None,
    cfg: RunConfig | None = None,
    transport=None,
) -> Sighting:
    """Read the IdP once and return the in-scope agents."""
    from .probe import _extract_nhis

    register = load_register(grid_dir)
    if register is None and fixture is None:
        return Sighting()
    register = register or {}
    cfg = cfg or RunConfig()
    estate, err, mode, source = _pull(register, grid_dir, fixture=fixture, cfg=cfg,
                                      transport=transport)
    out = Sighting(configured=True, mode=mode, source=source)
    if estate is not None:
        out.provider = estate.provider
        out.pages_fetched = estate.pages_fetched
        out.truncated = bool(estate.truncated)
        out.warnings = list(estate.warnings)
    if err or estate is None:
        out.error = err or "IdP returned nothing"
        return out
    out.observed = True
    nhis = _extract_nhis(estate.to_probe_blob())
    if not any(n.get("resource_grants") for n in nhis) and nhis:
        out.warnings.append(
            f"{estate.provider} did not report which resource each permission is "
            "held on, so reach into the ESP cannot be determined from this IdP. "
            "Only declared agents are listed."
        )
    out.agents, out.out_of_scope = build_subjects(nhis, register)
    return out


def attach(estate, grid_dir: Path, **kwargs: Any) -> Sighting:
    """Sight the IdP and put the agents on the estate the controls score."""
    sighting = sight(grid_dir, **kwargs)
    estate.agents = list(sighting.agents)
    return sighting


def unassessed(sighting: Sighting, controls: list[Control]) -> set[str]:
    """Agent controls whose open findings must be carried, not resolved."""
    if sighting.complete:
        return set()
    return {c.id for c in controls if c.subject == SUBJECT}


# ---------------------------------------------------------------------------
# Follow
# ---------------------------------------------------------------------------
def open_ledger(path: Path | None = None):
    from .nhi import NHIInventory

    return NHIInventory(path or CIP_AGENTS_FILE)


def _ledger_row(agent: dict) -> dict:
    from .probe import _is_write_scope

    perms = list(agent.get("permissions") or [])
    return {
        "id": agent["agent_id"],
        "app_id": agent["agent_id"],
        "client_id": agent["agent_id"],
        "name": agent["name"],
        "principal": agent["name"],
        "kind": "agent_principal" if agent.get("ai_agent") else "service_account",
        "status": agent.get("status"),
        "scopes": perms,
        "write_scopes": sorted(p for p in perms if _is_write_scope(p)),
        "owner": agent.get("owner"),
        "vendor_name": agent.get("vendor"),
        "home_vendor": agent.get("vendor_slug") or None,
        "declared": bool(agent.get("registered")),
        "idp": agent.get("idp"),
        "evidence": agent.get("evidence") or "",
    }


def follow(sighting: Sighting, ledger, cfg: RunConfig | None = None) -> list[dict]:
    """Fold a sighting into the ledger and say what changed since the last one.

    Events: ``new`` (first sighting), ``back`` (seen again after going away),
    ``permissions`` (role set changed), ``status`` (enabled/disabled), and
    ``gone`` (no longer in the IdP). ``gone`` is only ever concluded from a
    complete read.

    The very first read returns one ``first_read`` event rather than a ``new``
    per agent, for the same reason the monitor's first cycle sends no alerts:
    forty "new agent" lines on day one is how a channel gets muted.
    """
    from .nhi import identity_key

    cfg = cfg or RunConfig()
    if not sighting.configured:
        return []
    if not sighting.observed:
        ledger.mark_stale(LEDGER_SLUG, reason=sighting.error or "IdP not read")
        ledger.save(cfg)
        return []

    cold = not any(row.get("vendor") == LEDGER_SLUG for row in ledger.identities.values())
    before = {
        key for key, row in ledger.identities.items()
        if row.get("vendor") == LEDGER_SLUG and not row.get("gone")
    }
    events: list[dict] = []
    seen: set[str] = set()
    for agent in sighting.agents:
        row = _ledger_row(agent)
        key = identity_key(LEDGER_SLUG, row)
        prior = dict(ledger.identities[key]) if key in ledger.identities else None
        rec, change = ledger.upsert(LEDGER_SLUG, row)
        seen.add(rec["key"])
        base = {"agent_id": agent["agent_id"], "agent": agent["name"],
                "vendor": agent.get("vendor") or ""}
        if prior is None:
            events.append({**base, "kind": "new", "esp_systems": agent.get("esp_systems") or [],
                           "registered": bool(agent.get("registered"))})
            continue
        if prior.get("gone"):
            rec.pop("gone", None)
            events.append({**base, "kind": "back"})
        if change:
            events.append({**base, "kind": "permissions",
                           "added": change["added_scopes"],
                           "removed": change["removed_scopes"]})
        if (prior.get("status") or "") != (rec.get("status") or ""):
            events.append({**base, "kind": "status",
                           "was": prior.get("status"), "now": rec.get("status")})

    if sighting.complete:
        for key in sorted(before - seen):
            row = ledger.identities[key]
            row["gone"] = True
            events.append({"agent_id": row.get("id"), "agent": row.get("name"),
                           "vendor": row.get("vendor_name") or "", "kind": "gone"})
    ledger.save(cfg)
    if cold:
        return [{"kind": "first_read", "count": len(sighting.agents),
                 "undeclared": sum(1 for a in sighting.agents if not a.get("registered"))}]
    return events


def describe(event: dict) -> str:
    """One line for a cycle log."""
    who = f"{event.get('agent')} ({event.get('vendor') or 'vendor unknown'})"
    kind = event.get("kind")
    if kind == "first_read":
        n = event.get("count", 0)
        extra = f", {event['undeclared']} not declared" if event.get("undeclared") else ""
        return (f"following {n} third-party agent{'' if n == 1 else 's'} in the IdP{extra} "
                f"— first read; changes are reported from here")
    if kind == "new":
        reach = ", ".join(event.get("esp_systems") or []) or "no ESP-facing system"
        tag = "declared" if event.get("registered") else "NOT declared"
        return f"new agent in the IdP: {who} — reaches {reach}; {tag}"
    if kind == "back":
        return f"agent back in the IdP: {who}"
    if kind == "permissions":
        parts = [f"+{p}" for p in event.get("added") or []]
        parts += [f"-{p}" for p in event.get("removed") or []]
        return f"permissions changed: {who} {' '.join(parts)}"
    if kind == "status":
        return f"status changed: {who} {event.get('was')} -> {event.get('now')}"
    if kind == "gone":
        return f"no longer in the IdP: {who}"
    return f"{kind}: {who}"
