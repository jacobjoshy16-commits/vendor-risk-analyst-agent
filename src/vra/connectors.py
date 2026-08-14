"""Per-vendor NHI connectors — not just identity providers.

Okta / Auth0 is one plane: every vendor app that landed in *your* IdP.
This module is the other plane: identities that live *inside* a vendor
product. Same contract as ``idp.discover_okta``:

    point at the vendor API + a token in the environment
    → page every documented list
    → normalise into an IdPEstate
    → ``_extract_nhis`` turns each object into an observed NHI

A human does not type the identities. A human does not invent an API
the vendor has not published.

Documented sources used here
----------------------------
Atlassian Cloud Admin
    GET /admin/v1/orgs
    GET /admin/api-access/v1/orgs/{orgId}/api-tokens
    GET /admin/v1/orgs/{orgId}/users   (service / app accounts only)

    Rovo agents are **not** listed. Atlassian has not published a REST
    inventory of Rovo / Studio agents (community, 2026-02). We do not
    call a guessed ``/rovo/agents``. Tokens and service accounts are
    pulled; the missing agent list is a warning, not a silent pass.

Slack Web API
    GET /api/users.list     (``is_bot`` / ``is_app_user``)
    GET /api/auth.test
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .idp import (
    DEFAULT_MAX_PAGES,
    DEFAULT_PAGE_LIMIT,
    USER_AGENT,
    IdPEstate,
    Transport,
    _exchange,
    next_link,
)


def _bearer(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


def _items(body: Any, *keys: str) -> list[Any]:
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for key in keys:
        value = body.get(key)
        if isinstance(value, list):
            return value
    return []


def _json_next(body: Any, headers: dict[str, str], *, base: str) -> str | None:
    """Atlassian admin uses ``links.next``; some lists also send a Link header."""
    header = next_link(headers, base=base)
    if header:
        return header
    if not isinstance(body, dict):
        return None
    links = body.get("links") or body.get("meta") or {}
    nxt = links.get("next") if isinstance(links, dict) else None
    if isinstance(nxt, str) and nxt:
        return nxt
    return None


# ---------------------------------------------------------------------------
# Atlassian
# ---------------------------------------------------------------------------
def discover_atlassian(
    *,
    base_url: str,
    token: str,
    transport: Transport,
    org_id: str | None = None,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> IdPEstate:
    base = (base_url or "https://api.atlassian.com").rstrip("/")
    if "atlassian.com" not in urlparse(base).netloc and not base.endswith("atlassian.com"):
        # Site URL (acme.atlassian.net) still talks to the admin API.
        base = "https://api.atlassian.com"
    estate = IdPEstate(provider="atlassian", base_url=base)
    headers = _bearer(token)

    org = org_id
    if not org:
        status, body, resp = _exchange(transport, "GET", f"{base}/admin/v1/orgs", headers=headers)
        estate.requests_made += 1
        estate.pages_fetched += 1
        if status >= 400:
            estate.error = f"atlassian orgs list returned {status}"
            return estate
        orgs = _items(body, "data")
        if not orgs:
            estate.error = "atlassian API returned no organizations for this token"
            return estate
        first = orgs[0]
        org = first.get("id") or (first.get("attributes") or {}).get("id")
        estate.org = {
            "id": org,
            "name": (first.get("attributes") or {}).get("name") or first.get("name"),
        }
    else:
        estate.org = {"id": org}

    if not org:
        estate.error = "no Atlassian org id"
        return estate

    try:
        tokens = _paginate_atlassian(
            transport, f"{base}/admin/api-access/v1/orgs/{org}/api-tokens",
            headers, estate, page_limit=page_limit, max_pages=max_pages,
            keys=("data", "values", "tokens"),
        )
        estate.api_tokens = [_normalise_atlassian_token(tok) for tok in tokens]
    except RuntimeError as exc:
        estate.warnings.append(f"api-tokens skipped: {exc}")

    try:
        users = _paginate_atlassian(
            transport, f"{base}/admin/v1/orgs/{org}/users",
            headers, estate, page_limit=page_limit, max_pages=max_pages,
            keys=("data", "users", "accounts"),
        )
        services = [u for u in users if _is_atlassian_service(u)]
        estate.service_accounts = [_normalise_atlassian_user(u) for u in services]
    except RuntimeError as exc:
        estate.warnings.append(f"org users skipped: {exc}")

    # Honest gap: Rovo / Studio agents are not a published REST list.
    estate.warnings.append(
        "Atlassian has not published a REST inventory of Rovo / Studio agents. "
        "API tokens and service accounts were pulled. Agent principals will "
        "appear here when Atlassian exposes a list API — we will not guess one."
    )
    return estate


def _paginate_atlassian(
    transport: Transport,
    url: str,
    headers: dict[str, str],
    estate: IdPEstate,
    *,
    page_limit: int,
    max_pages: int,
    keys: tuple[str, ...],
) -> list[Any]:
    items: list[Any] = []
    pages = 0
    query: dict[str, Any] | None = {"limit": page_limit}
    current = url
    while current and pages < max_pages:
        status, body, resp = _exchange(
            transport, "GET", current, headers=headers, params=query
        )
        estate.requests_made += 1
        if status >= 400:
            raise RuntimeError(f"GET {current} returned {status}")
        chunk = _items(body, *keys)
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        current = _json_next(body, resp, base=url)
        query = None
        if not chunk and not current:
            break
    if current and pages >= max_pages:
        estate.truncated = True
    return items


def _is_atlassian_service(user: dict[str, Any]) -> bool:
    attrs = user.get("attributes") or user
    account_type = str(
        attrs.get("account_type")
        or attrs.get("accountType")
        or user.get("account_type")
        or user.get("type")
        or ""
    ).lower()
    if account_type in {"app", "service", "bot", "agent", "service_account"}:
        return True
    if attrs.get("account_status") == "closed":
        return False
    email = str(attrs.get("email") or attrs.get("emailAddress") or "").lower()
    return email.endswith("@connect.atlassian.com") or email.endswith("@bots.prod.atl-paas.net")


def _normalise_atlassian_token(token: dict[str, Any]) -> dict[str, Any]:
    attrs = token.get("attributes") or token
    tid = token.get("id") or attrs.get("id") or attrs.get("tokenId")
    name = attrs.get("label") or attrs.get("name") or tid
    return {
        "id": tid,
        "name": name,
        "created": attrs.get("createdAt") or attrs.get("created") or token.get("created"),
        "expiresAt": attrs.get("expiresAt"),
        "idp": "atlassian",
        "discovered_via": "atlassian_api_tokens",
    }


def _normalise_atlassian_user(user: dict[str, Any]) -> dict[str, Any]:
    attrs = user.get("attributes") or user
    uid = user.get("id") or attrs.get("account_id") or attrs.get("accountId")
    name = (
        attrs.get("name")
        or attrs.get("displayName")
        or attrs.get("email")
        or uid
    )
    return {
        "id": uid,
        "name": name,
        "status": attrs.get("account_status") or attrs.get("status") or "ACTIVE",
        "created": attrs.get("createdAt"),
        "userType": attrs.get("account_type") or attrs.get("accountType") or "service",
        "idp": "atlassian",
        "discovered_via": "atlassian_service_accounts",
    }


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
def discover_slack(
    *,
    base_url: str,
    token: str,
    transport: Transport,
    page_limit: int = 200,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> IdPEstate:
    base = (base_url or "https://slack.com").rstrip("/")
    if not base.endswith(".com") and "slack.com" not in base:
        base = "https://slack.com"
    api = base if base.endswith("/api") else f"{base}/api"
    estate = IdPEstate(provider="slack", base_url=base)
    headers = _bearer(token)

    status, body, _ = _exchange(transport, "GET", f"{api}/auth.test", headers=headers)
    estate.requests_made += 1
    if status >= 400 or (isinstance(body, dict) and body.get("ok") is False):
        err = (body or {}).get("error") if isinstance(body, dict) else status
        estate.error = f"slack auth.test failed: {err}"
        return estate
    if isinstance(body, dict):
        estate.org = {"team": body.get("team"), "team_id": body.get("team_id")}

    cursor = None
    pages = 0
    bots: list[dict] = []
    while pages < max_pages:
        params: dict[str, Any] = {"limit": page_limit}
        if cursor:
            params["cursor"] = cursor
        status, body, _ = _exchange(
            transport, "GET", f"{api}/users.list", headers=headers, params=params
        )
        estate.requests_made += 1
        estate.pages_fetched += 1
        pages += 1
        if status >= 400 or not isinstance(body, dict) or body.get("ok") is False:
            err = (body or {}).get("error") if isinstance(body, dict) else status
            estate.warnings.append(f"users.list failed: {err}")
            break
        members = body.get("members") or []
        for member in members:
            if member.get("is_bot") or member.get("is_app_user"):
                if member.get("id") == "USLACKBOT":
                    continue
                bots.append(member)
        cursor = ((body.get("response_metadata") or {}).get("next_cursor") or "").strip()
        if not cursor:
            break
    if cursor:
        estate.truncated = True

    estate.applications = [_normalise_slack_bot(b) for b in bots]
    return estate


def _normalise_slack_bot(member: dict[str, Any]) -> dict[str, Any]:
    profile = member.get("profile") or {}
    name = (
        profile.get("real_name")
        or member.get("real_name")
        or member.get("name")
        or member.get("id")
    )
    return {
        "id": member.get("id"),
        "label": name,
        "status": "INACTIVE" if member.get("deleted") else "ACTIVE",
        "signOnMode": "BOT",
        "app_type": "bot",
        "is_bot": True,
        "ai_component": bool(member.get("ai_component")),
        "created": None,
        "idp": "slack",
        "discovered_via": "slack_bots",
    }
