"""Protocol connectors — one implementation covers a class of APIs.

    oidc_apps     registered apps + granted scopes from any Okta / Auth0 /
                  Entra / Ping / OneLogin-style org (base URL + token)
    scim          service accounts from any SCIM 2.0 /Users endpoint
    generic_rest  caller supplies the list URL and a JSONPath mapping

These do not invent unpublished vendor routes. Flavor is inferred from
the hostname or set on the probe block (``flavor: entra``).
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

from .idp import (
    DEFAULT_MAX_PAGES,
    DEFAULT_PAGE_LIMIT,
    USER_AGENT,
    IdPEstate,
    Transport,
    _auth0_headers,
    _exchange,
    discover_auth0,
    discover_okta,
    next_link,
)
from .registry import ConnectorManifest, register

# ---------------------------------------------------------------------------
# Small JSONPath subset — no extra dependency
# ---------------------------------------------------------------------------
def jsonpath_get(data: Any, path: str) -> Any:
    """Resolve ``$.items[*].id`` / ``owner.email`` / ``items``. ``[*]`` flattens."""
    raw = (path or "").strip()
    if not raw or raw in {"$", "."}:
        return data
    raw = raw[1:] if raw.startswith("$") else raw
    raw = raw[1:] if raw.startswith(".") else raw
    cur: Any = data
    for part in raw.split("."):
        flatten = part.endswith("[*]")
        key = part[:-3] if flatten else part
        if key:
            if isinstance(cur, list):
                cur = [item.get(key) if isinstance(item, dict) else None for item in cur]
            elif isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
        if flatten:
            if isinstance(cur, list):
                continue
            if cur is None:
                return []
            cur = [cur]
    return cur


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _bearer(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


def _ssws(token: str) -> dict[str, str]:
    return {
        "Authorization": f"SSWS {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


# ---------------------------------------------------------------------------
# Flavor detection
# ---------------------------------------------------------------------------
def detect_oidc_flavor(url: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit.strip().lower()
    blob = (url or "").lower()
    if "auth0.com" in blob or ".auth0." in blob:
        return "auth0"
    if "okta.com" in blob or "oktapreview.com" in blob or "okta-" in blob:
        return "okta"
    if (
        "graph.microsoft.com" in blob
        or "microsoftonline.com" in blob
        or "login.microsoft.com" in blob
        or "windows.net" in blob
    ):
        return "entra"
    if "pingone.com" in blob or "pingidentity.com" in blob:
        return "ping"
    if "onelogin.com" in blob:
        return "onelogin"
    return ""


# ---------------------------------------------------------------------------
# Entra (Microsoft Graph) — documented
#   GET https://graph.microsoft.com/v1.0/applications
#   GET https://graph.microsoft.com/v1.0/servicePrincipals
#   pagination: @odata.nextLink
# ---------------------------------------------------------------------------
def discover_entra(
    *,
    base_url: str,
    token: str,
    transport: Transport,
    page_limit: int = 99,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    base = (base_url or "https://graph.microsoft.com").rstrip("/")
    if "graph.microsoft.com" not in urlparse(base).netloc:
        base = "https://graph.microsoft.com"
    estate = IdPEstate(provider="entra", base_url=base)
    headers = _bearer(token)
    apps = _odata_pages(
        transport, f"{base}/v1.0/applications", headers, estate,
        page_limit=page_limit, max_pages=max_pages,
    )
    sps = _odata_pages(
        transport, f"{base}/v1.0/servicePrincipals", headers, estate,
        page_limit=page_limit, max_pages=max_pages,
    )
    estate.applications = [_normalise_entra_app(a) for a in apps]
    estate.service_accounts = [_normalise_entra_sp(s) for s in sps]
    return estate


def _odata_pages(
    transport: Transport,
    url: str,
    headers: dict[str, str],
    estate: IdPEstate,
    *,
    page_limit: int,
    max_pages: int,
) -> list[Any]:
    items: list[Any] = []
    current = url
    query: dict[str, Any] | None = {"$top": page_limit}
    pages = 0
    while current and pages < max_pages:
        status, body, _ = _exchange(transport, "GET", current, headers=headers, params=query)
        estate.requests_made += 1
        if status >= 400:
            if status == 429:
                estate.truncated = True
                estate.warnings.append(f"GET {url} rate-limited; kept {len(items)} row(s)")
                return items
            if pages == 0:
                raise RuntimeError(f"GET {url} returned {status}")
            estate.warnings.append(f"GET {current} returned {status}")
            break
        blob = body if isinstance(body, dict) else {}
        chunk = blob.get("value") if isinstance(blob.get("value"), list) else (
            body if isinstance(body, list) else []
        )
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        nxt = blob.get("@odata.nextLink")
        current = nxt if isinstance(nxt, str) and nxt else None
        query = None
        if not chunk and not current:
            break
    if current and pages >= max_pages:
        estate.truncated = True
    return items


def _normalise_entra_app(app: dict[str, Any]) -> dict[str, Any]:
    app_id = app.get("appId") or app.get("id")
    return {
        "id": app.get("id") or app_id,
        "client_id": app_id,
        "label": app.get("displayName") or app_id,
        "status": "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "app_type": "application",
        "created": app.get("createdDateTime"),
        "idp": "entra",
        "discovered_via": "entra_applications",
    }


def _normalise_entra_sp(sp: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": sp.get("id") or sp.get("appId"),
        "name": sp.get("displayName") or sp.get("appId"),
        "status": "ACTIVE" if sp.get("accountEnabled", True) else "INACTIVE",
        "created": sp.get("createdDateTime"),
        "userType": "servicePrincipal",
        "idp": "entra",
        "discovered_via": "entra_service_principals",
    }


# ---------------------------------------------------------------------------
# PingOne — documented
#   GET /v1/environments/{envId}/applications
#   pagination: _links.next.href
# ---------------------------------------------------------------------------
def discover_ping(
    *,
    base_url: str,
    token: str,
    transport: Transport,
    org_id: str | None = None,
    page_limit: int = 100,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    base = (base_url or "https://api.pingone.com").rstrip("/")
    estate = IdPEstate(provider="ping", base_url=base)
    headers = _bearer(token)
    env = org_id or _ping_env(base)
    if not env:
        estate.error = "ping requires an environment id in the base URL or probe.org_id"
        return estate
    if "/environments/" not in base:
        list_url = f"{base}/v1/environments/{env}/applications"
    elif base.endswith("/applications"):
        list_url = base
    else:
        list_url = f"{base.rstrip('/')}/applications"
        if "/applications" not in list_url:
            list_url = f"{base}/applications"
    try:
        apps = _hal_pages(
            transport, list_url, headers, estate,
            page_limit=page_limit, max_pages=max_pages, keys=("_embedded", "applications"),
        )
    except RuntimeError as exc:
        estate.error = f"ping applications list failed: {exc}"
        return estate
    estate.org = {"id": env}
    estate.applications = [_normalise_ping_app(a) for a in apps]
    return estate


def _ping_env(base: str) -> str | None:
    parts = urlparse(base).path.strip("/").split("/")
    if "environments" in parts:
        idx = parts.index("environments")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _hal_pages(
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
    current = url
    query: dict[str, Any] | None = {"limit": page_limit}
    pages = 0
    while current and pages < max_pages:
        status, body, resp = _exchange(transport, "GET", current, headers=headers, params=query)
        estate.requests_made += 1
        if status >= 400:
            if status == 429:
                estate.truncated = True
                estate.warnings.append(f"GET {url} rate-limited; kept {len(items)} row(s)")
                return items
            raise RuntimeError(f"GET {current} returned {status}")
        chunk: list[Any] = []
        if isinstance(body, list):
            chunk = body
        elif isinstance(body, dict):
            embedded = body.get("_embedded") if "_embedded" in keys else None
            if isinstance(embedded, dict):
                for key in keys:
                    if key != "_embedded" and isinstance(embedded.get(key), list):
                        chunk = embedded[key]
                        break
            if not chunk:
                for key in ("applications", "items", "data"):
                    if isinstance(body.get(key), list):
                        chunk = body[key]
                        break
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        nxt = None
        if isinstance(body, dict):
            links = body.get("_links") or {}
            nxt = (links.get("next") or {}).get("href") if isinstance(links.get("next"), dict) else links.get("next")
        nxt = nxt or next_link(resp, base=url)
        current = nxt if isinstance(nxt, str) and nxt else None
        query = None
        if not chunk and not current:
            break
    if current and pages >= max_pages:
        estate.truncated = True
    return items


def _normalise_ping_app(app: dict[str, Any]) -> dict[str, Any]:
    aid = app.get("id") or app.get("clientId")
    return {
        "id": aid,
        "client_id": app.get("enabled") and (app.get("id") or aid),
        "label": app.get("name") or aid,
        "status": "ACTIVE" if app.get("enabled", True) else "INACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "app_type": app.get("type") or "oidc",
        "created": app.get("createdAt"),
        "idp": "ping",
        "discovered_via": "ping_applications",
    }


# ---------------------------------------------------------------------------
# OneLogin — documented GET /api/2/apps  (after_cursor)
# ---------------------------------------------------------------------------
def discover_onelogin(
    *,
    base_url: str,
    token: str,
    transport: Transport,
    page_limit: int = 100,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    base = (base_url or "https://api.us.onelogin.com").rstrip("/")
    estate = IdPEstate(provider="onelogin", base_url=base)
    headers = _bearer(token)
    list_url = base if base.endswith("/apps") else f"{base}/api/2/apps"
    items: list[Any] = []
    cursor = None
    pages = 0
    while pages < max_pages:
        params: dict[str, Any] = {"limit": page_limit}
        if cursor:
            params["after_cursor"] = cursor
        status, body, resp = _exchange(transport, "GET", list_url, headers=headers, params=params)
        estate.requests_made += 1
        if status >= 400:
            if status == 429:
                estate.truncated = True
                estate.warnings.append(f"GET {list_url} rate-limited; kept {len(items)} row(s)")
                break
            if pages == 0:
                estate.error = f"onelogin apps list returned {status}"
                return estate
            estate.warnings.append(f"GET {list_url} returned {status}")
            break
        chunk = body if isinstance(body, list) else (body or {}).get("data") or []
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        cursor = None
        if isinstance(body, dict):
            pag = body.get("pagination") or {}
            cursor = pag.get("after_cursor") or pag.get("next_cursor")
        cursor = cursor or resp.get("After-Cursor") or resp.get("after-cursor")
        if not chunk or not cursor:
            break
    if cursor:
        estate.truncated = True
    estate.applications = [_normalise_onelogin_app(a) for a in items]
    return estate


def _normalise_onelogin_app(app: dict[str, Any]) -> dict[str, Any]:
    aid = app.get("id") or app.get("connector_id")
    return {
        "id": str(aid) if aid is not None else None,
        "label": app.get("name") or str(aid),
        "status": "ACTIVE" if app.get("enabled", True) else "INACTIVE",
        "signOnMode": str(app.get("auth_method") or "SAML"),
        "app_type": app.get("connector_id") and "app",
        "created": app.get("created_at"),
        "idp": "onelogin",
        "discovered_via": "onelogin_apps",
    }


# ---------------------------------------------------------------------------
# oidc_apps dispatcher
# ---------------------------------------------------------------------------
def list_oidc_apps(
    *,
    base_url: str,
    token: str | None,
    transport: Transport,
    flavor: str | None = None,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_grant_fetches: int = 500,
    fetch_grants: bool = True,
    fetch_tokens: bool = True,
    fetch_users: bool = False,
    user_search: str | None = None,
    org_id: str | None = None,
    on_unauthorized=None,
    **_kwargs: Any,
) -> IdPEstate:
    kind = detect_oidc_flavor(base_url, flavor)
    if not token:
        estate = IdPEstate(provider=kind or "oidc_apps", base_url=base_url or "")
        estate.error = "no management token"
        return estate
    if kind == "auth0":
        return discover_auth0(
            domain=base_url,
            access_token=token,
            transport=transport,
            page_limit=min(page_limit, 100),
            max_pages=max_pages,
            fetch_grants=fetch_grants,
            on_unauthorized=on_unauthorized,
        )
    if kind == "entra":
        try:
            return discover_entra(
                base_url=base_url, token=token, transport=transport,
                page_limit=min(page_limit, 99), max_pages=max_pages,
            )
        except RuntimeError as exc:
            estate = IdPEstate(provider="entra", base_url=base_url)
            estate.error = str(exc)
            return estate
    if kind == "ping":
        return discover_ping(
            base_url=base_url, token=token, transport=transport,
            org_id=org_id, page_limit=page_limit, max_pages=max_pages,
        )
    if kind == "onelogin":
        return discover_onelogin(
            base_url=base_url, token=token, transport=transport,
            page_limit=page_limit, max_pages=max_pages,
        )
    if kind == "okta" or not kind:
        if not kind:
            # Unknown host: try Okta-shaped /api/v1/apps only if the URL looks
            # like an Okta org. Otherwise refuse rather than guess.
            estate = IdPEstate(provider="oidc_apps", base_url=base_url)
            estate.error = (
                "oidc_apps: could not tell Okta / Auth0 / Entra / Ping / OneLogin "
                "from the URL. Set probe.flavor."
            )
            return estate
        return discover_okta(
            base_url=base_url,
            token=token,
            transport=transport,
            page_limit=page_limit,
            max_pages=max_pages,
            max_grant_fetches=max_grant_fetches,
            fetch_grants=fetch_grants,
            fetch_tokens=fetch_tokens,
            fetch_users=fetch_users,
            user_search=user_search,
            on_unauthorized=on_unauthorized,
        )
    estate = IdPEstate(provider=kind, base_url=base_url)
    estate.error = f"unknown oidc_apps flavor {kind!r}"
    return estate


# ---------------------------------------------------------------------------
# SCIM 2.0 — RFC 7644 startIndex / itemsPerPage / totalResults
# ---------------------------------------------------------------------------
_SCIM_SERVICE = {
    "service account", "serviceaccount", "service", "bot", "app",
    "workload", "application", "nonhuman", "non-human",
}


def list_scim(
    *,
    base_url: str,
    token: str | None,
    transport: Transport,
    page_limit: int = 100,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    base = (base_url or "").rstrip("/")
    estate = IdPEstate(provider="scim", base_url=base)
    if not base:
        estate.error = "scim needs a base URL (the SCIM /Users root or its parent)"
        return estate
    if not token:
        estate.error = "no SCIM bearer token"
        return estate
    users_url = base if base.endswith("/Users") else f"{base}/Users"
    headers = _bearer(token)
    items: list[Any] = []
    start = 1
    pages = 0
    total = None
    while pages < max_pages:
        status, body, _ = _exchange(
            transport, "GET", users_url, headers=headers,
            params={"startIndex": start, "count": page_limit},
        )
        estate.requests_made += 1
        if status >= 400:
            if pages == 0:
                estate.error = f"scim Users list returned {status}"
                return estate
            estate.warnings.append(f"scim Users returned {status}")
            break
        blob = body if isinstance(body, dict) else {}
        chunk = blob.get("Resources") if isinstance(blob.get("Resources"), list) else (
            body if isinstance(body, list) else []
        )
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        try:
            total = int(blob.get("totalResults")) if blob.get("totalResults") is not None else total
        except (TypeError, ValueError):
            pass
        if not chunk:
            break
        start += len(chunk)
        if total is not None:
            if start > total:
                break
            continue
        if len(chunk) < page_limit:
            break
    if total is not None and len(items) < total and pages >= max_pages:
        estate.truncated = True
    services = [u for u in items if _is_scim_service(u)]
    skipped = len(items) - len(services)
    if skipped:
        estate.warnings.append(
            f"scim: kept {len(services)} service account(s), skipped {skipped} human user(s)"
        )
    estate.service_accounts = [_normalise_scim_user(u) for u in services]
    return estate


def _is_scim_service(user: dict[str, Any]) -> bool:
    user_type = str(user.get("userType") or user.get("user_type") or "").lower()
    if user_type in _SCIM_SERVICE:
        return True
    emails = user.get("emails") or []
    if isinstance(emails, list):
        for item in emails:
            value = (item.get("value") if isinstance(item, dict) else str(item)).lower()
            if "gserviceaccount.com" in value or value.startswith("svc-") or "+bot@" in value:
                return True
    ext = user.get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User") or {}
    if str(ext.get("employeeNumber") or "").lower().startswith("svc"):
        return True
    # Default: do not treat unmarked users as NHIs.
    return False


def _normalise_scim_user(user: dict[str, Any]) -> dict[str, Any]:
    uid = user.get("id") or user.get("externalId")
    name = (
        (user.get("name") or {}).get("formatted")
        if isinstance(user.get("name"), dict)
        else None
    ) or user.get("displayName") or user.get("userName") or uid
    return {
        "id": uid,
        "name": name,
        "status": "ACTIVE" if user.get("active", True) else "INACTIVE",
        "created": (user.get("meta") or {}).get("created"),
        "userType": user.get("userType") or "service",
        "idp": "scim",
        "discovered_via": "scim_users",
    }


# ---------------------------------------------------------------------------
# generic_rest — endpoint + JSONPath mapping
# ---------------------------------------------------------------------------
def list_generic_rest(
    *,
    base_url: str,
    token: str | None,
    transport: Transport,
    mapping: dict[str, str] | None = None,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    estate = IdPEstate(provider="generic_rest", base_url=base_url or "")
    if not base_url:
        estate.error = "generic_rest needs probe.base_url (the list endpoint)"
        return estate
    headers = _bearer(token or "")
    mapping = mapping or {}
    list_path = mapping.get("list") or mapping.get("items") or ""
    id_path = mapping.get("id") or "id"
    name_path = mapping.get("name") or mapping.get("display_name") or "name"
    scopes_path = mapping.get("scopes") or "scopes"
    owner_path = mapping.get("owner") or "owner"
    status, body, resp = _exchange(transport, "GET", base_url, headers=headers)
    estate.requests_made += 1
    estate.pages_fetched += 1
    if status >= 400:
        estate.error = f"generic_rest GET {base_url} returned {status}"
        return estate
    rows = jsonpath_get(body, list_path) if list_path else body
    if isinstance(rows, dict):
        for key in ("items", "data", "value", "results", "resources"):
            if isinstance(rows.get(key), list):
                rows = rows[key]
                break
    if not isinstance(rows, list):
        estate.error = (
            "generic_rest: response was not a list. Set probe.mapping.list "
            "to the JSONPath of the array (e.g. items or $.value)."
        )
        return estate
    nxt = next_link(resp, base=base_url)
    pages = 1
    while nxt and pages < max_pages:
        status, more, resp = _exchange(transport, "GET", nxt, headers=headers)
        estate.requests_made += 1
        if status >= 400:
            estate.warnings.append(f"generic_rest next page returned {status}")
            break
        extra = jsonpath_get(more, list_path) if list_path else more
        if isinstance(extra, list):
            rows.extend(extra)
        pages += 1
        estate.pages_fetched += 1
        nxt = next_link(resp, base=base_url)
        if isinstance(more, dict) and more.get("@odata.nextLink"):
            nxt = more["@odata.nextLink"]
    if nxt:
        estate.truncated = True

    apps: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        nid = jsonpath_get(row, id_path)
        if nid is None:
            continue
        scopes = jsonpath_get(row, scopes_path) or []
        if isinstance(scopes, str):
            scopes = [s for s in scopes.replace(",", " ").split() if s]
        owner = jsonpath_get(row, owner_path)
        if isinstance(owner, dict):
            owner = owner.get("email") or owner.get("name")
        scope_list = list(scopes) if isinstance(scopes, list) else []
        apps.append({
            "id": nid,
            "client_id": nid,
            "label": jsonpath_get(row, name_path) or nid,
            "status": "ACTIVE",
            "signOnMode": "API",
            "owner": owner,
            "idp": "generic_rest",
            "discovered_via": "generic_rest",
        })
        if scope_list:
            estate.oauth_grants.append({
                "app_id": nid,
                "client_name": jsonpath_get(row, name_path) or nid,
                "principal": jsonpath_get(row, name_path) or nid,
                "scopes": scope_list,
                "idp": "generic_rest",
                "discovered_via": "generic_rest",
            })
    estate.applications = apps
    return estate


# ---------------------------------------------------------------------------
# Pings
# ---------------------------------------------------------------------------
def _ping_okta(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport

    bus = transport or LiveTransport()
    base = (base_url or os.environ.get("OKTA_BASE_URL") or "").rstrip("/")
    if not base:
        return False, "pass --base-url https://your-org.okta.com"
    token = secrets.get("api_token") or ""
    status, _, _ = _exchange(
        bus, "GET", f"{base}/api/v1/org", headers=_ssws(token),
    )
    if status < 400:
        return True, f"okta org reachable ({status})"
    return False, f"okta /api/v1/org returned {status}"


def _ping_auth0(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport, _auth0_base, mint_auth0_token

    bus = transport or LiveTransport()
    domain = (base_url or os.environ.get("AUTH0_DOMAIN") or "").rstrip("/")
    if not domain:
        return False, "pass --base-url https://your-tenant.us.auth0.com"
    token = secrets.get("management_token")
    if not token and secrets.get("client_id") and secrets.get("client_secret"):
        token, _, err = mint_auth0_token(
            bus, domain, secrets["client_id"], secrets["client_secret"]
        )
        if err or not token:
            return False, err or "auth0 mint failed"
    if not token:
        return False, "need client_id+client_secret or management_token"
    base = _auth0_base(domain)
    status, _, _ = _exchange(
        bus, "GET", f"{base}/api/v2/clients",
        headers=_auth0_headers(token),
        params={"per_page": 1, "page": 0, "include_totals": "true"},
    )
    if status < 400:
        return True, f"auth0 clients reachable ({status})"
    return False, f"auth0 /api/v2/clients returned {status}"


def _ping_entra(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport

    bus = transport or LiveTransport()
    base = (base_url or "https://graph.microsoft.com").rstrip("/")
    token = secrets.get("api_token") or ""
    status, _, _ = _exchange(
        bus, "GET", f"{base}/v1.0/applications",
        headers=_bearer(token), params={"$top": 1},
    )
    if status < 400:
        return True, f"entra applications reachable ({status})"
    return False, f"entra /v1.0/applications returned {status}"


def _ping_scim(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport

    bus = transport or LiveTransport()
    base = (base_url or "").rstrip("/")
    if not base:
        return False, "pass --base-url of the SCIM endpoint"
    token = secrets.get("api_token") or ""
    url = f"{base}/ServiceProviderConfig" if not base.endswith("ServiceProviderConfig") else base
    status, _, _ = _exchange(bus, "GET", url, headers=_bearer(token))
    if status < 400:
        return True, f"scim ServiceProviderConfig reachable ({status})"
    users = base if base.endswith("/Users") else f"{base}/Users"
    status, _, _ = _exchange(
        bus, "GET", users, headers=_bearer(token), params={"count": 1, "startIndex": 1},
    )
    if status < 400:
        return True, f"scim Users reachable ({status})"
    return False, f"scim ping returned {status}"


def _ping_generic(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport

    bus = transport or LiveTransport()
    if not base_url:
        return False, "pass --base-url of the list endpoint"
    token = secrets.get("api_token") or ""
    status, _, _ = _exchange(bus, "GET", base_url, headers=_bearer(token))
    if status < 400:
        return True, f"generic_rest reachable ({status})"
    return False, f"generic_rest GET returned {status}"


def _ping_bearer(path: str, name: str):
    def _fn(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
        from .idp import LiveTransport

        bus = transport or LiveTransport()
        base = (base_url or "").rstrip("/")
        token = secrets.get("api_token") or ""
        url = (base + path) if base else path
        status, _, _ = _exchange(bus, "GET", url, headers=_bearer(token))
        if status < 400:
            return True, f"{name} reachable ({status})"
        return False, f"{name} returned {status}"
    return _fn


def _wrap_oidc(*, flavor: str | None = None):
    def _fn(*, base_url: str, token: str | None, transport: Transport, **kwargs: Any) -> IdPEstate:
        kwargs = dict(kwargs)
        kwargs.setdefault("flavor", flavor)
        return list_oidc_apps(base_url=base_url, token=token, transport=transport, **kwargs)
    return _fn


def register_all() -> None:
    oidc_fields = ("api_token",)
    auth0_fields = ("client_id", "client_secret", "management_token")

    register(
        ConnectorManifest(
            id="oidc_apps",
            display_name="OIDC apps (Okta / Auth0 / Entra / Ping / OneLogin)",
            kind="protocol",
            protocol="oidc_apps",
            auth="bearer",
            fields=oidc_fields,
            pagination="auto",
            list_method="GET applications / clients / servicePrincipals (flavor from URL)",
            category="identity_provider",
            url_prompt="Org / tenant URL?",
            url_hint="https://acme.okta.com  or  https://graph.microsoft.com",
            field_prompts={"api_token": "Paste API / management token (hidden)"},
        ),
        list_nhis=list_oidc_apps,
        ping=_ping_okta,
    )
    register(
        ConnectorManifest(
            id="okta",
            display_name="Okta",
            kind="alias",
            protocol="oidc_apps",
            flavor="okta",
            auth="ssws",
            fields=("api_token",),
            pagination="link",
            list_method="GET /api/v1/apps + /apps/{id}/grants + /api-tokens",
            category="identity_provider",
            url_prompt="Org URL?",
            url_hint="https://acme.okta.com",
            url_hosts=("okta.com", "oktapreview.com"),
            opaque_admin=True,
            env={"api_token": ("OKTA_API_TOKEN", "AEGIS_API_TOKEN")},
            field_prompts={"api_token": "Paste API token (hidden)"},
        ),
        list_nhis=_wrap_oidc(flavor="okta"),
        ping=_ping_okta,
    )
    register(
        ConnectorManifest(
            id="auth0",
            display_name="Auth0",
            kind="alias",
            protocol="oidc_apps",
            flavor="auth0",
            auth="oauth_client",
            fields=auth0_fields,
            required=("client_id", "client_secret"),
            pagination="page",
            list_method="GET /api/v2/clients + /api/v2/client-grants",
            category="identity_provider",
            url_prompt="Tenant URL?",
            url_hint="https://acme.us.auth0.com",
            url_hosts=("auth0.com",),
            env={
                "client_id": ("AUTH0_CLIENT_ID",),
                "client_secret": ("AUTH0_CLIENT_SECRET",),
                "management_token": ("AUTH0_MGMT_TOKEN",),
            },
            field_prompts={
                "client_id": "Client ID (hidden)",
                "client_secret": "Client secret (hidden)",
            },
        ),
        list_nhis=_wrap_oidc(flavor="auth0"),
        ping=_ping_auth0,
    )
    register(
        ConnectorManifest(
            id="entra",
            display_name="Microsoft Entra ID",
            kind="alias",
            protocol="oidc_apps",
            flavor="entra",
            auth="bearer",
            fields=("api_token",),
            pagination="odata",
            list_method="GET /v1.0/applications + /v1.0/servicePrincipals",
            category="identity_provider",
            url_prompt="Graph URL?",
            url_hint="https://graph.microsoft.com",
            default_url="https://graph.microsoft.com",
            url_required=False,
            url_hosts=("graph.microsoft.com", "microsoftonline.com"),
            field_prompts={"api_token": "Paste Graph token (hidden)"},
        ),
        list_nhis=_wrap_oidc(flavor="entra"),
        ping=_ping_entra,
    )
    register(
        ConnectorManifest(
            id="ping",
            display_name="PingOne",
            kind="alias",
            protocol="oidc_apps",
            flavor="ping",
            auth="bearer",
            fields=("api_token",),
            pagination="hal",
            list_method="GET /v1/environments/{id}/applications",
            category="identity_provider",
            url_prompt="Environment URL?",
            url_hint="https://api.pingone.com/v1/environments/{envId}",
            url_hosts=("pingone.com", "pingidentity.com"),
            field_prompts={"api_token": "Paste API token (hidden)"},
        ),
        list_nhis=_wrap_oidc(flavor="ping"),
        ping=_ping_bearer("/v1/environments", "ping"),
    )
    register(
        ConnectorManifest(
            id="onelogin",
            display_name="OneLogin",
            kind="alias",
            protocol="oidc_apps",
            flavor="onelogin",
            auth="bearer",
            fields=("api_token",),
            pagination="cursor",
            list_method="GET /api/2/apps",
            category="identity_provider",
            url_prompt="API URL?",
            url_hint="https://api.us.onelogin.com",
            default_url="https://api.us.onelogin.com",
            url_required=False,
            url_hosts=("onelogin.com",),
            field_prompts={"api_token": "Paste API token (hidden)"},
        ),
        list_nhis=_wrap_oidc(flavor="onelogin"),
        ping=_ping_bearer("/api/2/apps", "onelogin"),
    )
    register(
        ConnectorManifest(
            id="scim",
            display_name="SCIM 2.0",
            kind="protocol",
            protocol="scim",
            auth="bearer",
            fields=("api_token",),
            pagination="scim",
            list_method="GET /Users (startIndex / count) — service accounts only",
            category="identity_provider",
            url_prompt="SCIM base URL?",
            url_hint="https://example.com/scim/v2",
            field_prompts={"api_token": "Paste SCIM bearer token (hidden)"},
        ),
        list_nhis=list_scim,
        ping=_ping_scim,
    )
    register(
        ConnectorManifest(
            id="generic_rest",
            display_name="Generic REST (JSONPath)",
            kind="protocol",
            protocol="generic_rest",
            auth="bearer",
            fields=("api_token",),
            pagination="link",
            list_method="GET {endpoint} + probe.mapping JSONPath",
            category="other",
            url_prompt="List endpoint?",
            url_hint="https://api.example.com/v1/service-accounts",
            field_prompts={"api_token": "Paste bearer token (hidden)"},
        ),
        list_nhis=list_generic_rest,
        ping=_ping_generic,
    )
