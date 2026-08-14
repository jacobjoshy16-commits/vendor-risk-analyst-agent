"""Pull the full NHI list from an identity provider API.

The inventory is not a YAML file a human typed. It is every application,
OAuth client, client grant, API token, and (optionally) service-account
user the IdP actually returns. Two providers:

  Okta   — ``GET /api/v1/apps`` (Link-header pages), per-app
           ``/api/v1/apps/{id}/grants``, ``GET /api/v1/api-tokens``,
           optional ``GET /api/v1/users`` with a service-account search.
  Auth0  — ``GET /api/v2/clients`` and ``GET /api/v2/client-grants``
           (``page`` / ``per_page`` / ``include_totals``).

The same walker consumes live HTTP and recorded page sets. A single
hand-copied curl blob is not discovery; following every next-page is.

Tokens come from the environment only. They are never written to the
estate, the inventory, or the report. The model is not on this path.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from .config import REPO_ROOT, RunConfig

DEFAULT_PAGE_LIMIT = 200
DEFAULT_MAX_PAGES = 50
DEFAULT_MAX_GRANT_FETCHES = 500
USER_AGENT = "vra-nhi-monitor/1.4"

_LINK_NEXT = re.compile(r"<([^>]+)>\s*;\s*rel=\"?next\"?", re.I)
_SECRET_HEADER = {"authorization", "proxy-authorization"}
_SECRET_KEYS = {
    "client_secret",
    "password",
    "api_token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
}


# ---------------------------------------------------------------------------
# Estate
# ---------------------------------------------------------------------------
@dataclass
class IdPEstate:
    """Normalised tenant inventory. Every list item quotes an API object."""

    provider: str
    base_url: str
    org: dict[str, Any] = field(default_factory=dict)
    applications: list[dict] = field(default_factory=list)
    oauth_grants: list[dict] = field(default_factory=list)
    api_tokens: list[dict] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)
    settings: dict[str, Any] = field(default_factory=dict)
    pages_fetched: int = 0
    requests_made: int = 0
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        return {
            "applications": len(self.applications),
            "oauth_grants": len(self.oauth_grants),
            "api_tokens": len(self.api_tokens),
            "service_accounts": len(self.service_accounts),
        }

    def to_probe_blob(self) -> dict[str, Any]:
        """Shape ``probe._extract_nhis`` already understands, plus extras."""
        return {
            "org": self.org,
            "settings": self.settings,
            "applications": self.applications,
            "oauth_grants": self.oauth_grants,
            "api_tokens": self.api_tokens,
            "service_accounts": self.service_accounts,
            "_discovery": {
                "provider": self.provider,
                "base_url": self.base_url,
                "pages_fetched": self.pages_fetched,
                "requests_made": self.requests_made,
                "truncated": self.truncated,
                "warnings": list(self.warnings),
                "counts": self.counts,
            },
        }


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------
class Transport:
    """GET/POST JSON. Live and recorded implementations share this surface."""

    calls: list[tuple[str, str]]

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        raise NotImplementedError


class LiveTransport(Transport):
    def __init__(self) -> None:
        self.calls = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        import requests

        self.calls.append((method.upper(), _with_params(url, params)))
        response = requests.request(
            method,
            url,
            headers=headers,
            params=params,
            json=json_body,
            timeout=30,
        )
        try:
            body = response.json() if response.content else None
        except ValueError:
            body = None
        return response.status_code, body, {k: v for k, v in response.headers.items()}


class MemoryTransport(Transport):
    """Exact-URL (then path+query) map. Used by tests and recorded fixtures."""

    def __init__(self) -> None:
        self.routes: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []

    def add(
        self,
        method: str,
        url: str,
        body: Any,
        *,
        headers: dict[str, str] | None = None,
        status: int = 200,
    ) -> None:
        key = _route_key(method, url)
        self.routes[key] = {
            "body": body,
            "headers": {k: str(v) for k, v in (headers or {}).items()},
            "status": status,
        }

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        full = _with_params(url, params)
        self.calls.append((method.upper(), full))
        hit = self.routes.get(_route_key(method, full))
        if hit is None:
            # Fall back to path + query against whatever host was recorded.
            parsed = urlparse(full)
            for key, route in self.routes.items():
                stored_method, stored_url = key.split(" ", 1)
                if stored_method != method.upper():
                    continue
                stored = urlparse(stored_url)
                if stored.path == parsed.path and _query_dict(stored.query) == _query_dict(parsed.query):
                    hit = route
                    break
        if hit is None:
            return 404, None, {}
        return int(hit["status"]), hit["body"], dict(hit["headers"])


def load_recorded_transport(data: dict[str, Any] | Path) -> tuple[MemoryTransport, str, str]:
    """Build a MemoryTransport from a recorded page set.

    Accepted shapes:
      ``{"provider", "base_url", "pages": [{method, url, body, headers, status}]}``
      or a Path to that JSON.
    """
    if isinstance(data, Path):
        blob = json.loads(data.read_text(encoding="utf-8"))
    else:
        blob = data
    provider = (blob.get("provider") or "okta").lower()
    base = (blob.get("base_url") or blob.get("domain") or "").rstrip("/")
    transport = MemoryTransport()
    for page in blob.get("pages") or []:
        method = page.get("method") or "GET"
        url = page.get("url") or ""
        if url.startswith("/") and base:
            url = base + url
        transport.add(
            method,
            url,
            page.get("body"),
            headers=page.get("headers") or {},
            status=int(page.get("status") or 200),
        )
    return transport, provider, base


# ---------------------------------------------------------------------------
# URL / header helpers
# ---------------------------------------------------------------------------
def _query_dict(query: str) -> dict[str, str]:
    return {k: v for k, v in parse_qsl(query, keep_blank_values=True)}


def _canonical_url(url: str) -> str:
    parsed = urlparse(url)
    items = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(items)
    netloc = parsed.netloc
    return urlunparse((parsed.scheme, netloc, parsed.path, "", query, ""))


def _route_key(method: str, url: str) -> str:
    return f"{method.upper()} {_canonical_url(url)}"


def _with_params(url: str, params: dict[str, Any] | None) -> str:
    if not params:
        return url
    parsed = urlparse(url)
    merged = _query_dict(parsed.query)
    for key, value in params.items():
        if value is None:
            continue
        merged[str(key)] = str(value)
    return urlunparse(parsed._replace(query=urlencode(sorted(merged.items()))))


def next_link(headers: dict[str, str], *, base: str = "") -> str | None:
    raw = headers.get("Link") or headers.get("link") or ""
    if not raw:
        return None
    for part in raw.split(","):
        match = _LINK_NEXT.search(part)
        if match:
            href = match.group(1).strip()
            if href.startswith("http"):
                return href
            return urljoin(base.rstrip("/") + "/", href.lstrip("/"))
    return None


def infer_provider(block: dict[str, Any] | None, *, base_url: str = "") -> str:
    block = block or {}
    explicit = str(block.get("provider") or "").strip().lower()
    if explicit in {"okta", "auth0", "atlassian", "slack"}:
        return explicit
    url = (base_url or block.get("base_url") or block.get("domain") or "").lower()
    if "auth0.com" in url or ".auth0." in url:
        return "auth0"
    if "okta.com" in url or "oktapreview.com" in url or "okta-" in url:
        return "okta"
    if "atlassian.com" in url or "atlassian.net" in url:
        return "atlassian"
    if "slack.com" in url:
        return "slack"
    kind = str(block.get("type") or "").lower()
    if "identity" in kind:
        return "okta"
    return explicit or "okta"


def slug_from_base(url: str) -> str:
    host = urlparse(url).netloc or url
    host = host.split("@")[-1].split(":")[0]
    slug = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")
    return slug or "idp"


def redact(value: Any) -> Any:
    """Drop secrets so an estate / log can never echo a token."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEYS or str(key).lower() in _SECRET_HEADER:
                out[key] = "<redacted>"
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _contains_secret(blob: Any, secret: str) -> bool:
    if not secret:
        return False
    if isinstance(blob, str):
        return secret in blob
    if isinstance(blob, dict):
        return any(_contains_secret(v, secret) for v in blob.values())
    if isinstance(blob, list):
        return any(_contains_secret(v, secret) for v in blob)
    return False


# ---------------------------------------------------------------------------
# HTTP with 429 retry
# ---------------------------------------------------------------------------
def _exchange(
    transport: Transport,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    retries: int = 3,
) -> tuple[int, Any, dict[str, str]]:
    delay = 0.5
    status, body, resp_headers = 0, None, {}
    for attempt in range(retries):
        status, body, resp_headers = transport.request(
            method, url, headers=headers, params=params, json_body=json_body
        )
        if status != 429 or attempt == retries - 1:
            return status, body, resp_headers
        raw_wait = resp_headers.get("Retry-After") or resp_headers.get("retry-after") or delay
        try:
            wait = float(raw_wait)
        except (TypeError, ValueError):
            wait = delay
        time.sleep(min(max(wait, 0.0), 15.0))
        delay = min(delay * 2, 8.0)
    return status, body, resp_headers


# ---------------------------------------------------------------------------
# Classification — quote API fields only, never invent agent_principal
# ---------------------------------------------------------------------------
def classify_kind(app: dict[str, Any], provider: str) -> str:
    if app.get("ai_component"):
        return "agent_principal"
    if provider == "auth0":
        if str(app.get("app_type") or "") == "non_interactive":
            return "service_account"
        return "oauth_app"
    if provider == "slack":
        if app.get("is_bot") or str(app.get("app_type") or "") == "bot":
            return "bot"
        return "oauth_app"
    if provider == "atlassian":
        if str(app.get("app_type") or "") in {"agent", "rovo"}:
            return "agent_principal"
        return "oauth_app"
    mode = str(app.get("signOnMode") or "").upper()
    if mode in {"SERVICE", "SERVICE_ACCOUNT", "API_SERVICES"}:
        return "service_account"
    grants = app.get("grant_types") or []
    if grants and all(g == "client_credentials" for g in grants):
        return "service_account"
    return "oauth_app"


def _wants_okta_grants(app: dict[str, Any]) -> bool:
    mode = str(app.get("signOnMode") or "").upper()
    if mode in {"OPENID_CONNECT", "OAUTH2", "API_SERVICES"}:
        return True
    creds = app.get("credentials") or {}
    return bool(creds.get("oauthClient"))


# ---------------------------------------------------------------------------
# Okta
# ---------------------------------------------------------------------------
def _okta_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"SSWS {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


def _paginate_okta_list(
    transport: Transport,
    base: str,
    path: str,
    headers: dict[str, str],
    estate: IdPEstate,
    *,
    page_limit: int,
    max_pages: int,
    params: dict[str, Any] | None = None,
) -> list[Any]:
    items: list[Any] = []
    url = f"{base}{path}"
    query = {"limit": page_limit, **(params or {})}
    seen_first: set[str] = set()
    pages = 0
    while url and pages < max_pages:
        status, body, resp_headers = _exchange(
            transport, "GET", url, headers=headers, params=query
        )
        estate.requests_made += 1
        if status >= 400:
            raise RuntimeError(f"GET {path} returned {status}")
        page_items = body if isinstance(body, list) else (body or {}).get("items") or []
        if page_items:
            first_id = str(page_items[0].get("id") or page_items[0])
            if first_id in seen_first:
                break
            seen_first.add(first_id)
        items.extend(page_items)
        pages += 1
        estate.pages_fetched += 1
        url = next_link(resp_headers, base=base)
        query = None
        if not page_items and not url:
            break
    if url and pages >= max_pages:
        estate.truncated = True
    return items


def discover_okta(
    *,
    base_url: str,
    token: str,
    transport: Transport,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_grant_fetches: int = DEFAULT_MAX_GRANT_FETCHES,
    fetch_grants: bool = True,
    fetch_tokens: bool = True,
    fetch_users: bool = False,
    user_search: str | None = None,
) -> IdPEstate:
    base = base_url.rstrip("/")
    estate = IdPEstate(provider="okta", base_url=base, org={"subdomain": urlparse(base).netloc})
    headers = _okta_headers(token)

    try:
        raw_apps = _paginate_okta_list(
            transport, base, "/api/v1/apps", headers, estate,
            page_limit=page_limit, max_pages=max_pages,
        )
    except RuntimeError as exc:
        estate.error = f"okta apps list failed: {exc}"
        return estate

    estate.applications = [_normalise_okta_app(app) for app in raw_apps]

    if fetch_grants:
        fetched = 0
        for app in estate.applications:
            if fetched >= max_grant_fetches:
                estate.truncated = True
                estate.warnings.append(
                    f"stopped grant fetches at {max_grant_fetches} (more OIDC apps remain)"
                )
                break
            if not _wants_okta_grants(app):
                continue
            app_id = app["id"]
            status, body, _ = _exchange(
                transport,
                "GET",
                f"{base}/api/v1/apps/{app_id}/grants",
                headers=headers,
                params={"limit": page_limit},
            )
            estate.requests_made += 1
            fetched += 1
            if status == 404:
                continue
            if status >= 400:
                estate.warnings.append(f"grants for {app_id} returned {status}")
                continue
            raw_grants = body if isinstance(body, list) else []
            estate.oauth_grants.append(_normalise_okta_grants(app, raw_grants))

    if fetch_tokens:
        try:
            tokens = _paginate_okta_list(
                transport, base, "/api/v1/api-tokens", headers, estate,
                page_limit=page_limit, max_pages=max_pages,
            )
            estate.api_tokens = [_normalise_okta_token(tok) for tok in tokens]
        except RuntimeError as exc:
            estate.warnings.append(f"api-tokens skipped: {exc}")

    if fetch_users:
        search = user_search or 'profile.userType eq "Service Account"'
        try:
            users = _paginate_okta_list(
                transport, base, "/api/v1/users", headers, estate,
                page_limit=page_limit, max_pages=max_pages,
                params={"search": search},
            )
            estate.service_accounts = [_normalise_okta_user(user) for user in users]
        except RuntimeError as exc:
            estate.warnings.append(f"service-account users skipped: {exc}")

    return estate


def _normalise_okta_app(app: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": app.get("id"),
        "label": app.get("label") or app.get("name"),
        "status": app.get("status") or "ACTIVE",
        "signOnMode": app.get("signOnMode"),
        "ai_component": bool(app.get("ai_component")),
        "created": app.get("created"),
        "grant_types": list((app.get("settings") or {}).get("oauthClient", {}).get("grant_types") or []),
        "credentials": app.get("credentials") or {},
        "idp": "okta",
        "discovered_via": "okta_apps",
    }


def _normalise_okta_grants(app: dict[str, Any], grants: list[dict]) -> dict[str, Any]:
    scopes: list[str] = []
    issued = None
    for grant in grants:
        if grant.get("scopes"):
            scopes.extend(grant.get("scopes") or [])
        elif grant.get("scopeId"):
            scopes.append(str(grant["scopeId"]))
        issued = issued or grant.get("created") or grant.get("issued")
    scopes = sorted({s for s in scopes if s})
    return {
        "app_id": app.get("id"),
        "client_name": app.get("label"),
        "principal": app.get("label"),
        "scopes": scopes,
        "issued": issued,
        "idp": "okta",
        "discovered_via": "okta_grants",
    }


def _normalise_okta_token(token: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": token.get("id"),
        "name": token.get("name") or token.get("id"),
        "created": token.get("created"),
        "expiresAt": token.get("expiresAt"),
        "clientName": token.get("clientName"),
        "idp": "okta",
        "discovered_via": "okta_api_tokens",
    }


def _normalise_okta_user(user: dict[str, Any]) -> dict[str, Any]:
    profile = user.get("profile") or {}
    login = profile.get("login") or profile.get("email") or user.get("id")
    return {
        "id": user.get("id"),
        "name": login,
        "status": user.get("status"),
        "created": user.get("created"),
        "userType": profile.get("userType") or (user.get("type") or {}).get("id"),
        "idp": "okta",
        "discovered_via": "okta_users",
    }


# ---------------------------------------------------------------------------
# Auth0
# ---------------------------------------------------------------------------
def _auth0_headers(access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


def mint_auth0_token(
    transport: Transport,
    domain: str,
    client_id: str,
    client_secret: str,
    audience: str | None = None,
) -> tuple[str | None, str | None]:
    base = _auth0_base(domain)
    aud = audience or f"{base}/api/v2/"
    status, body, _ = _exchange(
        transport,
        "POST",
        f"{base}/oauth/token",
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        json_body={
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": aud,
            "grant_type": "client_credentials",
        },
    )
    if status >= 400 or not isinstance(body, dict) or not body.get("access_token"):
        return None, f"auth0 token endpoint returned {status}"
    return str(body["access_token"]), None


def _auth0_base(domain: str) -> str:
    raw = domain.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw.rstrip("/")
    return f"https://{raw.rstrip('/')}"


def _paginate_auth0(
    transport: Transport,
    base: str,
    path: str,
    key: str,
    headers: dict[str, str],
    estate: IdPEstate,
    *,
    page_limit: int,
    max_pages: int,
) -> list[Any]:
    items: list[Any] = []
    page = 0
    while page < max_pages:
        status, body, _ = _exchange(
            transport,
            "GET",
            f"{base}{path}",
            headers=headers,
            params={"page": page, "per_page": page_limit, "include_totals": "true"},
        )
        estate.requests_made += 1
        if status >= 400:
            raise RuntimeError(f"GET {path} returned {status}")
        if isinstance(body, list):
            chunk, total = body, None
        else:
            blob = body or {}
            chunk = blob.get(key) or blob.get("items") or []
            total = blob.get("total")
        items.extend(chunk)
        estate.pages_fetched += 1
        page += 1
        if not chunk:
            break
        if len(chunk) < page_limit:
            break
        if total is not None and page * page_limit >= int(total):
            break
    if page >= max_pages and (total is None or len(items) < int(total or 0)):
        # Only mark truncated when we stopped because of the cap, not because
        # the last page was full and also happened to be the last page.
        if total is not None and len(items) < int(total):
            estate.truncated = True
        elif total is None and len(chunk) == page_limit:
            estate.truncated = True
    return items


def discover_auth0(
    *,
    domain: str,
    access_token: str,
    transport: Transport,
    page_limit: int = 100,
    max_pages: int = DEFAULT_MAX_PAGES,
    fetch_grants: bool = True,
) -> IdPEstate:
    base = _auth0_base(domain)
    estate = IdPEstate(provider="auth0", base_url=base, org={"domain": urlparse(base).netloc})
    headers = _auth0_headers(access_token)

    try:
        clients = _paginate_auth0(
            transport, base, "/api/v2/clients", "clients", headers, estate,
            page_limit=page_limit, max_pages=max_pages,
        )
    except RuntimeError as exc:
        estate.error = f"auth0 clients list failed: {exc}"
        return estate

    estate.applications = [_normalise_auth0_client(c) for c in clients]
    names = {c.get("id"): c.get("label") for c in estate.applications}

    if fetch_grants:
        try:
            grants = _paginate_auth0(
                transport, base, "/api/v2/client-grants", "client_grants", headers, estate,
                page_limit=page_limit, max_pages=max_pages,
            )
            estate.oauth_grants = [_normalise_auth0_grant(g, names) for g in grants]
        except RuntimeError as exc:
            estate.warnings.append(f"client-grants skipped: {exc}")

    return estate


def _normalise_auth0_client(client: dict[str, Any]) -> dict[str, Any]:
    disabled = bool(client.get("is_disabled") or client.get("disabled"))
    return {
        "id": client.get("client_id") or client.get("id"),
        "label": client.get("name") or client.get("client_id"),
        "status": "INACTIVE" if disabled else "ACTIVE",
        "signOnMode": "OPENID_CONNECT",
        "app_type": client.get("app_type"),
        "ai_component": bool(client.get("ai_component")),
        "created": client.get("created_at") or client.get("created"),
        "grant_types": list(client.get("grant_types") or []),
        "idp": "auth0",
        "discovered_via": "auth0_clients",
    }


def _normalise_auth0_grant(grant: dict[str, Any], names: dict[Any, Any]) -> dict[str, Any]:
    client_id = grant.get("client_id")
    scopes = grant.get("scope") or grant.get("scopes") or []
    if isinstance(scopes, str):
        scopes = [s for s in scopes.split() if s]
    name = names.get(client_id) or client_id
    return {
        "app_id": client_id,
        "client_name": name,
        "principal": name,
        "scopes": list(scopes),
        "audience": grant.get("audience"),
        "issued": grant.get("created_at"),
        "idp": "auth0",
        "discovered_via": "auth0_client_grants",
    }


# ---------------------------------------------------------------------------
# Entry points used by probe / CLI
# ---------------------------------------------------------------------------
def discover_estate(
    *,
    provider: str,
    base_url: str,
    transport: Transport,
    token: str | None = None,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_grant_fetches: int = DEFAULT_MAX_GRANT_FETCHES,
    fetch_grants: bool = True,
    fetch_tokens: bool = True,
    fetch_users: bool = False,
    user_search: str | None = None,
    org_id: str | None = None,
) -> IdPEstate:
    provider = (provider or "okta").lower()
    if provider == "atlassian":
        if not token:
            estate = IdPEstate(provider="atlassian", base_url=base_url or "https://api.atlassian.com")
            estate.error = "no Atlassian API token"
            return estate
        from .connectors import discover_atlassian

        return discover_atlassian(
            base_url=base_url or "https://api.atlassian.com",
            token=token,
            transport=transport,
            org_id=org_id,
            page_limit=page_limit,
            max_pages=max_pages,
        )
    if provider == "slack":
        if not token:
            estate = IdPEstate(provider="slack", base_url=base_url or "https://slack.com")
            estate.error = "no Slack token"
            return estate
        from .connectors import discover_slack

        return discover_slack(
            base_url=base_url or "https://slack.com",
            token=token,
            transport=transport,
            page_limit=min(page_limit, 200),
            max_pages=max_pages,
        )
    if provider == "auth0":
        if not token:
            estate = IdPEstate(provider="auth0", base_url=_auth0_base(base_url))
            estate.error = "no Auth0 management token"
            return estate
        return discover_auth0(
            domain=base_url,
            access_token=token,
            transport=transport,
            page_limit=min(page_limit, 100),
            max_pages=max_pages,
            fetch_grants=fetch_grants,
        )
    if not token:
        estate = IdPEstate(provider="okta", base_url=base_url.rstrip("/"))
        estate.error = "no Okta API token"
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
    )


def _block_options(block: dict[str, Any]) -> dict[str, Any]:
    return {
        "page_limit": int(block.get("page_limit") or DEFAULT_PAGE_LIMIT),
        "max_pages": int(block.get("max_pages") or DEFAULT_MAX_PAGES),
        "max_grant_fetches": int(block.get("max_grant_fetches") or DEFAULT_MAX_GRANT_FETCHES),
        "fetch_grants": block.get("fetch_grants", True),
        "fetch_tokens": block.get("fetch_tokens", True),
        "fetch_users": bool(block.get("fetch_users")),
        "user_search": block.get("user_search"),
        "org_id": block.get("org_id"),
    }


def _live_token(block: dict[str, Any], provider: str, transport: Transport, base: str) -> tuple[str | None, str | None]:
    """Resolve a management token from the environment. Never persist it."""
    if provider == "atlassian":
        env_name = block.get("token_env") or "ATLASSIAN_API_TOKEN"
        token = os.environ.get(env_name, "")
        if not token:
            return None, f"no API token in ${env_name}; skipping Atlassian discovery"
        return token, None
    if provider == "slack":
        env_name = block.get("token_env") or "SLACK_BOT_TOKEN"
        token = os.environ.get(env_name, "") or os.environ.get("SLACK_TOKEN", "")
        if not token:
            return None, f"no Slack token in ${env_name} (or $SLACK_TOKEN)"
        return token, None
    if provider == "auth0":
        ready_env = block.get("token_env") or "AUTH0_MGMT_TOKEN"
        ready = os.environ.get(ready_env, "")
        if ready:
            return ready, None
        cid_env = block.get("client_id_env") or "AUTH0_CLIENT_ID"
        sec_env = block.get("client_secret_env") or "AUTH0_CLIENT_SECRET"
        client_id = os.environ.get(cid_env, "")
        client_secret = os.environ.get(sec_env, "")
        if not client_id or not client_secret:
            return None, (
                f"no Auth0 token in ${ready_env} and no client credentials in "
                f"${cid_env} / ${sec_env}"
            )
        audience = block.get("audience")
        return mint_auth0_token(transport, base, client_id, client_secret, audience)
    env_name = block.get("token_env") or "OKTA_API_TOKEN"
    token = os.environ.get(env_name, "")
    if not token:
        return None, f"no API token in ${env_name}; skipping live IdP discovery"
    return token, None


def discover_from_vendor(
    vendor: dict[str, Any],
    cfg: RunConfig,
    *,
    transport: Transport | None = None,
) -> tuple[IdPEstate | None, str | None]:
    """Live (or injected-transport) discovery from a vendor ``probe:`` block."""
    block = vendor.get("probe") or {}
    base = (block.get("base_url") or block.get("domain") or "").rstrip("/")
    provider = infer_provider(block, base_url=base)
    if not base:
        return None, "probe block has no base_url / domain"
    if cfg.offline and transport is None:
        return None, "offline mode: skipped live IdP discovery"
    bus = transport or LiveTransport()
    token, err = _live_token(block, provider, bus, base)
    if err:
        return None, err
    options = _block_options(block)
    estate = discover_estate(
        provider=provider,
        base_url=base,
        transport=bus,
        token=token,
        **options,
    )
    if token and _contains_secret(estate.to_probe_blob(), token):
        return None, "refusing to return an estate that echoed the API token"
    if estate.error:
        return estate, estate.error
    return estate, None


def discover_from_recorded(
    recorded: dict[str, Any] | Path,
    vendor: dict[str, Any] | None = None,
) -> tuple[IdPEstate | None, str | None]:
    """Walk a recorded page set through the same parser as live."""
    if isinstance(recorded, Path):
        blob: dict[str, Any] = json.loads(recorded.read_text(encoding="utf-8"))
    else:
        blob = recorded
    transport, provider, base = load_recorded_transport(blob)
    block = (vendor or {}).get("probe") or {}
    if not provider or provider not in {"okta", "auth0"}:
        provider = infer_provider(block, base_url=base)
    if not base:
        base = (block.get("base_url") or block.get("domain") or "").rstrip("/")
    if not base:
        return None, "recorded page set has no base_url"
    options = _block_options(block)
    for key in ("page_limit", "max_pages", "max_grant_fetches", "fetch_grants", "fetch_tokens", "fetch_users", "org_id"):
        if key in blob:
            options[key] = blob[key]
    # Recorded sets do not need a real token; the walker still sends the header.
    token = "recorded"
    estate = discover_estate(
        provider=provider,
        base_url=base,
        transport=transport,
        token=token,
        **options,
    )
    if estate.error:
        return estate, estate.error
    return estate, None


def recorded_path(vendor: dict[str, Any], cfg: RunConfig) -> Path | None:
    block = vendor.get("probe") or {}
    raw = block.get("pages") or block.get("recorded")
    if not raw:
        return None
    path = Path(str(raw).replace("{version}", cfg.snapshot_version))
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path if path.exists() else None
