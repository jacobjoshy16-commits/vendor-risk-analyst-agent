"""Native product connectors — documented APIs only.

    github             GET /orgs/{org}/installations  (GitHub Apps)
    google_workspace   GET Admin SDK users?query=email:*gserviceaccount.com
    aws_iam            IAM ListUsers + ListRoles (SigV4; unsigned for fixtures)

Atlassian and Slack stay in ``connectors.py`` and register themselves.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlparse
from xml.etree import ElementTree as ET

from .idp import (
    DEFAULT_MAX_PAGES,
    USER_AGENT,
    IdPEstate,
    Transport,
    _exchange,
    next_link,
)
from .registry import ConnectorManifest, register


def _bearer(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }


# ---------------------------------------------------------------------------
# GitHub — GET /orgs/{org}/installations  (Link pages)
# ---------------------------------------------------------------------------
def discover_github(
    *,
    base_url: str,
    token: str | None,
    transport: Transport,
    org_id: str | None = None,
    page_limit: int = 100,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    org = org_id or _github_org(base_url)
    api = "https://api.github.com"
    parsed = urlparse(base_url or "")
    if parsed.netloc and "github.com" not in parsed.netloc and "api.github.com" not in parsed.netloc:
        # Enterprise: https://github.example.com → https://github.example.com/api/v3
        api = f"{parsed.scheme or 'https'}://{parsed.netloc}/api/v3"
    elif parsed.netloc == "api.github.com":
        api = "https://api.github.com"
    estate = IdPEstate(provider="github", base_url=api, org={"login": org} if org else {})
    if not org:
        estate.error = "github needs an org in the URL (https://github.com/acme) or probe.org_id"
        return estate
    if not token:
        estate.error = "no GitHub token"
        return estate
    headers = {
        **_bearer(token),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    items: list[Any] = []
    url = f"{api}/orgs/{org}/installations"
    query: dict[str, Any] | None = {"per_page": page_limit}
    pages = 0
    while url and pages < max_pages:
        status, body, resp = _exchange(transport, "GET", url, headers=headers, params=query)
        estate.requests_made += 1
        if status >= 400:
            if pages == 0:
                estate.error = f"github installations returned {status}"
                return estate
            estate.warnings.append(f"GET {url} returned {status}")
            break
        if isinstance(body, dict) and isinstance(body.get("installations"), list):
            chunk = body["installations"]
        elif isinstance(body, list):
            chunk = body
        else:
            chunk = []
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        url = next_link(resp, base=api)
        query = None
        if not chunk and not url:
            break
    if url:
        estate.truncated = True
    estate.applications = [_normalise_github_install(i) for i in items]
    return estate


def _github_org(url: str) -> str | None:
    parsed = urlparse(url or "")
    parts = [p for p in parsed.path.split("/") if p]
    if parsed.netloc in {"github.com", "www.github.com", "api.github.com"} and parts:
        if parts[0] == "orgs" and len(parts) > 1:
            return parts[1]
        if parts[0] != "api":
            return parts[0]
    if "orgs" in parts:
        idx = parts.index("orgs")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _normalise_github_install(inst: dict[str, Any]) -> dict[str, Any]:
    app = inst.get("app_slug") or (inst.get("app_id") and f"app-{inst.get('app_id')}")
    return {
        "id": inst.get("id") or inst.get("app_id"),
        "client_id": inst.get("app_id") or inst.get("id"),
        "label": inst.get("app_slug") or app or inst.get("id"),
        "status": "ACTIVE" if (inst.get("suspended_at") in (None, "")) else "INACTIVE",
        "signOnMode": "GITHUB_APP",
        "app_type": "github_app",
        "created": inst.get("created_at"),
        "idp": "github",
        "discovered_via": "github_installations",
    }


def _ping_github(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport

    bus = transport or LiveTransport()
    org = _github_org(base_url or "") or os.environ.get("GITHUB_ORG") or ""
    token = secrets.get("api_token") or ""
    if not org:
        return False, "pass --base-url https://github.com/<org>"
    status, _, _ = _exchange(
        bus, "GET", f"https://api.github.com/orgs/{org}",
        headers={**_bearer(token), "Accept": "application/vnd.github+json"},
    )
    if status < 400:
        return True, f"github org {org} reachable ({status})"
    return False, f"github /orgs/{org} returned {status}"


# ---------------------------------------------------------------------------
# Google Workspace — Admin SDK Directory
#   GET /admin/directory/v1/users?customer=my_customer
#                &query=email:*gserviceaccount.com
# ---------------------------------------------------------------------------
def discover_google_workspace(
    *,
    base_url: str,
    token: str | None,
    transport: Transport,
    page_limit: int = 100,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    base = (base_url or "https://admin.googleapis.com").rstrip("/")
    if "googleapis.com" not in urlparse(base).netloc:
        base = "https://admin.googleapis.com"
    estate = IdPEstate(provider="google_workspace", base_url=base)
    if not token:
        estate.error = "no Google access token"
        return estate
    headers = _bearer(token)
    items: list[Any] = []
    page_token = None
    pages = 0
    url = f"{base}/admin/directory/v1/users"
    while pages < max_pages:
        params: dict[str, Any] = {
            "customer": "my_customer",
            "query": "email:*gserviceaccount.com",
            "maxResults": page_limit,
        }
        if page_token:
            params["pageToken"] = page_token
        status, body, _ = _exchange(transport, "GET", url, headers=headers, params=params)
        estate.requests_made += 1
        if status >= 400:
            if pages == 0:
                estate.error = f"google directory users returned {status}"
                return estate
            estate.warnings.append(f"directory users returned {status}")
            break
        blob = body if isinstance(body, dict) else {}
        chunk = blob.get("users") or []
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        page_token = blob.get("nextPageToken")
        if not page_token or not chunk:
            break
    if page_token:
        estate.truncated = True
    estate.service_accounts = [_normalise_google_user(u) for u in items]
    return estate


def _normalise_google_user(user: dict[str, Any]) -> dict[str, Any]:
    email = user.get("primaryEmail") or user.get("id")
    return {
        "id": user.get("id") or email,
        "name": user.get("name", {}).get("fullName") if isinstance(user.get("name"), dict) else email,
        "status": "INACTIVE" if user.get("suspended") else "ACTIVE",
        "created": user.get("creationTime"),
        "userType": "service_account",
        "idp": "google_workspace",
        "discovered_via": "google_directory_service_accounts",
    }


def _ping_google(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport

    bus = transport or LiveTransport()
    token = secrets.get("api_token") or ""
    status, _, _ = _exchange(
        bus, "GET", "https://admin.googleapis.com/admin/directory/v1/users",
        headers=_bearer(token),
        params={"customer": "my_customer", "maxResults": 1, "query": "email:*gserviceaccount.com"},
    )
    if status < 400:
        return True, f"google directory reachable ({status})"
    return False, f"google directory returned {status}"


# ---------------------------------------------------------------------------
# AWS IAM — ListUsers + ListRoles. SigV4 when a secret is present.
# Fixtures / token=recorded skip the signature so MemoryTransport matches.
# ---------------------------------------------------------------------------
def discover_aws_iam(
    *,
    base_url: str,
    token: str | None,
    transport: Transport,
    page_limit: int = 100,
    max_pages: int = DEFAULT_MAX_PAGES,
    **_kwargs: Any,
) -> IdPEstate:
    endpoint = (base_url or "https://iam.amazonaws.com").rstrip("/")
    estate = IdPEstate(provider="aws_iam", base_url=endpoint)
    access_key = token or ""
    secret_key = ""
    if access_key and access_key != "recorded":
        from .creds import resolve_secrets

        secrets, _, _ = resolve_secrets("aws_iam", allow_env=True)
        access_key = secrets.get("access_key_id") or access_key
        secret_key = secrets.get("secret_access_key") or ""
        secrets.clear()
    users = _iam_list(
        transport, estate, endpoint, "ListUsers", "Users", "User",
        access_key, secret_key, page_limit, max_pages, marker_in="Marker",
    )
    if estate.error:
        return estate
    roles = _iam_list(
        transport, estate, endpoint, "ListRoles", "Roles", "Role",
        access_key, secret_key, page_limit, max_pages, marker_in="Marker",
    )
    estate.service_accounts = (
        [_normalise_aws_user(u) for u in users]
        + [_normalise_aws_role(r) for r in roles]
    )
    return estate


def _iam_list(
    transport: Transport,
    estate: IdPEstate,
    endpoint: str,
    action: str,
    wrapper: str,
    item_tag: str,
    access_key: str,
    secret_key: str,
    page_limit: int,
    max_pages: int,
    marker_in: str,
) -> list[dict]:
    items: list[dict] = []
    marker = None
    pages = 0
    while pages < max_pages:
        params = {
            "Action": action,
            "Version": "2010-05-08",
            "MaxItems": str(page_limit),
        }
        if marker:
            params[marker_in] = marker
        url = endpoint + "/"
        headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
        if secret_key and access_key and access_key != "recorded":
            headers.update(_sigv4_headers("GET", url, params, access_key, secret_key))
        status, body, _ = _exchange(transport, "GET", url, headers=headers, params=params)
        estate.requests_made += 1
        if status >= 400:
            if pages == 0 and action == "ListUsers":
                estate.error = f"aws {action} returned {status}"
            else:
                estate.warnings.append(f"aws {action} returned {status}")
            break
        chunk, marker = _parse_iam_body(body, wrapper, item_tag)
        items.extend(chunk)
        pages += 1
        estate.pages_fetched += 1
        if not marker or not chunk:
            break
    if marker:
        estate.truncated = True
    return items


def _parse_iam_body(body: Any, wrapper: str, item_tag: str) -> tuple[list[dict], str | None]:
    if isinstance(body, dict) and body.get("_xml"):
        return _parse_iam_xml(str(body["_xml"]), wrapper, item_tag)
    if isinstance(body, dict):
        # JSON fixture shapes: {Users: [...]} or {ListUsersResponse: {ListUsersResult: {Users: [...]}}}
        if isinstance(body.get(wrapper), list):
            marker = body.get("Marker") or body.get("IsTruncated") and body.get("Marker")
            if body.get("IsTruncated") in (True, "true") and body.get("Marker"):
                marker = body.get("Marker")
            else:
                marker = body.get("Marker") if body.get("IsTruncated") else None
            return list(body[wrapper]), marker if isinstance(marker, str) else None
        for key in body:
            inner = body[key]
            if isinstance(inner, dict):
                found, marker = _parse_iam_body(inner, wrapper, item_tag)
                if found or marker:
                    return found, marker
        if isinstance(body.get(item_tag), list):
            return list(body[item_tag]), None
    if isinstance(body, list):
        return list(body), None
    if isinstance(body, str) and body.lstrip().startswith("<"):
        return _parse_iam_xml(body, wrapper, item_tag)
    return [], None


def _parse_iam_xml(text: str, wrapper: str, item_tag: str) -> tuple[list[dict], str | None]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [], None
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def local(tag: str) -> str:
        return tag.split("}")[-1]

    rows: list[dict] = []
    marker = None
    truncated = False
    for el in root.iter():
        name = local(el.tag)
        if name == item_tag:
            row = {local(child.tag): (child.text or "") for child in list(el)}
            if row:
                rows.append(row)
        elif name == "Marker" and el.text:
            marker = el.text
        elif name == "IsTruncated" and (el.text or "").lower() == "true":
            truncated = True
    if not truncated:
        marker = None
    _ = wrapper
    _ = ns
    return rows, marker


def _normalise_aws_user(user: dict[str, Any]) -> dict[str, Any]:
    uid = user.get("UserId") or user.get("UserName")
    return {
        "id": uid,
        "name": user.get("UserName") or uid,
        "status": "ACTIVE",
        "created": user.get("CreateDate"),
        "userType": "iam_user",
        "idp": "aws_iam",
        "discovered_via": "aws_list_users",
    }


def _normalise_aws_role(role: dict[str, Any]) -> dict[str, Any]:
    rid = role.get("RoleId") or role.get("RoleName")
    return {
        "id": rid,
        "name": role.get("RoleName") or rid,
        "status": "ACTIVE",
        "created": role.get("CreateDate"),
        "userType": "iam_role",
        "idp": "aws_iam",
        "discovered_via": "aws_list_roles",
    }


def _sigv4_headers(
    method: str,
    url: str,
    params: dict[str, str],
    access_key: str,
    secret_key: str,
    *,
    region: str = "us-east-1",
    service: str = "iam",
    now: datetime | None = None,
) -> dict[str, str]:
    """Minimal AWS SigV4 for IAM query requests. Never logs the secret."""
    stamped = now or datetime.now(timezone.utc)
    amz_date = stamped.strftime("%Y%m%dT%H%M%SZ")
    datestamp = stamped.strftime("%Y%m%d")
    parsed = urlparse(url)
    host = parsed.netloc or "iam.amazonaws.com"
    canonical_query = urlencode(sorted(params.items()))
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    canonical_request = "\n".join([
        method.upper(),
        parsed.path or "/",
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    credential_scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = hmac.new(k_date, region.encode("utf-8"), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode("utf-8"), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    auth = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return {"Authorization": auth, "X-Amz-Date": amz_date, "Host": host}


def _ping_aws(secrets: dict[str, str], *, base_url: str | None = None, transport=None) -> tuple[bool, str]:
    from .idp import LiveTransport

    bus = transport or LiveTransport()
    endpoint = (base_url or "https://iam.amazonaws.com").rstrip("/")
    params = {"Action": "ListUsers", "Version": "2010-05-08", "MaxItems": "1"}
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    access = secrets.get("access_key_id") or ""
    secret = secrets.get("secret_access_key") or ""
    if access and secret:
        headers.update(_sigv4_headers("GET", endpoint + "/", params, access, secret))
    status, _, _ = _exchange(bus, "GET", endpoint + "/", headers=headers, params=params)
    if status < 400:
        return True, f"aws iam ListUsers reachable ({status})"
    return False, f"aws iam ListUsers returned {status}"


def register_all() -> None:
    register(
        ConnectorManifest(
            id="github",
            display_name="GitHub",
            kind="native",
            auth="bearer",
            fields=("api_token",),
            pagination="link",
            list_method="GET /orgs/{org}/installations",
            category="development",
            url_prompt="Org URL?",
            url_hint="https://github.com/acme",
            url_hosts=("github.com",),
            env={"api_token": ("GITHUB_TOKEN", "GH_TOKEN")},
            field_prompts={"api_token": "Paste GitHub token (hidden)"},
        ),
        list_nhis=discover_github,
        ping=_ping_github,
    )
    register(
        ConnectorManifest(
            id="google_workspace",
            display_name="Google Workspace",
            kind="native",
            auth="bearer",
            fields=("api_token",),
            pagination="page_token",
            list_method="GET /admin/directory/v1/users?query=email:*gserviceaccount.com",
            category="identity_provider",
            url_prompt="Admin API URL? (optional)",
            url_hint="https://admin.googleapis.com",
            default_url="https://admin.googleapis.com",
            url_required=False,
            url_hosts=("googleapis.com", "google.com"),
            env={"api_token": ("GOOGLE_ACCESS_TOKEN",)},
            field_prompts={"api_token": "Paste Google access token (hidden)"},
        ),
        list_nhis=discover_google_workspace,
        ping=_ping_google,
    )
    register(
        ConnectorManifest(
            id="aws_iam",
            display_name="AWS IAM",
            kind="native",
            auth="aws_sigv4",
            fields=("access_key_id", "secret_access_key"),
            required=("access_key_id", "secret_access_key"),
            pagination="marker",
            list_method="IAM ListUsers + ListRoles",
            category="cloud",
            url_prompt="IAM endpoint? (optional)",
            url_hint="https://iam.amazonaws.com",
            default_url="https://iam.amazonaws.com",
            url_required=False,
            url_hosts=("amazonaws.com",),
            opaque_admin=True,
            env={
                "access_key_id": ("AWS_ACCESS_KEY_ID",),
                "secret_access_key": ("AWS_SECRET_ACCESS_KEY",),
            },
            field_prompts={
                "access_key_id": "Access key id (hidden)",
                "secret_access_key": "Secret access key (hidden)",
            },
        ),
        list_nhis=discover_aws_iam,
        ping=_ping_aws,
    )
