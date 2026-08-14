"""OS-keychain credentials for vendor connectors.

Secrets live in the platform keychain (macOS Keychain, Windows Credential
Locker, Linux Secret Service) via the ``keyring`` library. The CLI never
accepts a secret as an argument. Connectors fetch a field at the moment of
use and drop it when the request returns.

Service name: ``vra:<connector>`` / username: ``<field>``.
An index of *names only* is stored at ``vra:_index`` so ``creds list``
does not have to dump the keychain.

Env-var fallback is CI-only: ``--allow-env-creds``.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from contextlib import contextmanager
from typing import Any, Iterator

SERVICE_PREFIX = "vra"
INDEX_SERVICE = "vra:_index"
INDEX_USER = "connectors"

CONNECTORS: dict[str, dict[str, Any]] = {
    "okta": {
        "fields": ("api_token",),
        "env": {"api_token": ("OKTA_API_TOKEN", "AEGIS_API_TOKEN")},
        "opaque_admin": True,
    },
    "auth0": {
        "fields": ("client_id", "client_secret", "management_token"),
        "required": ("client_id", "client_secret"),
        "env": {
            "client_id": ("AUTH0_CLIENT_ID",),
            "client_secret": ("AUTH0_CLIENT_SECRET",),
            "management_token": ("AUTH0_MGMT_TOKEN",),
        },
        "opaque_admin": False,
    },
    "atlassian": {
        "fields": ("api_token",),
        "env": {"api_token": ("ATLASSIAN_API_TOKEN",)},
        "opaque_admin": True,
    },
    "slack": {
        "fields": ("bot_token",),
        "env": {"bot_token": ("SLACK_BOT_TOKEN", "SLACK_TOKEN")},
        "opaque_admin": False,
    },
}

WRITE_SCOPE_MARKERS = ("manage", "write", "revoke", "delete", "create", "update", "admin")


class MemoryKeyring:
    """In-process keyring for tests. Never used as a production store."""

    priority = 1

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self._store.pop((service, username), None)


_TEST_BACKEND: MemoryKeyring | None = None


def use_memory_keyring(backend: MemoryKeyring | None = None) -> MemoryKeyring:
    """Install an in-process keyring. Tests only."""
    global _TEST_BACKEND
    _TEST_BACKEND = backend or MemoryKeyring()
    return _TEST_BACKEND


def reset_memory_keyring() -> None:
    global _TEST_BACKEND
    _TEST_BACKEND = None


def _backend():
    if _TEST_BACKEND is not None:
        return _TEST_BACKEND
    import keyring

    return keyring.get_keyring()


def service_name(connector: str) -> str:
    return f"{SERVICE_PREFIX}:{connector}"


def _load_index() -> dict[str, list[str]]:
    try:
        raw = _backend().get_password(INDEX_SERVICE, INDEX_USER)
    except Exception:
        return {}
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): [str(x) for x in (v or [])] for k, v in data.items()}


def _save_index(index: dict[str, list[str]]) -> None:
    _backend().set_password(INDEX_SERVICE, INDEX_USER, json.dumps(index, sort_keys=True))


def set_secret(connector: str, field: str, value: str) -> None:
    connector = _norm_connector(connector)
    field = field.strip()
    if not value:
        raise ValueError(f"{connector}:{field} is empty")
    _backend().set_password(service_name(connector), field, value)
    index = _load_index()
    fields = list(index.get(connector) or [])
    if field not in fields:
        fields.append(field)
        index[connector] = sorted(fields)
        _save_index(index)


def get_secret(connector: str, field: str) -> str | None:
    connector = _norm_connector(connector)
    try:
        return _backend().get_password(service_name(connector), field)
    except Exception:
        return None


def delete_connector(connector: str) -> list[str]:
    connector = _norm_connector(connector)
    index = _load_index()
    fields = list(index.get(connector) or CONNECTORS.get(connector, {}).get("fields") or [])
    removed: list[str] = []
    for field in fields:
        try:
            _backend().delete_password(service_name(connector), field)
            removed.append(field)
        except Exception:
            if get_secret(connector, field) is None:
                continue
            raise
    index.pop(connector, None)
    _save_index(index)
    return removed


def listed_connectors() -> dict[str, list[str]]:
    """Names of stored fields. Never values."""
    return _load_index()


def _norm_connector(name: str) -> str:
    key = (name or "").strip().lower()
    if key not in CONNECTORS:
        raise ValueError(f"unknown connector {name!r}; choose {', '.join(sorted(CONNECTORS))}")
    return key


@contextmanager
def secret_field(connector: str, field: str) -> Iterator[str | None]:
    """Yield a secret and wipe the local binding on the way out."""
    value = get_secret(connector, field)
    try:
        yield value
    finally:
        value = None


def resolve_secrets(
    connector: str,
    *,
    allow_env: bool = False,
    env_map: dict[str, tuple[str, ...]] | None = None,
) -> tuple[dict[str, str], str | None, bool]:
    """Fetch connector secrets. Returns (secrets, error, used_env).

    Callers must drop the dict after the request.
    """
    connector = _norm_connector(connector)
    spec = CONNECTORS[connector]
    fields: tuple[str, ...] = spec["fields"]
    required: tuple[str, ...] = spec.get("required") or fields[:1]
    merged: dict[str, tuple[str, ...]] = dict(spec.get("env") or {})
    if env_map:
        for key, names in env_map.items():
            merged[key] = tuple(n for n in names if n) + tuple(merged.get(key) or ())
    env_map = merged
    out: dict[str, str] = {}
    used_env = False
    for field in fields:
        value = get_secret(connector, field)
        if not value and allow_env:
            for env_name in env_map.get(field, ()):
                value = os.environ.get(env_name, "")
                if value:
                    used_env = True
                    break
        if value:
            out[field] = value
    missing = [f for f in required if not out.get(f)]
    if missing and connector == "auth0" and out.get("management_token"):
        missing = []
    if missing:
        return {}, (
            f"no keychain secret for {connector} ({', '.join(missing)}). "
            f"Run: python3 vra.py creds set {connector}"
        ), used_env
    return out, None, used_env


def is_write_scope(scope: str) -> bool:
    return any(marker in scope.lower() for marker in WRITE_SCOPE_MARKERS)


def jwt_scopes(token: str) -> list[str]:
    """Decode a JWT payload without verifying. Returns [] if not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception:
        return []
    raw = claims.get("scope") or claims.get("scp") or claims.get("permissions") or []
    if isinstance(raw, str):
        return [s for s in raw.replace(",", " ").split() if s]
    if isinstance(raw, list):
        return [str(s) for s in raw if s]
    return []


def inspect_scopes(connector: str, secrets: dict[str, str]) -> dict[str, Any]:
    """Look at the credential itself. Does not invent grants."""
    connector = _norm_connector(connector)
    spec = CONNECTORS[connector]
    token = (
        secrets.get("api_token")
        or secrets.get("bot_token")
        or secrets.get("management_token")
        or secrets.get("client_secret")
        or ""
    )
    scopes = jwt_scopes(token)
    if connector == "slack" and token.startswith("xoxp-"):
        scopes = sorted(set(scopes + ["user_token"]))
    writes = sorted({s for s in scopes if is_write_scope(s)})
    opaque = bool(spec.get("opaque_admin")) and not scopes
    warning = None
    if writes:
        warning = (
            "WARNING: this credential carries write scope(s): "
            + ", ".join(writes)
            + ". This is a compliance monitor — use a read-only token."
        )
    elif opaque:
        warning = (
            "WARNING: this looks like a full-privilege admin token "
            f"({connector}). This is a compliance monitor — prefer a "
            "read-only / scoped credential."
        )
    return {
        "connector": connector,
        "scopes": scopes,
        "write_scopes": writes,
        "opaque_admin": opaque,
        "warning": warning,
    }


def verify_readonly(
    connector: str,
    secrets: dict[str, str],
    *,
    base_url: str | None = None,
    transport=None,
) -> tuple[bool, str]:
    """One read-only call so `creds test` can say the token works."""
    from .idp import LiveTransport, _exchange

    bus = transport or LiveTransport()
    connector = _norm_connector(connector)
    if connector == "okta":
        base = (base_url or os.environ.get("OKTA_BASE_URL") or "").rstrip("/")
        if not base:
            return False, "pass --base-url https://your-org.okta.com"
        token = secrets.get("api_token") or ""
        status, body, _ = _exchange(
            bus, "GET", f"{base}/api/v1/org",
            headers={"Authorization": f"SSWS {token}", "Accept": "application/json"},
        )
        if status < 400:
            return True, f"okta org reachable ({status})"
        return False, f"okta /api/v1/org returned {status}"
    if connector == "auth0":
        domain = (base_url or os.environ.get("AUTH0_DOMAIN") or "").rstrip("/")
        if not domain:
            return False, "pass --base-url https://your-tenant.us.auth0.com"
        from .idp import _auth0_base, mint_auth0_token, _auth0_headers

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
    if connector == "atlassian":
        token = secrets.get("api_token") or ""
        status, _, _ = _exchange(
            bus, "GET", "https://api.atlassian.com/admin/v1/orgs",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if status < 400:
            return True, f"atlassian orgs reachable ({status})"
        return False, f"atlassian /admin/v1/orgs returned {status}"
    if connector == "slack":
        token = secrets.get("bot_token") or ""
        status, body, _ = _exchange(
            bus, "GET", "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        ok = status < 400 and isinstance(body, dict) and body.get("ok") is True
        if ok:
            return True, f"slack auth.test ok (team={body.get('team')})"
        err = (body or {}).get("error") if isinstance(body, dict) else status
        return False, f"slack auth.test failed: {err}"
    return False, f"no probe for {connector}"


def env_fallback_names(connector: str) -> list[str]:
    spec = CONNECTORS[_norm_connector(connector)]
    names: list[str] = []
    for group in (spec.get("env") or {}).values():
        names.extend(group)
    return names


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra creds",
        description="Store vendor API credentials in the OS keychain. Secrets are never CLI args.",
    )
    sub = p.add_subparsers(dest="action", required=True)
    set_p = sub.add_parser("set", help="prompt for secrets and write them to the keychain")
    set_p.add_argument("connector", choices=sorted(CONNECTORS))
    set_p.add_argument("--field", action="append", default=[], dest="fields",
                       help="only this field (repeatable). Default: the connector's required fields")
    sub.add_parser("list", help="show which connectors have credentials (names only)")
    rm_p = sub.add_parser("rm", help="delete a connector's secrets from the keychain")
    rm_p.add_argument("connector", choices=sorted(CONNECTORS))
    test_p = sub.add_parser("test", help="read-only ping + write-scope warning")
    test_p.add_argument("connector", choices=sorted(CONNECTORS))
    test_p.add_argument("--base-url", default=None)
    test_p.add_argument("--allow-env-creds", action="store_true")
    return p


def _prompt_fields(connector: str, fields: list[str]) -> None:
    print(f"vra creds: storing {connector} in the OS keychain (input is hidden)")
    for field in fields:
        value = getpass.getpass(f"  {connector}:{field}: ")
        set_secret(connector, field, value)
        print(f"  stored vra:{connector}:{field}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == "list":
            index = listed_connectors()
            if not index:
                print("vra creds: no connectors stored")
                return 0
            print(f"{'Connector':<16} Fields")
            print("-" * 40)
            for name, fields in sorted(index.items()):
                print(f"{name:<16} {', '.join(fields)}")
            return 0
        if args.action == "rm":
            removed = delete_connector(args.connector)
            print(f"vra creds: removed {args.connector} ({', '.join(removed) or 'nothing stored'})")
            return 0
        if args.action == "set":
            spec = CONNECTORS[args.connector]
            fields = args.fields or list(spec.get("required") or spec["fields"])
            unknown = [f for f in fields if f not in spec["fields"]]
            if unknown:
                print(f"vra creds: unknown field(s) {unknown} for {args.connector}", file=sys.stderr)
                return 2
            _prompt_fields(args.connector, fields)
            secrets, err, _ = resolve_secrets(args.connector)
            if err:
                print(f"vra creds: {err}", file=sys.stderr)
                return 2
            info = inspect_scopes(args.connector, secrets)
            if info.get("warning"):
                print(info["warning"], file=sys.stderr)
            secrets.clear()
            return 0
        if args.action == "test":
            secrets, err, used_env = resolve_secrets(
                args.connector, allow_env=args.allow_env_creds
            )
            if err:
                print(f"vra creds: {err}", file=sys.stderr)
                return 2
            if used_env:
                print(
                    "vra creds: WARNING using environment variables "
                    "(--allow-env-creds). Prefer `vra.py creds set`.",
                    file=sys.stderr,
                )
            info = inspect_scopes(args.connector, secrets)
            ok, detail = verify_readonly(
                args.connector, secrets, base_url=args.base_url
            )
            secrets.clear()
            print(f"  connector : {args.connector}")
            print(f"  reachable : {'yes' if ok else 'no'} — {detail}")
            print(f"  scopes    : {', '.join(info['scopes']) or '(none visible on the credential)'}")
            if info.get("warning"):
                print(info["warning"], file=sys.stderr)
            return 0 if ok else 2
    except ValueError as exc:
        print(f"vra creds: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"vra creds: keychain error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
