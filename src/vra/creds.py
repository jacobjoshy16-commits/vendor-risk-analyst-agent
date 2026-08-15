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
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SERVICE_PREFIX = "vra"
INDEX_SERVICE = "vra:_index"
INDEX_USER = "connectors"

# Last-resort store when the OS has no keychain (headless Linux, this sandbox).
# Override in tests with VRA_KEYRING_FILE. Never commit this file.
_DEFAULT_FILE = Path.home() / ".local/share/vra/keyring.json"

def connector_catalog() -> dict[str, dict[str, Any]]:
    """Live view of registered connectors. Generated from the registry."""
    from .registry import creds_catalog

    return creds_catalog()


# Kept as a name tests / older callers may import. Always rebuilt.
def _connectors() -> dict[str, dict[str, Any]]:
    return connector_catalog()

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
_ACTIVE_BACKEND: Any = None
_FALLBACK_WARNED = False


class FileKeyring:
    """chmod-0600 JSON file. Used only when the OS keychain is missing.

    Survives a shell restart. Not an in-process vault and not an env var.
    On macOS / Windows / a Linux desktop with Secret Service this class
    is never selected.
    """

    def __init__(self, path: Path | None = None) -> None:
        raw = path or os.environ.get("VRA_KEYRING_FILE") or _DEFAULT_FILE
        self.path = Path(raw)
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, str]]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        out: dict[str, dict[str, str]] = {}
        for service, bucket in data.items():
            if isinstance(bucket, dict):
                out[str(service)] = {str(k): str(v) for k, v in bucket.items()}
        return out

    def _dump(self, data: dict[str, dict[str, str]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        os.chmod(self.path, 0o600)

    def get_password(self, service: str, username: str) -> str | None:
        with self._lock:
            return (self._load().get(service) or {}).get(username)

    def set_password(self, service: str, username: str, password: str) -> None:
        with self._lock:
            data = self._load()
            data.setdefault(service, {})[username] = password
            self._dump(data)

    def delete_password(self, service: str, username: str) -> None:
        with self._lock:
            data = self._load()
            bucket = data.get(service) or {}
            bucket.pop(username, None)
            if bucket:
                data[service] = bucket
            else:
                data.pop(service, None)
            self._dump(data)


def use_memory_keyring(backend: MemoryKeyring | None = None) -> MemoryKeyring:
    """Install an in-process keyring. Tests only."""
    global _TEST_BACKEND, _ACTIVE_BACKEND
    _TEST_BACKEND = backend or MemoryKeyring()
    _ACTIVE_BACKEND = None
    return _TEST_BACKEND


def reset_memory_keyring() -> None:
    global _TEST_BACKEND, _ACTIVE_BACKEND, _FALLBACK_WARNED
    _TEST_BACKEND = None
    _ACTIVE_BACKEND = None
    _FALLBACK_WARNED = False


def _os_backend_usable(kr: Any) -> bool:
    module = type(kr).__module__
    if module.startswith("keyring.backends.fail") or module.startswith("keyring.backends.null"):
        return False
    try:
        kr.set_password("vra:_probe", "_", "x")
        kr.delete_password("vra:_probe", "_")
    except Exception:
        return False
    return True


def _warn_fallback(path: Path) -> None:
    global _FALLBACK_WARNED
    if _FALLBACK_WARNED:
        return
    _FALLBACK_WARNED = True
    print(
        "vra creds: no OS keychain on this machine "
        "(macOS Keychain / Windows Credential Locker / Linux Secret Service).\n"
        f"  Tokens will live in {path} (mode 0600) so they survive a restart.\n"
        "  On a normal desktop they go in the OS keychain instead.",
        file=sys.stderr,
    )


def _choose_backend():
    import keyring

    try:
        kr = keyring.get_keyring()
    except Exception:
        kr = None
    if kr is not None and _os_backend_usable(kr):
        return kr
    fallback = FileKeyring()
    _warn_fallback(fallback.path)
    return fallback


def _backend():
    global _ACTIVE_BACKEND
    if _TEST_BACKEND is not None:
        return _TEST_BACKEND
    if _ACTIVE_BACKEND is None:
        _ACTIVE_BACKEND = _choose_backend()
    return _ACTIVE_BACKEND


def backend_info() -> str:
    """Where tokens actually live. Never includes values."""
    b = _backend()
    if isinstance(b, MemoryKeyring):
        return "memory (tests)"
    if isinstance(b, FileKeyring):
        return f"file ({b.path})"
    return f"os-keychain ({type(b).__module__}.{type(b).__name__})"


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
    try:
        _backend().set_password(service_name(connector), field, value)
    except Exception as exc:
        raise RuntimeError(
            f"could not store {connector}:{field} in {backend_info()}: {exc}"
        ) from exc
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
    fields = list(index.get(connector) or connector_catalog().get(connector, {}).get("fields") or [])
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
    catalog = connector_catalog()
    if key not in catalog:
        raise ValueError(f"unknown connector {name!r}; choose {', '.join(sorted(catalog))}")
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
    spec = connector_catalog()[connector]
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
    spec = connector_catalog()[connector]
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
    from .registry import ping

    connector = _norm_connector(connector)
    return ping(connector, secrets, base_url=base_url, transport=transport)


def env_fallback_names(connector: str) -> list[str]:
    spec = connector_catalog()[_norm_connector(connector)]
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
    set_p.add_argument("connector", choices=sorted(connector_catalog()))
    set_p.add_argument("--field", action="append", default=[], dest="fields",
                       help="only this field (repeatable). Default: the connector's required fields")
    sub.add_parser("list", help="show which connectors have credentials (names only)")
    rm_p = sub.add_parser("rm", help="delete a connector's secrets from the keychain")
    rm_p.add_argument("connector", choices=sorted(connector_catalog()))
    test_p = sub.add_parser("test", help="read-only ping + write-scope warning")
    test_p.add_argument("connector", choices=sorted(connector_catalog()))
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
            print(f"vra creds: backend = {backend_info()}")
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
            spec = connector_catalog()[args.connector]
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
