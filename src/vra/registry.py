"""Connector registry — manifests drive the CLI, not a hardcoded vendor list.

A connector is:

    manifest  (id, display name, auth, fields, pagination, list method)
    + list_nhis()   pull every non-human identity the vendor actually returns
    + optional ping() for ``creds test``

Adding a vendor is registering a manifest. ``connect``, ``creds``, and
``discover`` build their menus from whatever is registered. Protocol
connectors (oidc_apps, scim, generic_rest) cover a class of APIs; native
connectors cover one product.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from .idp import IdPEstate, Transport

ListNhis = Callable[..., IdPEstate]
PingFn = Callable[..., tuple[bool, str]]


@dataclass
class ConnectorManifest:
    id: str
    display_name: str
    auth: str
    fields: tuple[str, ...]
    pagination: str
    list_method: str
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    env: dict[str, tuple[str, ...]] = field(default_factory=dict)
    category: str = "other"
    url_required: bool = True
    url_prompt: str = "Base URL?"
    url_hint: str = ""
    default_url: str = ""
    opaque_admin: bool = False
    field_prompts: dict[str, str] = field(default_factory=dict)
    protocol: str | None = None
    flavor: str | None = None
    url_hosts: tuple[str, ...] = ()
    show_in_menu: bool = True
    kind: str = "native"  # protocol | native | alias

    def __post_init__(self) -> None:
        if not self.required:
            object.__setattr__(self, "required", self.fields[:1] if self.fields else ())

    def as_creds(self) -> dict[str, Any]:
        return {
            "fields": self.fields,
            "required": self.required,
            "env": dict(self.env),
            "opaque_admin": self.opaque_admin,
        }

    def as_connect(self) -> dict[str, Any]:
        return {
            "label": self.display_name,
            "category": self.category,
            "url_prompt": self.url_prompt,
            "url_hint": self.url_hint or self.default_url,
            "url_required": self.url_required,
            "default_url": self.default_url or None,
            "fields": self.fields,
            "optional_fields": self.optional,
            "field_prompts": dict(self.field_prompts),
            "protocol": self.protocol,
            "flavor": self.flavor,
        }


_MANIFESTS: dict[str, ConnectorManifest] = {}
_LISTERS: dict[str, ListNhis] = {}
_PINGS: dict[str, PingFn] = {}
_READY = False


def register(
    manifest: ConnectorManifest,
    *,
    list_nhis: ListNhis | None = None,
    ping: PingFn | None = None,
) -> ConnectorManifest:
    """Register (or replace) a connector. Idempotent on the same id."""
    _MANIFESTS[manifest.id] = manifest
    if list_nhis is not None:
        _LISTERS[manifest.id] = list_nhis
    if ping is not None:
        _PINGS[manifest.id] = ping
    return manifest


def _ensure() -> None:
    global _READY
    if _READY:
        return
    _READY = True
    from . import connectors as _connectors
    from . import natives as _natives
    from . import protocol as _protocol

    _protocol.register_all()
    _natives.register_all()
    _connectors.register_all()


def all_manifests(*, menu: bool = False) -> list[ConnectorManifest]:
    _ensure()
    rows = list(_MANIFESTS.values())
    if menu:
        rows = [m for m in rows if m.show_in_menu]
    return sorted(rows, key=lambda m: m.id)


def known_ids() -> set[str]:
    _ensure()
    return set(_MANIFESTS)


def get_manifest(connector_id: str) -> ConnectorManifest:
    _ensure()
    key = (connector_id or "").strip().lower()
    if key not in _MANIFESTS:
        raise ValueError(
            f"unknown connector {connector_id!r}; choose {', '.join(sorted(_MANIFESTS))}"
        )
    return _MANIFESTS[key]


def creds_catalog() -> dict[str, dict[str, Any]]:
    return {m.id: m.as_creds() for m in all_manifests()}


def connect_catalog() -> dict[str, dict[str, Any]]:
    return {m.id: m.as_connect() for m in all_manifests(menu=True)}


def menu_ids() -> list[str]:
    return [m.id for m in all_manifests(menu=True)]


def infer_from_url(url: str) -> str | None:
    """Return a connector id from a hostname, or None."""
    _ensure()
    host = (urlparse(url).netloc or url).lower()
    blob = (url or "").lower()
    for manifest in _MANIFESTS.values():
        for hint in manifest.url_hosts:
            if hint and (hint in host or hint in blob):
                return manifest.id
    return None


def list_nhis(
    connector_id: str,
    *,
    base_url: str,
    token: str | None,
    transport: Transport,
    **kwargs: Any,
) -> IdPEstate:
    """Dispatch to the registered list_nhis. Does not invent identities."""
    _ensure()
    key = (connector_id or "").strip().lower()
    fn = _LISTERS.get(key)
    if fn is None:
        estate = IdPEstate(provider=key or "unknown", base_url=base_url or "")
        estate.error = f"no list_nhis registered for {key!r}"
        return estate
    return fn(
        base_url=base_url,
        token=token,
        transport=transport,
        **kwargs,
    )


def ping(
    connector_id: str,
    secrets: dict[str, str],
    *,
    base_url: str | None = None,
    transport: Transport | None = None,
) -> tuple[bool, str]:
    _ensure()
    fn = _PINGS.get((connector_id or "").strip().lower())
    if fn is None:
        return False, f"no probe for {connector_id}"
    return fn(secrets, base_url=base_url, transport=transport)
