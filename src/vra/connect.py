"""Friendly front door: one command to attach a vendor.

Humans should not have to remember ``--provider okta --base-url …``.
``vra.py connect`` asks the three questions, stores the token in the OS
keychain, checks the connection, pulls the identities, and writes a
minimal ``vendors/{slug}.yaml`` stub so the monitor can pick the vendor
up on the next cycle.

The flag-based path stays underneath for scripts and CI — they cannot
answer prompts. This module is the human front door on top of
``creds`` + ``discover``.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import yaml

from .config import REPO_ROOT, VENDORS_DIR, RunConfig
from .creds import (
    get_secret,
    inspect_scopes,
    resolve_secrets,
    set_secret,
    verify_readonly,
)

PROVIDERS: dict[str, dict[str, Any]] = {
    "okta": {
        "label": "Okta",
        "category": "identity_provider",
        "url_prompt": "Org URL?",
        "url_hint": "https://acme.okta.com",
        "url_required": True,
        "default_url": None,
        "fields": ("api_token",),
        "field_prompts": {"api_token": "Paste API token (hidden)"},
    },
    "auth0": {
        "label": "Auth0",
        "category": "identity_provider",
        "url_prompt": "Tenant URL?",
        "url_hint": "https://acme.us.auth0.com",
        "url_required": True,
        "default_url": None,
        "fields": ("client_id", "client_secret"),
        "optional_fields": ("management_token",),
        "field_prompts": {
            "client_id": "Client ID (hidden)",
            "client_secret": "Client secret (hidden)",
        },
    },
    "slack": {
        "label": "Slack",
        "category": "collaboration",
        "url_prompt": "Workspace URL? (optional)",
        "url_hint": "https://acme.slack.com",
        "url_required": False,
        "default_url": "https://slack.com",
        "fields": ("bot_token",),
        "field_prompts": {"bot_token": "Paste bot token (hidden)"},
    },
    "atlassian": {
        "label": "Atlassian",
        "category": "collaboration",
        "url_prompt": "Admin API URL? (optional)",
        "url_hint": "https://api.atlassian.com",
        "url_required": False,
        "default_url": "https://api.atlassian.com",
        "fields": ("api_token",),
        "field_prompts": {"api_token": "Paste API token (hidden)"},
    },
}

STUB_NOTES = (
    "Minimal stub written by `vra connect`. NHI discovery and entitlement "
    "tracking work immediately. AIV-* feature scoring needs register fields "
    "this stub cannot invent — those show up as unknown gaps (21-day "
    "questions) until you fill them with `python3 vra.py enrich {slug}`."
)


InputFn = Callable[[str], str]
GetPassFn = Callable[[str], str]


@dataclass
class ConnectResult:
    provider: str
    slug: str
    vendor_name: str
    base_url: str
    register_path: Path | None = None
    stored: bool = False
    connection_ok: bool = False
    connection_detail: str = ""
    scope_warning: str | None = None
    discovered: int = 0
    identities: list[dict] = field(default_factory=list)
    created: bool = False
    updated: bool = False
    skipped_discover: bool = False
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False

    def lines(self) -> list[str]:
        bits: list[str] = []
        stored = "✓ stored in keychain" if self.stored else "· keychain unchanged"
        if self.connection_ok:
            conn = f"✓ connection ok"
        elif self.connection_detail:
            conn = f"✗ connection failed — {self.connection_detail}"
        else:
            conn = "· connection not checked"
        line = f"{stored}   {conn}"
        if self.scope_warning:
            short = self.scope_warning
            if short.startswith("WARNING: "):
                short = short[len("WARNING: "):]
            line += f"   ⚠ {short}"
        bits.append(line)
        if self.skipped_discover:
            bits.append("· discovery skipped")
        elif self.errors and self.discovered == 0 and not self.connection_ok:
            pass
        else:
            n = self.discovered
            noun = "identity" if n == 1 else "identities"
            bits.append(f"✓ discovered {n} {noun}",)
        if self.register_path:
            rel = _rel(self.register_path)
            if self.created:
                bits.append(f"✓ created {rel}")
            elif self.updated:
                bits.append(f"✓ updated {rel}")
            else:
                bits.append(f"· register {rel}")
        elif self.dry_run:
            bits.append(f"· would write vendors/{self.slug}.yaml (dry-run)")
        for err in self.errors:
            bits.append(f"! {err}")
        return bits


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def normalize_base_url(provider: str, raw: str | None) -> str:
    spec = PROVIDERS[provider]
    text = (raw or "").strip()
    if not text:
        return spec.get("default_url") or ""
    if "://" not in text:
        text = "https://" + text
    return text.rstrip("/")


def default_slug(provider: str, base_url: str = "") -> str:
    """One file per connector by default (``vendors/okta.yaml``).

    Pass ``--slug`` when you have two orgs of the same kind.
    """
    _ = base_url
    return provider


def default_vendor_name(provider: str, base_url: str) -> str:
    host = urlparse(base_url).netloc or ""
    host = host.split("@")[-1].split(":")[0]
    if host and host not in {"slack.com", "api.atlassian.com", "atlassian.com"}:
        return f"{PROVIDERS[provider]['label']} ({host})"
    return PROVIDERS[provider]["label"]


def is_connect_stub(data: dict) -> bool:
    onboarding = data.get("onboarding") or {}
    return onboarding.get("by") == "vra connect" or bool(onboarding.get("stub"))


def build_stub(
    *,
    provider: str,
    slug: str,
    vendor_name: str,
    base_url: str,
    fixture: str | None = None,
) -> dict[str, Any]:
    spec = PROVIDERS[provider]
    today = date.today().isoformat()
    now = datetime.now(timezone.utc).isoformat()
    probe: dict[str, Any] = {
        "type": "identity_provider_api",
        "provider": provider,
        "enabled": True,
        "mode": "fixture" if fixture else "live",
        "base_url": base_url,
        "page_limit": 200,
        "max_pages": 50,
    }
    if fixture:
        probe["fixture"] = fixture
    if provider == "auth0":
        probe["domain"] = base_url
    return {
        "vendor": vendor_name,
        "slug": slug,
        "tier": "high",
        "category": spec["category"],
        "description": (
            f"Connected via `vra connect`. Non-human identities are pulled "
            f"from the {spec['label']} API. Overlay fields (owner, "
            f"last_rotated, resides_in) and AIV-* feature scoring stay "
            f"unknown until you fill them — `python3 vra.py enrich {slug}`."
        ),
        "contract": {
            "baa_on_file": False,
            "ai_addendum_signed": False,
            "last_review": today,
            "baa_covered_subprocessors": [],
        },
        "ai_surface": [],
        "nhis": [],
        "watch": {},
        "probe": probe,
        "onboarding": {
            "onboarded_at": now,
            "by": "vra connect",
            "stub": True,
            "provider": provider,
            "base_url": base_url,
            "notes": STUB_NOTES.format(slug=slug),
        },
        "state": {
            "last_assessed": None,
            "snapshot_hashes": {},
        },
    }


def _secret_in_mapping(blob: Any, secret: str) -> bool:
    # Short strings ("x", "ok") appear in ordinary YAML. Real tokens are long.
    if not secret or len(secret) < 8:
        return False
    if isinstance(blob, str):
        return secret in blob
    if isinstance(blob, dict):
        return any(_secret_in_mapping(v, secret) for v in blob.values())
    if isinstance(blob, list):
        return any(_secret_in_mapping(v, secret) for v in blob)
    return False


def write_stub(
    stub: dict[str, Any],
    *,
    root: Path,
    force: bool = False,
    secrets: dict[str, str] | None = None,
) -> tuple[Path, bool, bool]:
    """Write ``vendors/{slug}.yaml``. Returns (path, created, updated)."""
    dest = root / "vendors"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{stub['slug']}.yaml"
    created = not path.exists()
    updated = False
    if path.exists():
        existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not is_connect_stub(existing) and not force:
            raise ValueError(
                f"{path} already exists and was not created by connect. "
                f"Pass --slug something-else, or --force to replace it."
            )
        # Keep any overlay a human added on a previous stub.
        if is_connect_stub(existing) and not force:
            if existing.get("nhis"):
                stub["nhis"] = existing["nhis"]
            if existing.get("ai_surface"):
                stub["ai_surface"] = existing["ai_surface"]
            if existing.get("watch"):
                stub["watch"] = existing["watch"]
            contract = existing.get("contract") or {}
            if contract.get("baa_covered_subprocessors"):
                stub["contract"]["baa_covered_subprocessors"] = contract["baa_covered_subprocessors"]
            if contract.get("baa_on_file"):
                stub["contract"]["baa_on_file"] = contract["baa_on_file"]
            if contract.get("ai_addendum_signed"):
                stub["contract"]["ai_addendum_signed"] = contract["ai_addendum_signed"]
            stub["onboarding"]["onboarded_at"] = (existing.get("onboarding") or {}).get(
                "onboarded_at"
            ) or stub["onboarding"]["onboarded_at"]
        updated = True
        created = False
    dumped = yaml.safe_dump(stub, sort_keys=False, default_flow_style=False, allow_unicode=True)
    for value in (secrets or {}).values():
        if value and value in dumped:
            raise ValueError("refusing to write a vendor register that contains a secret")
    path.write_text(dumped, encoding="utf-8")
    return path, created, updated


def _store_secrets(provider: str, secrets: dict[str, str]) -> bool:
    stored = False
    for field_name, value in secrets.items():
        if not value:
            continue
        set_secret(provider, field_name, value)
        stored = True
    return stored


def _prompt_missing(
    provider: str,
    have: dict[str, str],
    *,
    getpass_fn: GetPassFn,
    input_fn: InputFn,
) -> dict[str, str]:
    spec = PROVIDERS[provider]
    out = dict(have)
    for field_name in spec["fields"]:
        if out.get(field_name) or get_secret(provider, field_name):
            continue
        label = spec.get("field_prompts", {}).get(field_name, f"Paste {field_name} (hidden)")
        value = getpass_fn(f"{label}  > ")
        if value:
            out[field_name] = value
    return out


def _ask(prompt: str, *, default: str | None = None, input_fn: InputFn) -> str:
    suffix = f" [{default}]" if default else ""
    raw = input_fn(f"{prompt}{suffix}  > ")
    text = (raw or "").strip()
    return text or (default or "")


def _discover(
    *,
    provider: str,
    slug: str,
    vendor_name: str,
    base_url: str,
    fixture: str | None,
    cfg: RunConfig,
    nhi_path: Path | None,
) -> tuple[list[dict], str | None]:
    from .discover import _estate_to_nhis
    from .idp import discover_from_recorded, discover_from_vendor
    from .nhi import NHIInventory

    if fixture:
        path = Path(fixture)
        if not path.is_absolute():
            path = REPO_ROOT / path
        estate, err = discover_from_recorded(path)
        if err or estate is None:
            return [], err or "fixture discovery failed"
        nhis = _estate_to_nhis(estate)
    else:
        vendor = {
            "slug": slug,
            "vendor": vendor_name,
            "probe": {
                "provider": provider,
                "base_url": base_url,
                "domain": base_url,
                "mode": "live",
                "enabled": True,
            },
        }
        estate, err = discover_from_vendor(vendor, cfg)
        if err or estate is None:
            return [], err or "discovery failed"
        nhis = _estate_to_nhis(estate)
    if not cfg.dry_run:
        inventory = NHIInventory(path=nhi_path) if nhi_path else NHIInventory()
        for nhi in nhis:
            row = dict(nhi)
            row["vendor_name"] = vendor_name
            inventory.upsert(slug, row)
        inventory.save(cfg)
    return nhis, None


def connect(
    provider: str,
    *,
    base_url: str | None = None,
    slug: str | None = None,
    vendor_name: str | None = None,
    secrets: dict[str, str] | None = None,
    fixture: str | None = None,
    force: bool = False,
    dry_run: bool = False,
    skip_discover: bool = False,
    allow_env_creds: bool = False,
    offline: bool = False,
    prompt: bool = False,
    input_fn: InputFn | None = None,
    getpass_fn: GetPassFn | None = None,
    root: Path | None = None,
    nhi_path: Path | None = None,
    transport=None,
) -> ConnectResult:
    """Attach one vendor. Fully programmatic — the CLI is a thin wrapper."""
    provider = (provider or "").strip().lower()
    if provider not in PROVIDERS:
        raise ValueError(
            f"unknown vendor {provider!r}; choose {', '.join(sorted(PROVIDERS))}"
        )
    spec = PROVIDERS[provider]
    input_fn = input_fn or input
    getpass_fn = getpass_fn or getpass.getpass
    root = root or REPO_ROOT

    url = normalize_base_url(provider, base_url)
    if prompt and spec["url_required"] and not url:
        url = normalize_base_url(
            provider,
            _ask(spec["url_prompt"], default=spec.get("url_hint"), input_fn=input_fn),
        )
    if spec["url_required"] and not url:
        raise ValueError(f"{spec['url_prompt']} is required (e.g. {spec['url_hint']})")
    if not url:
        url = spec.get("default_url") or ""

    slug = (slug or default_slug(provider, url)).strip()
    vendor_name = (vendor_name or default_vendor_name(provider, url)).strip()
    result = ConnectResult(
        provider=provider,
        slug=slug,
        vendor_name=vendor_name,
        base_url=url,
        dry_run=dry_run,
    )

    incoming = {k: v for k, v in (secrets or {}).items() if v}
    if prompt:
        incoming = _prompt_missing(
            provider, incoming, getpass_fn=getpass_fn, input_fn=input_fn
        )

    if incoming and not dry_run:
        result.stored = _store_secrets(provider, incoming)

    resolved, resolve_err, used_env = resolve_secrets(provider, allow_env=allow_env_creds)
    if used_env:
        result.errors.append(
            "using environment variables (--allow-env-creds). Prefer the keychain."
        )
    have_any = bool(resolved) or bool(incoming)
    if have_any:
        # inspect_scopes never needs the network
        info = inspect_scopes(provider, resolved or incoming)
        result.scope_warning = info.get("warning")
        if not result.stored and resolved and not used_env:
            result.stored = True  # already in the keychain from a previous connect
    elif resolve_err and not fixture:
        result.errors.append(resolve_err)

    cfg = RunConfig(offline=offline or bool(fixture), dry_run=dry_run, allow_env_creds=allow_env_creds)

    if fixture:
        result.connection_ok = True
        result.connection_detail = "fixture walk (offline)"
    elif resolved and not offline:
        ok, detail = verify_readonly(
            provider, resolved, base_url=url, transport=transport
        )
        result.connection_ok = ok
        result.connection_detail = detail
        if not ok:
            result.errors.append(detail)
    elif offline and not fixture:
        result.connection_detail = "offline — live check skipped"
    elif not resolved:
        result.connection_detail = resolve_err or "no credential"

    # Drop local secret bindings before we touch YAML or logs.
    check_values = list((resolved or {}).values()) + list(incoming.values())
    resolved.clear()
    incoming.clear()

    stub = build_stub(
        provider=provider,
        slug=slug,
        vendor_name=vendor_name,
        base_url=url,
        fixture=fixture,
    )
    for secret in check_values:
        if _secret_in_mapping(stub, secret):
            raise ValueError("refusing to write a vendor register that contains a secret")

    if not dry_run:
        path, created, updated = write_stub(
            stub, root=root, force=force, secrets={str(i): v for i, v in enumerate(check_values)}
        )
        result.register_path = path
        result.created = created
        result.updated = updated
    else:
        result.register_path = (root / "vendors" / f"{slug}.yaml")

    if skip_discover:
        result.skipped_discover = True
        return result

    if fixture or result.connection_ok:
        dest = nhi_path
        if dest is None and root != REPO_ROOT:
            dest = root / "data" / "nhis.json"
        nhis, err = _discover(
            provider=provider,
            slug=slug,
            vendor_name=vendor_name,
            base_url=url,
            fixture=fixture,
            cfg=cfg,
            nhi_path=dest,
        )
        result.identities = nhis
        result.discovered = len(nhis)
        if err:
            result.errors.append(err)
    else:
        result.skipped_discover = True
        if not any("no keychain" in e or "no credential" in e for e in result.errors):
            result.errors.append("discovery skipped because the connection check failed")
    return result


def enrich_vendor(slug: str | None = None, *, root: Path | None = None) -> list[str]:
    """Describe what a stub is still missing. Does not invent values."""
    root = root or REPO_ROOT
    vendors_dir = root / "vendors" if root != REPO_ROOT else VENDORS_DIR
    lines: list[str] = []
    paths: list[Path]
    if slug:
        path = vendors_dir / f"{slug}.yaml"
        if not path.exists():
            return [f"no register for {slug!r} — run `python3 vra.py connect` first."]
        paths = [path]
    else:
        paths = sorted(vendors_dir.glob("*.yaml"))
        if not paths:
            return ["no vendors yet. Run `python3 vra.py connect`."]

    from .nhi import NHIInventory
    from .config import NHI_FILE

    inventory = NHIInventory(path=(root / "data" / "nhis.json") if root != REPO_ROOT else NHI_FILE)

    for path in paths:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        this_slug = data.get("slug") or path.stem
        stub = is_connect_stub(data)
        lines.append(f"{_rel(path)}" + ("  (connect stub)" if stub else ""))
        missing: list[str] = []
        contract = data.get("contract") or {}
        if not contract.get("baa_on_file"):
            missing.append("contract.baa_on_file")
        if not contract.get("ai_addendum_signed"):
            missing.append("contract.ai_addendum_signed")
        if not data.get("ai_surface"):
            missing.append("ai_surface  (empty — AIV-* feature scoring waits)")
        if missing:
            lines.append("  unknown / empty (21-day questions, not failures):")
            for item in missing:
                lines.append(f"    - {item}")
        else:
            lines.append("  register overlay looks filled in.")
        rows = inventory.for_vendor(this_slug)
        if rows:
            lines.append("  NHI overlay (optional — owner, last_rotated, resides_in):")
            for row in rows:
                name = row.get("display_name") or row.get("name") or row.get("id")
                owner = row.get("owner") or "unknown"
                rotated = row.get("last_rotated") or "unknown"
                lines.append(f"    {name:<28} owner={owner}  last_rotated={rotated}")
        lines.append("")
    lines.append(
        "Edit the YAML yourself — the model will not fill these in. "
        "The next monitor cycle scores what you wrote."
    )
    lines.append("  python3 vra.py enrich <slug> --edit")
    return lines


def _open_in_editor(path: Path) -> int:
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or "nano"
    try:
        return os.spawnvp(os.P_WAIT, editor, [editor, str(path)])
    except OSError as exc:
        print(f"vra enrich: could not open editor ({exc}). Edit {path} by hand.", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra connect",
        description=(
            "Attach a vendor by answering a few questions. "
            "Stores the token in the OS keychain, checks the connection, "
            "discovers identities, and writes a starter vendors/{slug}.yaml. "
            "Flags stay available for scripts."
        ),
    )
    p.add_argument(
        "provider",
        nargs="?",
        choices=sorted(PROVIDERS),
        help="okta / auth0 / slack / atlassian. Asked if omitted.",
    )
    p.add_argument("--provider", dest="provider_flag", choices=sorted(PROVIDERS), default=None)
    p.add_argument("--base-url", default=None, help="Org / tenant URL")
    p.add_argument("--slug", default=None, help="vendors/{slug}.yaml (default: the vendor kind)")
    p.add_argument("--name", dest="vendor_name", default=None, help="display name in the register")
    p.add_argument("--fixture", default=None, help="recorded page set — no live network")
    p.add_argument("--offline", action="store_true", help="do not call the live vendor API")
    p.add_argument("--dry-run", action="store_true", help="print, write nothing")
    p.add_argument("--force", action="store_true", help="replace an existing register")
    p.add_argument("--skip-discover", action="store_true", help="write the stub only")
    p.add_argument("--yes", "--non-interactive", dest="yes", action="store_true",
                   help="never prompt; fail if a required value is missing")
    p.add_argument("--allow-env-creds", action="store_true",
                   help="CI only: fall back to environment variables")
    return p


def _interactive_available(force_yes: bool) -> bool:
    if force_yes:
        return False
    return bool(sys.stdin.isatty())


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    provider = args.provider_flag or args.provider
    interactive = _interactive_available(args.yes)

    if not provider:
        if not interactive:
            print(
                "vra connect: this command asks questions in a terminal.\n"
                "For scripts, pass --provider and --base-url "
                "(store the token first with `python3 vra.py creds set <connector>`).",
                file=sys.stderr,
            )
            return 2
        provider = _ask(
            "Vendor? [okta / auth0 / slack / atlassian]",
            input_fn=input,
        ).strip().lower()
        if provider not in PROVIDERS:
            print(f"vra connect: unknown vendor {provider!r}", file=sys.stderr)
            return 2

    if not args.base_url and PROVIDERS[provider]["url_required"] and not interactive and not args.fixture:
        print(
            f"vra connect: pass --base-url ({PROVIDERS[provider]['url_hint']}) "
            "or run without --yes so it can ask.",
            file=sys.stderr,
        )
        return 2

    try:
        result = connect(
            provider,
            base_url=args.base_url,
            slug=args.slug,
            vendor_name=args.vendor_name,
            fixture=args.fixture,
            force=args.force,
            dry_run=args.dry_run,
            skip_discover=args.skip_discover,
            allow_env_creds=args.allow_env_creds,
            offline=args.offline,
            prompt=interactive,
        )
    except ValueError as exc:
        print(f"vra connect: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"vra connect: {exc}", file=sys.stderr)
        return 2

    print()
    for line in result.lines():
        print(f"  {line}")
    print()
    if result.created or result.updated:
        print(
            "  Next:  python3 vra.py monitor     "
            "(picks this vendor up on the next cycle)"
        )
        print(
            f"  Later: python3 vra.py enrich {result.slug}   "
            "(optional — fill AIV-* register fields)"
        )
        print()
    if result.errors and not result.connection_ok and not args.fixture:
        return 2
    return 0


def enrich_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="vra enrich",
        description=(
            "Show which register fields a connect stub still has as unknown. "
            "Does not invent answers. Optional --edit opens the YAML."
        ),
    )
    p.add_argument("slug", nargs="?", help="vendor slug (default: every vendor)")
    p.add_argument("--edit", action="store_true", help="open vendors/{slug}.yaml in $EDITOR")
    args = p.parse_args(argv)
    if args.edit and not args.slug:
        print("vra enrich: --edit needs a slug (e.g. python3 vra.py enrich okta --edit)", file=sys.stderr)
        return 2
    lines = enrich_vendor(args.slug)
    print()
    for line in lines:
        print(line)
    print()
    if args.edit and args.slug:
        path = VENDORS_DIR / f"{args.slug}.yaml"
        if not path.exists():
            return 2
        return _open_in_editor(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
