"""Standalone NHI discovery — pull the full list from Auth0 / Okta.

    python3 vra.py discover --provider okta --base-url https://org.okta.com
    python3 vra.py discover --provider auth0 --domain tenant.us.auth0.com
    python3 vra.py discover --vendor aegis-identity-cloud --offline
    python3 vra.py discover --provider okta --fixture sandbox/probe/idp/okta_pages.json

A human does not type identities into YAML. This command (and the monitor
cycle that calls the same walker) pages the IdP until there is no next
page, then writes ``data/nhis.json``. ``vendors/*.yaml`` ``nhis:`` is an
optional overlay (owner, last_rotated, resides_in) — not the inventory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .config import REPO_ROOT, RunConfig
from .idp import (
    IdPEstate,
    discover_estate,
    discover_from_recorded,
    discover_from_vendor,
    infer_provider,
    slug_from_base,
)
from .nhi import NHIInventory, discover_nhis
from .probe import ProbeResult, _extract_nhis, run_probe
from .register import load_vendors


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra discover",
        description=(
            "Pull every non-human identity from a vendor API "
            "(Okta, Auth0, Atlassian, Slack). Paginates. Does not invent identities."
        ),
    )
    p.add_argument("--provider", choices=("okta", "auth0", "atlassian", "slack"), default=None,
                   help="Vendor API: okta, auth0, atlassian, slack. Inferred from --base-url if omitted.")
    p.add_argument("--base-url", default=None,
                   help="Okta org URL (https://org.okta.com) or Auth0 issuer")
    p.add_argument("--domain", default=None,
                   help="Auth0 tenant domain (tenant.us.auth0.com)")
    p.add_argument("--token-env", default=None,
                   help="env var holding the Okta SSWS token or Auth0 management token")
    p.add_argument("--client-id-env", default="AUTH0_CLIENT_ID",
                   help="Auth0 M2M client id env var (default AUTH0_CLIENT_ID)")
    p.add_argument("--client-secret-env", default="AUTH0_CLIENT_SECRET",
                   help="Auth0 M2M client secret env var")
    p.add_argument("--audience", default=None, help="Auth0 management audience")
    p.add_argument("--vendor", action="append", default=[], dest="vendors",
                   help="use this vendor's probe: block (repeatable)")
    p.add_argument("--fixture", default=None,
                   help="recorded page set (JSON). Walked by the same parser as live.")
    p.add_argument("--offline", action="store_true",
                   help="do not call the network; use --fixture or the vendor fixture")
    p.add_argument("--dry-run", action="store_true", help="print, do not write data/nhis.json")
    p.add_argument("--page-limit", type=int, default=None, help="page size (Okta default 200)")
    p.add_argument("--max-pages", type=int, default=None, help="safety cap on list pages")
    p.add_argument("--no-grants", action="store_true", help="skip per-app / client-grant fetches")
    p.add_argument("--no-tokens", action="store_true", help="skip Okta /api/v1/api-tokens")
    p.add_argument("--users", action="store_true",
                   help="also list Okta users matching the service-account search")
    p.add_argument("--allow-env-creds", action="store_true",
                   help="CI only: fall back to environment variables if the keychain is empty")
    return p


def _print_estate(estate: IdPEstate, nhis: list[dict]) -> None:
    print(f"vra discover: {estate.provider} {estate.base_url}")
    print(
        f"  pages={estate.pages_fetched}  requests={estate.requests_made}  "
        f"apps={estate.counts['applications']}  grants={estate.counts['oauth_grants']}  "
        f"tokens={estate.counts['api_tokens']}  service_accounts={estate.counts['service_accounts']}"
        + ("  TRUNCATED" if estate.truncated else "")
    )
    for warning in estate.warnings:
        print(f"  ! {warning}")
    if estate.error:
        print(f"  ! {estate.error}", file=sys.stderr)
    print()
    print(f"{'Identity':<36} {'Kind':<18} {'Write scopes':<28} Via")
    print("-" * 110)
    for nhi in nhis:
        writes = ", ".join(nhi.get("write_scopes") or []) or "none"
        print(
            f"{(nhi.get('name') or nhi.get('principal') or nhi.get('id') or ''):<36} "
            f"{(nhi.get('kind') or ''):<18} "
            f"{writes[:28]:<28} "
            f"{nhi.get('discovered_via') or nhi.get('source') or ''}"
        )
    print(f"\n{len(nhis)} identit{'y' if len(nhis) == 1 else 'ies'} discovered from the {estate.provider} API")


def _estate_to_nhis(estate: IdPEstate) -> list[dict]:
    return _extract_nhis(estate.to_probe_blob())


def _persist(vendor_slug: str, vendor_name: str, nhis: list[dict], cfg: RunConfig) -> int:
    inventory = NHIInventory()
    rows = []
    for nhi in nhis:
        row = dict(nhi)
        row["vendor_name"] = vendor_name
        rec, _ev = inventory.upsert(vendor_slug, row)
        rows.append(rec)
    inventory.save(cfg)
    return len(rows)


def _discover_raw(args: argparse.Namespace, cfg: RunConfig) -> tuple[IdPEstate | None, str | None]:
    fixture = args.fixture
    base = (args.base_url or args.domain or "").rstrip("/")
    provider = args.provider or infer_provider({"provider": args.provider}, base_url=base)

    if fixture:
        path = Path(fixture)
        if not path.is_absolute():
            path = REPO_ROOT / path
        if not path.exists():
            return None, f"fixture not found: {path}"
        return discover_from_recorded(path)

    if cfg.offline:
        return None, "offline discovery needs --fixture (or --vendor with a fixture probe)"
    if not base:
        return None, "need --base-url / --domain, or --vendor, or --fixture"

    block: dict[str, Any] = {
        "provider": provider,
        "base_url": base,
        "domain": args.domain or base,
        "token_env": args.token_env or {
            "auth0": "AUTH0_MGMT_TOKEN",
            "atlassian": "ATLASSIAN_API_TOKEN",
            "slack": "SLACK_BOT_TOKEN",
        }.get(provider or "", "OKTA_API_TOKEN"),
        "client_id_env": args.client_id_env,
        "client_secret_env": args.client_secret_env,
        "audience": args.audience,
        "fetch_grants": not args.no_grants,
        "fetch_tokens": not args.no_tokens,
        "fetch_users": bool(args.users),
    }
    if args.page_limit:
        block["page_limit"] = args.page_limit
    if args.max_pages:
        block["max_pages"] = args.max_pages
    vendor = {"slug": slug_from_base(base), "vendor": slug_from_base(base), "probe": block}
    return discover_from_vendor(vendor, cfg)


def discover_vendor_probe(vendor: dict, cfg: RunConfig) -> tuple[list[dict], dict[str, Any]]:
    """Run the vendor's configured probe and return observed NHIs.

    Fixture-mode vendors (sandbox) go through ``run_probe``. Live IdP
    vendors go through the paginating client. Either way the human did
    not type the list.
    """
    block = vendor.get("probe") or {}
    meta: dict[str, Any] = {"vendor": vendor.get("slug"), "mode": block.get("mode")}
    if block.get("mode") == "live" and not cfg.offline:
        estate, err = discover_from_vendor(vendor, cfg)
        if err or estate is None:
            return [], {**meta, "error": err or "discovery failed"}
        nhis = _estate_to_nhis(estate)
        meta.update({
            "provider": estate.provider,
            "pages_fetched": estate.pages_fetched,
            "truncated": estate.truncated,
            "counts": estate.counts,
            "warnings": estate.warnings,
        })
        return nhis, meta

    probe = run_probe(vendor, cfg)
    meta.update({
        "ran": probe.ran,
        "error": probe.error,
        "provider": probe.provider,
        "pages_fetched": probe.pages_fetched,
        "truncated": probe.truncated,
        "counts": probe.resource_counts,
    })
    if not probe.ran:
        return [], meta
    # Merge register overlay so declared identities stay declared.
    merged = discover_nhis(vendor, probe, portfolio=[vendor])
    return merged, meta


def run_discover(args: argparse.Namespace) -> int:
    cfg = RunConfig(
        offline=args.offline, dry_run=args.dry_run,
        allow_env_creds=bool(getattr(args, "allow_env_creds", False)),
    )

    # Path 1: explicit IdP flags / recorded pages — no vendor YAML required.
    if args.fixture or args.base_url or args.domain:
        estate, err = _discover_raw(args, cfg)
        if err or estate is None:
            print(f"vra discover: {err}", file=sys.stderr)
            return 2
        nhis = _estate_to_nhis(estate)
        _print_estate(estate, nhis)
        slug = slug_from_base(estate.base_url)
        written = _persist(slug, slug, nhis, cfg)
        if not cfg.dry_run:
            print(f"wrote {written} identit{'y' if written == 1 else 'ies'} to data/nhis.json")
        return 0 if not estate.error else 2

    # Path 2: one or more vendor probe blocks (or every vendor that has one).
    filter_cfg = RunConfig(offline=args.offline, dry_run=args.dry_run, vendors=list(args.vendors))
    vendors = load_vendors(filter_cfg if args.vendors else RunConfig())
    vendors = [v for v in vendors if v.get("probe")]
    if not vendors:
        print(
            "vra discover: no vendor probe configured. "
            "Pass --provider okta --base-url https://org.okta.com "
            "(token in $OKTA_API_TOKEN), or add a probe: block to a vendor YAML.",
            file=sys.stderr,
        )
        return 2

    total = 0
    errors = 0
    for vendor in vendors:
        nhis, meta = discover_vendor_probe(vendor, cfg)
        print(f"vra discover: {vendor.get('vendor')} ({vendor.get('slug')})")
        if meta.get("error"):
            print(f"  ! {meta['error']}")
            errors += 1
            continue
        print(
            f"  mode={meta.get('mode')}  provider={meta.get('provider') or '—'}  "
            f"pages={meta.get('pages_fetched') or 0}  "
            f"identities={len(nhis)}"
            + ("  TRUNCATED" if meta.get("truncated") else "")
        )
        fake = ProbeResult(vendor=vendor["slug"], ran=True, mode=str(meta.get("mode") or "fixture"), nhis=nhis)
        merged = discover_nhis(vendor, fake, portfolio=vendors)
        _persist(vendor["slug"], vendor.get("vendor") or vendor["slug"], merged, cfg)
        total += len(merged)
        for nhi in merged:
            writes = ", ".join(nhi.get("write_scopes") or []) or "none"
            print(
                f"    {(nhi.get('name') or nhi.get('principal') or ''):<32} "
                f"{(nhi.get('kind') or ''):<16} {writes[:24]:<24} "
                f"{nhi.get('source') or ''} {nhi.get('discovered_via') or ''}"
            )
    print(f"\n{total} identit{'y' if total == 1 else 'ies'} across {len(vendors)} vendor probe(s)")
    if not cfg.dry_run:
        print("inventory: data/nhis.json")
    return 2 if errors and total == 0 else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run_discover(args)
    except Exception as exc:
        print(f"vra discover: {exc}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
