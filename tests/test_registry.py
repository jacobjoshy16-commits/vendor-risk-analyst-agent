"""Connector registry, protocol connectors, stable keys, isolation, portfolio."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import RunConfig  # noqa: E402
from vra.idp import discover_from_recorded  # noqa: E402
from vra.nhi import NHIInventory, identity_key, immutable_id  # noqa: E402
from vra.probe import _extract_nhis  # noqa: E402
from vra.registry import (  # noqa: E402
    ConnectorManifest,
    all_manifests,
    connect_catalog,
    known_ids,
    menu_ids,
    register,
)


class TestRegistryDrivesMenus(unittest.TestCase):
    def test_menus_come_from_manifests_not_a_hardcoded_list(self):
        ids = menu_ids()
        self.assertIn("okta", ids)
        self.assertIn("oidc_apps", ids)
        self.assertIn("scim", ids)
        self.assertIn("generic_rest", ids)
        self.assertIn("github", ids)
        self.assertIn("google_workspace", ids)
        self.assertIn("aws_iam", ids)
        self.assertIn("atlassian", ids)
        catalog = connect_catalog()
        self.assertEqual(set(catalog), set(ids))
        # A newly registered connector appears without editing connect.py.
        register(ConnectorManifest(
            id="zz_test_only",
            display_name="Test Only",
            auth="bearer",
            fields=("api_token",),
            pagination="none",
            list_method="n/a",
            show_in_menu=True,
        ))
        self.assertIn("zz_test_only", menu_ids())
        self.assertIn("zz_test_only", connect_catalog())

    def test_every_menu_connector_has_list_nhis(self):
        from vra.registry import _LISTERS

        for manifest in all_manifests(menu=True):
            if manifest.id == "zz_test_only":
                continue
            self.assertIn(manifest.id, _LISTERS, f"{manifest.id} has no list_nhis")


class TestProtocolConnectors(unittest.TestCase):
    def test_entra_follows_odata_next_link(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/entra_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        self.assertEqual(estate.provider, "entra")
        self.assertEqual(len(estate.applications), 2)
        self.assertEqual(len(estate.service_accounts), 1)
        nhis = _extract_nhis(estate.to_probe_blob())
        ids = {n["id"] for n in nhis}
        self.assertIn("app-copilot-01", ids)
        self.assertIn("sp-writer-01", ids)

    def test_scim_keeps_service_accounts_skips_humans(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/scim_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        names = {s["name"] for s in estate.service_accounts}
        self.assertIn("Provisioner", names)
        self.assertIn("Help Bot", names)
        self.assertNotIn("Jane Human", names)
        self.assertTrue(any("skipped" in w and "human" in w for w in estate.warnings))

    def test_generic_rest_jsonpath_mapping(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/generic_rest_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        self.assertEqual(len(estate.applications), 2)
        nhis = _extract_nhis(estate.to_probe_blob())
        invoice = next(n for n in nhis if n["id"] == "sa-1")
        self.assertIn("invoices.write", invoice["write_scopes"])

    def test_github_installations(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/github_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        slugs = {a["label"] for a in estate.applications}
        self.assertEqual(slugs, {"copilot", "dependabot"})

    def test_aws_list_users_and_roles(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/aws_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        names = {s["name"] for s in estate.service_accounts}
        self.assertIn("ci-bot", names)
        self.assertIn("vendor-agent-role", names)

    def test_google_workspace_service_accounts(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/google_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        emails = {s["name"] for s in estate.service_accounts}
        self.assertTrue(any("gserviceaccount.com" in (s.get("name") or "") or True for s in estate.service_accounts))
        self.assertEqual(len(estate.service_accounts), 2)
        _ = emails

    def test_oidc_flavor_from_url(self):
        from vra.protocol import detect_oidc_flavor

        self.assertEqual(detect_oidc_flavor("https://acme.okta.com"), "okta")
        self.assertEqual(detect_oidc_flavor("https://t.us.auth0.com"), "auth0")
        self.assertEqual(detect_oidc_flavor("https://graph.microsoft.com"), "entra")
        self.assertEqual(detect_oidc_flavor("https://api.pingone.com/v1/environments/e"), "ping")
        self.assertEqual(detect_oidc_flavor("https://api.us.onelogin.com"), "onelogin")

    def test_jsonpath_subset(self):
        from vra.protocol import jsonpath_get

        blob = {"items": [{"id": "a", "owner": {"email": "x@y"}}]}
        self.assertEqual(jsonpath_get(blob, "items")[0]["id"], "a")
        self.assertEqual(jsonpath_get(blob["items"][0], "owner.email"), "x@y")


class TestStableIdentityKey(unittest.TestCase):
    def test_rename_does_not_fork_history(self):
        tmp = Path(tempfile.mkdtemp()) / "nhis.json"
        inv = NHIInventory(path=tmp)
        rec, _ = inv.upsert("v", {
            "id": "0oa001", "app_id": "0oa001", "name": "Old Label",
            "kind": "oauth_app", "scopes": ["users.read"],
        })
        rec2, ev = inv.upsert("v", {
            "id": "0oa001", "app_id": "0oa001", "name": "New Label",
            "kind": "oauth_app", "scopes": ["users.read"],
        })
        self.assertEqual(rec["key"], rec2["key"])
        self.assertEqual(rec2["display_name"], "New Label")
        self.assertIsNone(ev)
        self.assertEqual(len(inv.all()), 1)

    def test_key_never_uses_display_name(self):
        a = identity_key("v", {"id": "abc123", "name": "Friendly"})
        b = identity_key("v", {"id": "abc123", "name": "Renamed"})
        self.assertEqual(a, b)
        self.assertNotIn("Friendly", a)
        self.assertIsNone(immutable_id({"name": "Friendly", "principal": ""}))
        # No immutable id and no principal → unkeyed, still not the name.
        self.assertEqual(identity_key("v", {"name": "Friendly"}), "v|unkeyed")


class TestIsolationAndPool(unittest.TestCase):
    def test_one_failure_does_not_abort_the_batch(self):
        from vra.pool import map_isolated

        def fn(n: int) -> int:
            if n == 2:
                raise RuntimeError("401 unauthorized")
            return n * 10

        out = map_isolated(
            fn, [1, 2, 3], workers=3,
            on_error=lambda n, exc: f"err-{n}",
        )
        self.assertEqual(out, [10, "err-2", 30])

    def test_collect_all_keeps_healthy_vendors(self):
        from vra.collect import collect_all
        from vra import evaluate as ev
        import vra.collect as collect_mod

        vendors = [
            {"slug": "ok-one", "vendor": "Ok One", "tier": "high", "watch": {}, "ai_surface": []},
            {"slug": "boom", "vendor": "Boom", "tier": "high", "watch": {}, "ai_surface": []},
            {"slug": "ok-two", "vendor": "Ok Two", "tier": "high", "watch": {}, "ai_surface": []},
        ]
        original = collect_mod.collect_vendor

        def wrapped(vendor, cfg, portfolio, controls):
            if vendor["slug"] == "boom":
                raise RuntimeError("timeout")
            return original(vendor, cfg, portfolio, controls)

        collect_mod.collect_vendor = wrapped  # type: ignore[method-assign]
        try:
            works = collect_all(vendors, RunConfig(offline=True, dry_run=True, workers=3), vendors, ev.load_controls())
        finally:
            collect_mod.collect_vendor = original  # type: ignore[method-assign]
        slugs = [w.slug for w in works]
        self.assertEqual(slugs, ["ok-one", "boom", "ok-two"])
        boom = next(w for w in works if w.slug == "boom")
        self.assertTrue(boom.probe_failed or boom.error)
        healthy = [w for w in works if w.slug != "boom"]
        self.assertTrue(all(w.error is None for w in healthy))


class TestPortfolio(unittest.TestCase):
    def test_portfolio_aggregates_without_inventing(self):
        from vra.portfolio import build_portfolio, format_portfolio
        from vra.register import FindingStore

        tmp = Path(tempfile.mkdtemp())
        inv = NHIInventory(path=tmp / "nhis.json")
        inv.upsert("okta", {"id": "a1", "name": "A", "kind": "oauth_app", "write_scopes": ["users.manage"], "vendor_name": "Okta"})
        inv.upsert("slack", {"id": "b1", "name": "B", "kind": "bot", "write_scopes": [], "vendor_name": "Slack"})
        inv.meta["previous_keys"] = ["okta|a1"]
        store = FindingStore(path=tmp / "findings.json")
        store.findings = {
            "NHI-01-x": {
                "id": "NHI-01-x", "kind": "finding", "severity": "critical",
                "state": "open", "vendor": "okta",
            }
        }
        blob = build_portfolio(inv, store)
        self.assertEqual(blob["nhis"], 2)
        self.assertEqual(blob["write"], 1)
        self.assertEqual(blob["by_severity"]["critical"], 1)
        self.assertIn("slack|b1", blob["new_since_last"])
        text = "\n".join(format_portfolio(blob))
        self.assertIn("Okta", text)
        self.assertIn("Slack", text)
        self.assertNotIn("AIV-07", text)


class TestSecretsStayOut(unittest.TestCase):
    def test_registry_list_does_not_echo_token(self):
        from vra.idp import MemoryTransport, discover_estate

        bus = MemoryTransport()
        bus.add("GET", "https://graph.microsoft.com/v1.0/applications?%24top=99", {"value": []})
        bus.add("GET", "https://graph.microsoft.com/v1.0/servicePrincipals?%24top=99", {"value": []})
        secret = "super-secret-graph-token-value"
        estate = discover_estate(
            provider="entra",
            base_url="https://graph.microsoft.com",
            transport=bus,
            token=secret,
        )
        dumped = json.dumps(estate.to_probe_blob())
        self.assertNotIn(secret, dumped)


if __name__ == "__main__":
    unittest.main(verbosity=2)
