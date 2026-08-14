"""Automatic NHI discovery from Auth0 / Okta — the list is the API, not YAML.

A human does not type 100 identities into a register. These tests walk
paginated management-API pages (the same walker live HTTP uses) and
assert every identity comes back without a ``nhis:`` block.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import RunConfig  # noqa: E402
from vra.idp import (  # noqa: E402
    MemoryTransport,
    classify_kind,
    discover_auth0,
    discover_estate,
    discover_from_recorded,
    discover_okta,
    infer_provider,
    next_link,
    redact,
    slug_from_base,
)
from vra.nhi import discover_nhis  # noqa: E402
from vra.probe import _extract_nhis, run_probe  # noqa: E402


OKTA = "https://org.okta.example"
AUTH0 = "https://tenant.us.auth0.com"


def _okta_app(i: int, **kw) -> dict:
    return {
        "id": f"0oa{i:010d}",
        "label": kw.get("label", f"Vendor App {i:03d}"),
        "status": kw.get("status", "ACTIVE"),
        "signOnMode": kw.get("signOnMode", "OPENID_CONNECT"),
        "created": "2026-01-15T00:00:00.000Z",
        "credentials": {"oauthClient": {"client_id": f"0oa{i:010d}"}},
        **{k: v for k, v in kw.items() if k not in {"label", "status", "signOnMode"}},
    }


def _page_okta_apps(apps: list[dict], page_size: int, base: str = OKTA) -> MemoryTransport:
    transport = MemoryTransport()
    for start in range(0, len(apps), page_size):
        chunk = apps[start:start + page_size]
        if start == 0:
            url = f"{base}/api/v1/apps?limit={page_size}"
        else:
            url = f"{base}/api/v1/apps?after={apps[start - 1]['id']}&limit={page_size}"
        headers = {}
        if start + page_size < len(apps):
            nxt = f"{base}/api/v1/apps?after={chunk[-1]['id']}&limit={page_size}"
            headers["Link"] = f'<{nxt}>; rel="next"'
        transport.add("GET", url, chunk, headers=headers)
    transport.add("GET", f"{base}/api/v1/api-tokens?limit={page_size}", [])
    return transport


class TestLinkAndProvider(unittest.TestCase):
    def test_okta_link_header_picks_rel_next(self):
        headers = {
            "Link": (
                '<https://org.okta.example/api/v1/apps?after=aaa&limit=200>; rel="self", '
                '<https://org.okta.example/api/v1/apps?after=bbb&limit=200>; rel="next"'
            )
        }
        self.assertEqual(
            next_link(headers),
            "https://org.okta.example/api/v1/apps?after=bbb&limit=200",
        )

    def test_infer_provider_from_url_and_block(self):
        self.assertEqual(infer_provider({"provider": "auth0"}), "auth0")
        self.assertEqual(infer_provider({}, base_url="https://x.us.auth0.com"), "auth0")
        self.assertEqual(infer_provider({}, base_url="https://org.okta.com"), "okta")
        self.assertEqual(infer_provider({"type": "identity_provider_api"}), "okta")
        self.assertEqual(infer_provider({}, base_url="https://api.atlassian.com"), "atlassian")
        self.assertEqual(infer_provider({}, base_url="https://slack.com"), "slack")

    def test_slug_from_base(self):
        self.assertEqual(slug_from_base("https://acme.okta.com"), "acme-okta-com")


class TestOktaPagination(unittest.TestCase):
    def test_one_hundred_twenty_apps_no_yaml(self):
        apps = [_okta_app(i) for i in range(120)]
        transport = _page_okta_apps(apps, page_size=50)
        estate = discover_okta(
            base_url=OKTA, token="ssws-test-token", transport=transport,
            page_limit=50, fetch_grants=False, fetch_tokens=True,
        )
        self.assertIsNone(estate.error)
        self.assertEqual(len(estate.applications), 120)
        self.assertEqual(estate.pages_fetched, 4)  # 3 app pages + 1 empty tokens page
        self.assertFalse(estate.truncated)
        nhis = _extract_nhis(estate.to_probe_blob())
        self.assertEqual(len(nhis), 120)
        vendor = {"vendor": "Acme IdP", "slug": "acme-idp", "tier": "critical", "nhis": []}
        merged = discover_nhis(
            vendor,
            type("P", (), {"ran": True, "nhis": nhis})(),
            portfolio=[vendor],
        )
        self.assertEqual(len(merged), 120)
        self.assertTrue(all(n.get("source") == "observed" for n in merged))

    def test_does_not_call_fake_apps_grants_collection(self):
        apps = [_okta_app(1), _okta_app(2, signOnMode="SAML_2_0")]
        # strip oauthClient from the SAML app so grants are not fetched
        apps[1]["credentials"] = {}
        transport = _page_okta_apps(apps, page_size=200)
        transport.add(
            "GET",
            f"{OKTA}/api/v1/apps/{apps[0]['id']}/grants?limit=200",
            [{"scopeId": "okta.users.read", "created": "2026-01-15T00:00:00.000Z"}],
        )
        estate = discover_okta(
            base_url=OKTA, token="ssws-test-token", transport=transport,
            page_limit=200, fetch_tokens=False,
        )
        urls = [u for _, u in transport.calls]
        self.assertTrue(any("/api/v1/apps?" in u or u.endswith("/api/v1/apps") for u in urls))
        self.assertTrue(any(f"/api/v1/apps/{apps[0]['id']}/grants" in u for u in urls))
        self.assertFalse(any(u.rstrip("/").endswith("/api/v1/apps/grants") for u in urls))
        self.assertEqual(len(estate.oauth_grants), 1)
        self.assertIn("okta.users.read", estate.oauth_grants[0]["scopes"])

    def test_api_tokens_become_api_key_nhis(self):
        transport = MemoryTransport()
        transport.add("GET", f"{OKTA}/api/v1/apps?limit=200", [])
        transport.add(
            "GET",
            f"{OKTA}/api/v1/api-tokens?limit=200",
            [{"id": "00Tabc", "name": "terraform", "created": "2026-01-01T00:00:00.000Z"}],
        )
        estate = discover_okta(
            base_url=OKTA, token="ssws-test-token", transport=transport, fetch_grants=False,
        )
        nhis = _extract_nhis(estate.to_probe_blob())
        self.assertEqual(len(nhis), 1)
        self.assertEqual(nhis[0]["kind"], "api_key")
        self.assertEqual(nhis[0]["name"], "terraform")
        self.assertEqual(nhis[0]["discovered_via"], "okta_api_tokens")

    def test_max_pages_truncates(self):
        apps = [_okta_app(i) for i in range(80)]
        transport = _page_okta_apps(apps, page_size=20)
        estate = discover_okta(
            base_url=OKTA, token="ssws-test-token", transport=transport,
            page_limit=20, max_pages=2, fetch_grants=False, fetch_tokens=False,
        )
        self.assertTrue(estate.truncated)
        self.assertEqual(len(estate.applications), 40)

    def test_token_never_written_to_estate(self):
        secret = "ssws-SUPER-SECRET-do-not-leak"
        transport = MemoryTransport()
        transport.add("GET", f"{OKTA}/api/v1/apps?limit=200", [_okta_app(1)])
        estate = discover_okta(
            base_url=OKTA, token=secret, transport=transport,
            fetch_grants=False, fetch_tokens=False,
        )
        blob = json.dumps(estate.to_probe_blob())
        self.assertNotIn(secret, blob)
        self.assertNotIn("SSWS", blob)

    def test_missing_token_is_an_error(self):
        estate = discover_estate(
            provider="okta", base_url=OKTA, transport=MemoryTransport(), token=None,
        )
        self.assertIsNotNone(estate.error)


class TestAuth0Pagination(unittest.TestCase):
    def test_one_hundred_clients_across_pages(self):
        transport = MemoryTransport()
        total = 100
        per_page = 50
        for page in range(2):
            clients = [
                {
                    "client_id": f"c{page * per_page + i:04d}",
                    "name": f"Client {page * per_page + i:04d}",
                    "app_type": "non_interactive" if i % 5 == 0 else "spa",
                    "grant_types": ["client_credentials"] if i % 5 == 0 else ["authorization_code"],
                    "created_at": "2026-01-01T00:00:00.000Z",
                }
                for i in range(per_page)
            ]
            transport.add(
                "GET",
                f"{AUTH0}/api/v2/clients?include_totals=true&page={page}&per_page={per_page}",
                {"start": page * per_page, "limit": per_page, "total": total, "clients": clients},
            )
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/client-grants?include_totals=true&page=0&per_page={per_page}",
            {"start": 0, "limit": per_page, "total": 0, "client_grants": []},
        )
        estate = discover_auth0(
            domain=AUTH0, access_token="mgmt-token", transport=transport, page_limit=50,
        )
        self.assertIsNone(estate.error)
        self.assertEqual(len(estate.applications), 100)
        nhis = _extract_nhis(estate.to_probe_blob())
        self.assertEqual(len(nhis), 100)
        m2m = [n for n in nhis if n["kind"] == "service_account"]
        spas = [n for n in nhis if n["kind"] == "oauth_app"]
        self.assertEqual(len(m2m), 20)
        self.assertEqual(len(spas), 80)

    def test_include_totals_stops_on_last_page(self):
        transport = MemoryTransport()
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/clients?include_totals=true&page=0&per_page=3",
            {"total": 4, "clients": [
                {"client_id": "a", "name": "A", "app_type": "spa"},
                {"client_id": "b", "name": "B", "app_type": "spa"},
                {"client_id": "c", "name": "C", "app_type": "spa"},
            ]},
        )
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/clients?include_totals=true&page=1&per_page=3",
            {"total": 4, "clients": [
                {"client_id": "d", "name": "D", "app_type": "spa"},
            ]},
        )
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/client-grants?include_totals=true&page=0&per_page=3",
            {"total": 0, "client_grants": []},
        )
        estate = discover_auth0(
            domain=AUTH0, access_token="mgmt-token", transport=transport, page_limit=3,
        )
        self.assertEqual([a["id"] for a in estate.applications], ["a", "b", "c", "d"])
        client_calls = [u for m, u in transport.calls if "/api/v2/clients" in u]
        self.assertEqual(len(client_calls), 2)

    def test_non_interactive_is_service_account(self):
        self.assertEqual(
            classify_kind({"app_type": "non_interactive"}, "auth0"),
            "service_account",
        )
        self.assertEqual(classify_kind({"app_type": "spa"}, "auth0"), "oauth_app")
        self.assertEqual(
            classify_kind({"ai_component": True, "app_type": "spa"}, "auth0"),
            "agent_principal",
        )


class TestRecordedFixtures(unittest.TestCase):
    def test_okta_recorded_pages_yield_every_identity(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/okta_pages.json")
        self.assertIsNone(err)
        self.assertIsNotNone(estate)
        assert estate is not None
        self.assertEqual(len(estate.applications), 6)
        self.assertEqual(len(estate.api_tokens), 2)
        nhis = _extract_nhis(estate.to_probe_blob())
        ids = {n["id"] for n in nhis}
        self.assertIn("0oa006shadow006", ids)
        self.assertIn("00Tterraform01", ids)
        self.assertGreaterEqual(len(nhis), 8)
        payroll = next(n for n in nhis if n["id"] == "0oa004payroll04")
        self.assertIn("okta.users.manage", payroll["write_scopes"])

    def test_auth0_recorded_pages_classify_m2m(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/auth0_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        self.assertEqual(len(estate.applications), 5)
        nhis = _extract_nhis(estate.to_probe_blob())
        kinds = {n["id"]: n["kind"] for n in nhis}
        self.assertEqual(kinds["m2mBilling001"], "service_account")
        self.assertEqual(kinds["spaConsole002"], "oauth_app")
        billing = next(n for n in nhis if n["id"] == "m2mBilling001")
        self.assertIn("write:invoices", billing["write_scopes"])

    def test_legacy_aegis_blob_still_extracts_three_apps(self):
        """Planted sandbox path must not break because we added pagination."""
        vendor = {
            "slug": "aegis-identity-cloud",
            "vendor": "Aegis Identity Cloud",
            "probe": {
                "enabled": True,
                "mode": "fixture",
                "fixture": "sandbox/probe/aegis_tenant_v1.json",
            },
        }
        probe = run_probe(vendor, RunConfig(snapshot_version="v1", offline=True))
        self.assertTrue(probe.ran)
        ids = {n["app_id"] for n in probe.nhis}
        self.assertEqual(ids, {"0oa1copilotagent01", "0oa2loopworkspace2", "0oa3meridianrev33"})
        copilot = next(n for n in probe.nhis if n["app_id"] == "0oa1copilotagent01")
        self.assertEqual(copilot["kind"], "agent_principal")

    def test_offline_skips_live_idp(self):
        from vra.idp import discover_from_vendor

        vendor = {
            "slug": "live-idp",
            "probe": {
                "provider": "okta",
                "base_url": "https://org.okta.com",
                "token_env": "OKTA_API_TOKEN",
                "mode": "live",
            },
        }
        estate, err = discover_from_vendor(vendor, RunConfig(offline=True))
        self.assertIsNone(estate)
        self.assertIn("offline", err or "")


class TestDiscoverCLI(unittest.TestCase):
    def test_fixture_command_lists_without_yaml(self):
        from vra.discover import main

        code = main(["--fixture", "sandbox/probe/idp/okta_pages.json", "--dry-run"])
        self.assertEqual(code, 0)

    def test_redact_strips_secrets(self):
        blob = redact({"Authorization": "SSWS abc", "client_secret": "xyz", "name": "ok"})
        self.assertEqual(blob["Authorization"], "<redacted>")
        self.assertEqual(blob["client_secret"], "<redacted>")
        self.assertEqual(blob["name"], "ok")


class TestSameWalkerLiveAndRecorded(unittest.TestCase):
    def test_memory_transport_matches_recorded_okta(self):
        """The recorded file is just pages; the walker is discover_okta."""
        recorded, err = discover_from_recorded(REPO / "sandbox/probe/idp/okta_pages.json")
        self.assertIsNone(err)
        assert recorded is not None
        # Re-feed the same pages through MemoryTransport + discover_okta.
        from vra.idp import load_recorded_transport

        transport, provider, base = load_recorded_transport(
            REPO / "sandbox/probe/idp/okta_pages.json"
        )
        self.assertEqual(provider, "okta")
        live_shaped = discover_okta(
            base_url=base, token="recorded", transport=transport,
            page_limit=3, fetch_users=False,
        )
        self.assertEqual(
            [a["id"] for a in live_shaped.applications],
            [a["id"] for a in recorded.applications],
        )


class TestVendorConnectors(unittest.TestCase):
    """NHIs live inside vendor products, not only in Okta."""

    def test_atlassian_pulls_tokens_and_service_accounts_not_humans(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/atlassian_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        self.assertEqual(estate.provider, "atlassian")
        nhis = _extract_nhis(estate.to_probe_blob())
        ids = {n["id"] for n in nhis}
        self.assertIn("tok-rovo-mcp-01", ids)
        self.assertIn("svc-rovo-writer", ids)
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaa", ids)  # Jane Human
        kinds = {n["id"]: n["kind"] for n in nhis}
        self.assertEqual(kinds["tok-rovo-mcp-01"], "api_key")
        self.assertEqual(kinds["svc-rovo-writer"], "service_account")
        self.assertTrue(any("Rovo" in w and "not published" in w for w in estate.warnings))

    def test_atlassian_does_not_call_invented_rovo_agents_endpoint(self):
        from vra.idp import load_recorded_transport
        from vra.connectors import discover_atlassian

        transport, _, base = load_recorded_transport(
            REPO / "sandbox/probe/idp/atlassian_pages.json"
        )
        estate = discover_atlassian(
            base_url=base, token="recorded", transport=transport, org_id="org-acme-1",
        )
        urls = [u for _, u in transport.calls]
        self.assertFalse(any("/rovo/" in u for u in urls))
        self.assertTrue(any("api-tokens" in u for u in urls))
        self.assertIsNone(estate.error)

    def test_slack_lists_bots_skips_humans_and_slackbot(self):
        estate, err = discover_from_recorded(REPO / "sandbox/probe/idp/slack_pages.json")
        self.assertIsNone(err)
        assert estate is not None
        nhis = _extract_nhis(estate.to_probe_blob())
        ids = {n["id"] for n in nhis}
        self.assertEqual(ids, {"B0ROVO1", "B0ASSIST"})
        self.assertTrue(all(n["kind"] == "bot" for n in nhis))
        self.assertNotIn("U00HUMAN", ids)
        self.assertNotIn("USLACKBOT", ids)

    def test_same_pattern_no_yaml_for_atlassian(self):
        estate, _ = discover_from_recorded(REPO / "sandbox/probe/idp/atlassian_pages.json")
        assert estate is not None
        nhis = _extract_nhis(estate.to_probe_blob())
        vendor = {"vendor": "Atlassian", "slug": "atlassian", "tier": "high", "nhis": []}
        merged = discover_nhis(
            vendor, type("P", (), {"ran": True, "nhis": nhis})(), portfolio=[vendor],
        )
        self.assertGreaterEqual(len(merged), 2)
        self.assertTrue(all(n.get("source") == "observed" for n in merged))


class TestTokenLifecycle(unittest.TestCase):
    def test_auth0_client_credentials_cached_then_reminted(self):
        from vra.idp import TokenVault, _live_token

        clock = {"t": 0.0}
        vault = TokenVault(clock=lambda: clock["t"])
        transport = MemoryTransport()
        transport.add(
            "POST",
            f"{AUTH0}/oauth/token",
            {"access_token": "tok-1", "expires_in": 100},
        )
        transport.add(
            "POST",
            f"{AUTH0}/oauth/token",
            {"access_token": "tok-2", "expires_in": 100},
        )
        block = {
            "client_id_env": "TEST_A0_ID",
            "client_secret_env": "TEST_A0_SEC",
        }
        import os

        os.environ["TEST_A0_ID"] = "cid"
        os.environ["TEST_A0_SEC"] = "csec"
        try:
            first, err, meta = _live_token(block, "auth0", transport, AUTH0, vault=vault)
            self.assertIsNone(err)
            self.assertEqual(first, "tok-1")
            self.assertTrue(meta["remintable"])
            second, _, _ = _live_token(block, "auth0", transport, AUTH0, vault=vault)
            self.assertEqual(second, "tok-1")  # cache hit
            clock["t"] = 50  # still inside 100-60 skew? 50+60=110 > 100, expired
            third, _, _ = _live_token(block, "auth0", transport, AUTH0, vault=vault)
            self.assertEqual(third, "tok-2")
        finally:
            os.environ.pop("TEST_A0_ID", None)
            os.environ.pop("TEST_A0_SEC", None)

    def test_auth0_401_remints_and_retries(self):
        from vra.idp import TOKEN_VAULT, discover_from_vendor

        TOKEN_VAULT._items.clear()
        transport = MemoryTransport()
        transport.add(
            "POST",
            f"{AUTH0}/oauth/token",
            {"access_token": "stale", "expires_in": 86400},
        )
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/clients?include_totals=true&page=0&per_page=100",
            {"error": "expired"},
            status=401,
        )
        transport.add(
            "POST",
            f"{AUTH0}/oauth/token",
            {"access_token": "fresh", "expires_in": 86400},
        )
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/clients?include_totals=true&page=0&per_page=100",
            {"total": 1, "clients": [
                {"client_id": "c1", "name": "Alive", "app_type": "non_interactive"}
            ]},
        )
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/client-grants?include_totals=true&page=0&per_page=100",
            {"total": 0, "client_grants": []},
        )
        import os

        os.environ["TEST_A0_ID2"] = "cid"
        os.environ["TEST_A0_SEC2"] = "csec"
        try:
            vendor = {
                "slug": "auth0-tenant",
                "probe": {
                    "provider": "auth0",
                    "base_url": AUTH0,
                    "client_id_env": "TEST_A0_ID2",
                    "client_secret_env": "TEST_A0_SEC2",
                    "mode": "live",
                },
            }
            estate, err = discover_from_vendor(
                vendor, RunConfig(offline=False), transport=transport
            )
            self.assertIsNone(err)
            assert estate is not None
            self.assertEqual(len(estate.applications), 1)
            self.assertEqual(estate.applications[0]["id"], "c1")
        finally:
            os.environ.pop("TEST_A0_ID2", None)
            os.environ.pop("TEST_A0_SEC2", None)
            TOKEN_VAULT._items.clear()

    def test_static_auth0_token_warns_it_cannot_remint(self):
        from vra.idp import TOKEN_VAULT, discover_from_vendor

        TOKEN_VAULT._items.clear()
        transport = MemoryTransport()
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/clients?include_totals=true&page=0&per_page=100",
            {"total": 0, "clients": []},
        )
        transport.add(
            "GET",
            f"{AUTH0}/api/v2/client-grants?include_totals=true&page=0&per_page=100",
            {"total": 0, "client_grants": []},
        )
        import os

        os.environ["AUTH0_MGMT_TOKEN"] = "static-24h"
        try:
            vendor = {
                "slug": "auth0-tenant",
                "probe": {"provider": "auth0", "base_url": AUTH0, "mode": "live"},
            }
            estate, err = discover_from_vendor(
                vendor, RunConfig(offline=False), transport=transport
            )
            self.assertIsNone(err)
            assert estate is not None
            self.assertTrue(any("24h" in w or "expire" in w for w in estate.warnings))
        finally:
            os.environ.pop("AUTH0_MGMT_TOKEN", None)


class TestRateLimitBackoff(unittest.TestCase):
    def test_429_then_200_returns_the_page(self):
        transport = MemoryTransport()
        transport.add(
            "GET", f"{OKTA}/api/v1/apps?limit=200", None,
            headers={"Retry-After": "0"}, status=429,
        )
        transport.add("GET", f"{OKTA}/api/v1/apps?limit=200", [_okta_app(1)])
        transport.add("GET", f"{OKTA}/api/v1/api-tokens?limit=200", [])
        estate = discover_okta(
            base_url=OKTA, token="ssws", transport=transport,
            fetch_grants=False, fetch_tokens=True,
        )
        self.assertIsNone(estate.error)
        self.assertEqual(len(estate.applications), 1)

    def test_persistent_429_keeps_partial_list(self):
        apps = [_okta_app(i) for i in range(3)]
        transport = MemoryTransport()
        transport.add(
            "GET", f"{OKTA}/api/v1/apps?limit=2", apps[:2],
            headers={"Link": f'<{OKTA}/api/v1/apps?after={apps[1]["id"]}&limit=2>; rel="next"'},
        )
        for _ in range(6):
            transport.add(
                "GET",
                f"{OKTA}/api/v1/apps?after={apps[1]['id']}&limit=2",
                None,
                headers={"Retry-After": "0"},
                status=429,
            )
        estate = discover_okta(
            base_url=OKTA, token="ssws", transport=transport,
            page_limit=2, fetch_grants=False, fetch_tokens=False,
        )
        self.assertTrue(estate.truncated)
        self.assertEqual(len(estate.applications), 2)
        self.assertTrue(any("rate-limited" in w for w in estate.warnings))


class TestCrossPlaneDedup(unittest.TestCase):
    def test_same_name_on_idp_and_vendor_is_one_identity(self):
        from vra.nhi import link_cross_plane

        okta_row = {
            "id": "0oa2loopworkspace2",
            "app_id": "0oa2loopworkspace2",
            "name": "Loop Assist",
            "principal": "loop-assist",
            "idp": "okta",
            "source": "observed",
            "declared": False,
            "cross_vendor": False,
        }
        slack_row = {
            "id": "B0ASSIST",
            "app_id": "B0ASSIST",
            "name": "Loop Assist",
            "principal": "loop-assist",
            "idp": "slack",
            "source": "observed",
            "declared": False,
        }
        by_vendor = {
            "aegis-identity-cloud": [okta_row],
            "loop-workspace": [slack_row],
        }
        link_cross_plane(by_vendor)
        self.assertTrue(okta_row["cross_plane"])
        self.assertTrue(slack_row["cross_plane"])
        self.assertIn("loop-workspace", okta_row["also_seen_on"])
        self.assertTrue(okta_row["declared"], "home-plane observation satisfies NHI-06")
        self.assertEqual(okta_row["home_vendor"], "loop-workspace")

    def test_unrelated_names_are_not_merged(self):
        from vra.nhi import link_cross_plane

        a = {"id": "a", "name": "Payroll Sync", "idp": "okta", "declared": False}
        b = {"id": "b", "name": "Rovo Writer service", "idp": "atlassian", "declared": False}
        link_cross_plane({"idp": [a], "atlassian": [b]})
        self.assertFalse(a.get("cross_plane"))
        self.assertFalse(b.get("cross_plane"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
