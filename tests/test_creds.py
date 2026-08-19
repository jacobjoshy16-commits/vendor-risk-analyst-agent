"""Keychain credentials, entitlement diffs, and the LLM trust boundary."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.creds import (  # noqa: E402
    inspect_scopes,
    jwt_scopes,
    listed_connectors,
    reset_memory_keyring,
    resolve_secrets,
    set_secret,
    use_memory_keyring,
    delete_connector,
    get_secret,
)
from vra.llm import SecretInPromptError, assert_prompt_clean, call_json  # noqa: E402
from vra.nhi import NHIInventory, entitlement_diff, entitlement_hash  # noqa: E402
from vra.config import RunConfig  # noqa: E402


class TestKeychainRoundTrip(unittest.TestCase):
    def setUp(self):
        use_memory_keyring()

    def tearDown(self):
        reset_memory_keyring()

    def test_set_get_list_rm(self):
        set_secret("okta", "api_token", "ssws-secret-value")
        self.assertEqual(get_secret("okta", "api_token"), "ssws-secret-value")
        listed = listed_connectors()
        self.assertIn("okta", listed)
        self.assertIn("api_token", listed["okta"])
        dumped = json.dumps(listed)
        self.assertNotIn("ssws-secret-value", dumped)
        delete_connector("okta")
        self.assertIsNone(get_secret("okta", "api_token"))
        self.assertNotIn("okta", listed_connectors())

    def test_resolve_prefers_keychain_over_env(self):
        import os

        os.environ["OKTA_API_TOKEN"] = "from-env"
        try:
            set_secret("okta", "api_token", "from-keychain")
            secrets, err, used_env = resolve_secrets("okta", allow_env=True)
            self.assertIsNone(err)
            self.assertFalse(used_env)
            self.assertEqual(secrets["api_token"], "from-keychain")
        finally:
            os.environ.pop("OKTA_API_TOKEN", None)

    def test_env_fallback_requires_flag(self):
        import os

        os.environ["OKTA_API_TOKEN"] = "from-env"
        try:
            secrets, err, used_env = resolve_secrets("okta", allow_env=False)
            self.assertTrue(err)
            self.assertEqual(secrets, {})
            secrets, err, used_env = resolve_secrets("okta", allow_env=True)
            self.assertIsNone(err)
            self.assertTrue(used_env)
            self.assertEqual(secrets["api_token"], "from-env")
        finally:
            os.environ.pop("OKTA_API_TOKEN", None)


class TestWriteScopeWarning(unittest.TestCase):
    def test_jwt_with_write_scope_warns(self):
        payload = base64_jwt({"scope": "okta.users.read okta.users.manage"})
        info = inspect_scopes("okta", {"api_token": payload})
        self.assertIn("okta.users.manage", info["write_scopes"])
        self.assertIn("WARNING", info["warning"] or "")
        self.assertIn("read-only", (info["warning"] or "").lower())

    def test_opaque_admin_token_warns_without_inventing_scopes(self):
        info = inspect_scopes("okta", {"api_token": "00Tplaintextadmintoken"})
        self.assertEqual(info["scopes"], [])
        self.assertTrue(info["opaque_admin"])
        self.assertIn("WARNING", info["warning"] or "")

    def test_read_only_jwt_is_quiet(self):
        payload = base64_jwt({"scope": "okta.users.read okta.logs.read"})
        info = inspect_scopes("auth0", {"management_token": payload})
        self.assertEqual(info["write_scopes"], [])
        self.assertIsNone(info["warning"])


def base64_jwt(claims: dict) -> str:
    import base64

    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("ascii")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{b64({'alg': 'none'})}.{b64(claims)}.x"


class TestEntitlementDiff(unittest.TestCase):
    def test_hash_is_order_independent(self):
        self.assertEqual(
            entitlement_hash(["b", "a"]),
            entitlement_hash(["a", "b"]),
        )
        self.assertNotEqual(entitlement_hash(["a"]), entitlement_hash(["a", "b"]))

    def test_upsert_emits_change_when_scopes_change(self):
        tmp = Path(tempfile.mkdtemp()) / "nhis.json"
        inv = NHIInventory(path=tmp)
        rec, ev = inv.upsert("v", {
            "id": "bot-1", "app_id": "bot-1", "name": "Agent",
            "kind": "agent_principal", "scopes": ["users.read"],
        })
        self.assertIsNone(ev)
        self.assertEqual(rec["type"], "agent_principal")
        self.assertEqual(rec["last_seen"], date.today().isoformat())
        rec2, ev2 = inv.upsert("v", {
            "id": "bot-1", "app_id": "bot-1", "name": "Agent",
            "kind": "agent_principal", "scopes": ["users.read", "users.manage"],
        })
        self.assertIsNotNone(ev2)
        assert ev2 is not None
        self.assertEqual(ev2["kind"], "entitlement_change")
        self.assertEqual(ev2["added_scopes"], ["users.manage"])
        self.assertEqual(ev2["removed_scopes"], [])
        self.assertTrue(ev2["gained_write_scope"])

    def test_upsert_silent_when_scopes_unchanged(self):
        tmp = Path(tempfile.mkdtemp()) / "nhis.json"
        inv = NHIInventory(path=tmp)
        inv.upsert("v", {"id": "bot-1", "name": "Agent", "scopes": ["users.read"]})
        _, ev = inv.upsert("v", {"id": "bot-1", "name": "Agent", "scopes": ["users.read"]})
        self.assertIsNone(ev)
        self.assertEqual(entitlement_diff(["a"], ["a"]), {"added_scopes": [], "removed_scopes": []})


class TestLlmTrustBoundary(unittest.TestCase):
    def test_assert_rejects_bearer_and_ssws(self):
        with self.assertRaises(SecretInPromptError):
            assert_prompt_clean("Authorization: SSWS 00Tabcdefghijklmnop")
        with self.assertRaises(SecretInPromptError):
            assert_prompt_clean("Authorization: Bearer " + "a" * 24)
        with self.assertRaises(SecretInPromptError):
            assert_prompt_clean("xoxb-123456789012-abcdefgh")
        assert_prompt_clean("scopes: okta.users.read, okta.users.manage")  # names are fine

    def test_call_json_never_forwards_a_secret(self):
        from vra.triage import _schema_check

        with self.assertRaises(SecretInPromptError):
            call_json(
                system="you are a triage helper",
                prompt="TASK: AI_RELEVANCE_TRIAGE\nAuthorization: SSWS supersecrettokenvalue",
                cfg=RunConfig(offline=True),
                schema_check=_schema_check,
                task="ai_relevance_triage",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
