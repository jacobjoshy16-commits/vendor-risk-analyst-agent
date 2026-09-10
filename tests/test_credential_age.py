"""The tool's own token is a non-human credential and is held to NHI-03.

NHI-03 asks whether a vendor rotates its non-human credentials at least
annually. The token this tool stores to read a tenant is exactly such a
credential, and it has no expiry — it is used until someone replaces it. So its
age is tracked and reported rather than exempted.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
import unittest.mock
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import creds  # noqa: E402
from vra.creds import (  # noqa: E402
    ageing_credentials,
    credential_age_days,
    delete_connector,
    get_secret,
    listed_connectors,
    reset_memory_keyring,
    set_secret,
    stored_at,
    use_memory_keyring,
)


def _backdate(connector: str, field: str, days: int) -> None:
    blob = creds._read_index_blob()
    when = datetime.now(timezone.utc) - timedelta(days=days)
    blob["connectors"][connector]["stored_at"][field] = when.isoformat()
    creds._save_index_blob(blob)


class TestCredentialAge(unittest.TestCase):
    def setUp(self):
        use_memory_keyring()
        self.addCleanup(reset_memory_keyring)

    def test_a_freshly_stored_secret_is_zero_days_old(self):
        set_secret("okta", "api_token", "secret-value")
        self.assertEqual(credential_age_days("okta", "api_token"), 0)
        self.assertTrue(stored_at("okta", "api_token"))

    def test_age_grows_with_the_clock(self):
        set_secret("okta", "api_token", "secret-value")
        _backdate("okta", "api_token", 400)
        self.assertEqual(credential_age_days("okta", "api_token"), 400)

    def test_rewriting_a_secret_restarts_its_clock(self):
        """That is what rotation is."""
        set_secret("okta", "api_token", "old-value")
        _backdate("okta", "api_token", 400)
        self.assertEqual(credential_age_days("okta", "api_token"), 400)

        set_secret("okta", "api_token", "rotated-value")
        self.assertEqual(credential_age_days("okta", "api_token"), 0)
        self.assertEqual(get_secret("okta", "api_token"), "rotated-value")

    def test_an_unstored_secret_has_no_age(self):
        self.assertIsNone(credential_age_days("okta", "api_token"))

    def test_ageing_credentials_lists_only_those_past_the_limit(self):
        set_secret("okta", "api_token", "a")
        set_secret("entra", "api_token", "b")
        _backdate("okta", "api_token", 400)

        rows = ageing_credentials(max_age_days=365)
        self.assertEqual([r["connector"] for r in rows], ["okta"])
        self.assertEqual(rows[0]["age_days"], 400)

    def test_the_limit_is_configurable(self):
        set_secret("okta", "api_token", "a")
        _backdate("okta", "api_token", 100)
        self.assertEqual(ageing_credentials(max_age_days=365), [])
        self.assertEqual(len(ageing_credentials(max_age_days=90)), 1)

    def test_oldest_first(self):
        for connector, days in (("okta", 400), ("entra", 900), ("slack", 500)):
            set_secret(connector, "api_token", "x")
            _backdate(connector, "api_token", days)
        self.assertEqual([r["connector"] for r in ageing_credentials(365)],
                         ["entra", "slack", "okta"])


class TestIndexUpgrade(unittest.TestCase):
    """The names-only index must keep working, just without ages."""

    def setUp(self):
        self.backend = use_memory_keyring()
        self.addCleanup(reset_memory_keyring)

    def _write_v1(self, payload):
        self.backend.set_password(creds.INDEX_SERVICE, creds.INDEX_USER,
                                  json.dumps(payload))

    def test_a_v1_index_still_lists_its_connectors(self):
        self._write_v1({"okta": ["api_token"], "entra": ["api_token"]})
        self.assertEqual(listed_connectors(),
                         {"okta": ["api_token"], "entra": ["api_token"]})

    def test_a_v1_entry_has_unknown_age_rather_than_a_wrong_one(self):
        self._write_v1({"okta": ["api_token"]})
        self.assertIsNone(credential_age_days("okta", "api_token"))
        self.assertEqual(ageing_credentials(max_age_days=1), [],
                         "an unknown age must not be reported as overdue")

    def test_writing_after_an_upgrade_starts_tracking(self):
        self._write_v1({"okta": ["api_token"]})
        set_secret("okta", "api_token", "new-value")
        self.assertEqual(credential_age_days("okta", "api_token"), 0)

    def test_a_corrupt_index_does_not_crash(self):
        self.backend.set_password(creds.INDEX_SERVICE, creds.INDEX_USER, "{not json")
        self.assertEqual(listed_connectors(), {})


class TestForgettingIsComplete(unittest.TestCase):
    def setUp(self):
        use_memory_keyring()
        self.addCleanup(reset_memory_keyring)

    def test_removing_a_connector_drops_its_age_record_too(self):
        set_secret("okta", "api_token", "a")
        self.assertTrue(stored_at("okta", "api_token"))

        delete_connector("okta")
        self.assertEqual(listed_connectors(), {})
        self.assertIsNone(stored_at("okta", "api_token"))
        self.assertIsNone(get_secret("okta", "api_token"))

    def test_removing_one_connector_leaves_the_others(self):
        set_secret("okta", "api_token", "a")
        set_secret("entra", "api_token", "b")
        delete_connector("okta")
        self.assertEqual(listed_connectors(), {"entra": ["api_token"]})
        self.assertIsNotNone(stored_at("entra", "api_token"))


class TestTheIndexNeverHoldsASecret(unittest.TestCase):
    def setUp(self):
        self.backend = use_memory_keyring()
        self.addCleanup(reset_memory_keyring)

    def test_only_names_and_timestamps_are_indexed(self):
        set_secret("okta", "api_token", "SUPER-SECRET-TOKEN-VALUE")
        raw = self.backend.get_password(creds.INDEX_SERVICE, creds.INDEX_USER)
        self.assertNotIn("SUPER-SECRET-TOKEN-VALUE", raw)
        self.assertIn("api_token", raw)


class TestTheRunSaysSo(unittest.TestCase):
    def setUp(self):
        use_memory_keyring()
        self.addCleanup(reset_memory_keyring)

    def test_creds_list_flags_an_overdue_token(self):
        from vra.creds import main as creds_main

        set_secret("okta", "api_token", "a")
        _backdate("okta", "api_token", 400)

        buf = io.StringIO()
        with redirect_stdout(buf):
            creds_main(["list"])
        out = buf.getvalue()

        self.assertIn("400d", out)
        self.assertIn("ROTATE", out)
        self.assertIn("NHI-03", out)

    def test_creds_list_is_quiet_when_everything_is_fresh(self):
        from vra.creds import main as creds_main

        set_secret("okta", "api_token", "a")
        buf = io.StringIO()
        with redirect_stdout(buf):
            creds_main(["list"])
        self.assertNotIn("ROTATE", buf.getvalue())

    def test_an_unreadable_keychain_does_not_fail_a_run(self):
        """A run must survive a keychain it cannot open."""
        from vra import cli

        with unittest.mock.patch("vra.creds.ageing_credentials",
                                 side_effect=RuntimeError("keychain locked")):
            from vra.config import RunConfig

            with redirect_stdout(io.StringIO()):
                result = cli.assess(RunConfig(offline=True, dry_run=True,
                                              snapshot_version="v1"))
        self.assertIn(result.exit_code, (0, 1))


if __name__ == "__main__":
    unittest.main()
