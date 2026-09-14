"""Last-known data must never read as current data.

A stored API token has no expiry in this tool: it is used until someone removes
it. So the interesting failure is not "the token expired" but "the token was
revoked and nobody noticed" — the tenant stops answering, the inventory freezes,
and every later cycle reports a confident picture of a tenant it can no longer
see. These tests pin the signals that make that impossible to miss.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import RunConfig  # noqa: E402
from vra.nhi import NHIInventory, is_stale, staleness_days  # noqa: E402
from vra.register import FindingStore  # noqa: E402
from vra.report import build_report  # noqa: E402


def _identity(**over):
    row = {
        "id": "0oa1payroll", "name": "Payroll Sync", "principal": "payroll-sync",
        "kind": "oauth_app", "scopes": ["okta.users.manage"],
        "write_scopes": ["okta.users.manage"], "vendor_name": "Okta",
    }
    row.update(over)
    return row


class TestStalenessMeasurement(unittest.TestCase):
    def test_an_identity_seen_today_is_current(self):
        row = {"last_seen": date.today().isoformat()}
        self.assertEqual(staleness_days(row), 0)
        self.assertFalse(is_stale(row))

    def test_age_is_counted_from_last_seen(self):
        row = {"last_seen": (date.today() - timedelta(days=9)).isoformat()}
        self.assertEqual(staleness_days(row), 9)
        self.assertTrue(is_stale(row))

    def test_the_threshold_is_configurable(self):
        row = {"last_seen": (date.today() - timedelta(days=5)).isoformat()}
        self.assertTrue(is_stale(row, after_days=2))
        self.assertFalse(is_stale(row, after_days=30))

    def test_an_explicit_mark_wins_over_the_clock(self):
        """A probe that failed this cycle is stale immediately, not in two days."""
        row = {"last_seen": date.today().isoformat(), "stale": True}
        self.assertTrue(is_stale(row))

    def test_a_missing_or_unparseable_last_seen_does_not_crash(self):
        for value in (None, "", "not-a-date", 12345):
            with self.subTest(value=value):
                self.assertEqual(staleness_days({"last_seen": value}), 0)


class TestInventoryMarksHeldIdentities(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.inv = NHIInventory(Path(self.tmp.name) / "nhis.json")

    def test_marking_records_the_reason(self):
        self.inv.upsert_many("okta", [_identity()])
        rows = self.inv.mark_stale("okta", reason="okta apps list failed: 401")

        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["stale"])
        self.assertIn("401", rows[0]["stale_reason"])
        self.assertTrue(is_stale(rows[0]))

    def test_the_identity_is_kept_not_deleted(self):
        """Absence of evidence is not evidence the identity was removed."""
        self.inv.upsert_many("okta", [_identity()])
        self.inv.mark_stale("okta", reason="tenant not reached")

        self.assertEqual(len(self.inv.for_vendor("okta")), 1)
        self.assertEqual(self.inv.for_vendor("okta")[0]["write_scopes"],
                         ["okta.users.manage"])

    def test_only_the_named_vendor_is_marked(self):
        self.inv.upsert_many("okta", [_identity()])
        self.inv.upsert_many("entra", [_identity(id="sp-other", name="Other")])
        self.inv.mark_stale("okta", reason="tenant not reached")

        self.assertTrue(self.inv.for_vendor("okta")[0]["stale"])
        self.assertFalse(self.inv.for_vendor("entra")[0].get("stale"))

    def test_a_later_successful_probe_clears_the_mark(self):
        self.inv.upsert_many("okta", [_identity()])
        self.inv.mark_stale("okta", reason="tenant not reached")
        self.assertTrue(self.inv.for_vendor("okta")[0]["stale"])

        self.inv.upsert_many("okta", [_identity()])
        self.assertFalse(self.inv.for_vendor("okta")[0].get("stale"),
                         "re-observing an identity must make it current again")


class TestReportSaysWhatIsHeld(unittest.TestCase):
    def _ctx(self, nhis, failed=()):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return {
            "vendors": [{"vendor": "Okta", "slug": "okta", "tier": "high"}],
            "findings": [], "gaps": [], "triages": [], "probes": [], "parses": [],
            "nhis": nhis, "new_ids": set(), "closed": [],
            "store": FindingStore(Path(tmp.name) / "f.json"),
            "backend": "offline-heuristic", "events": [],
            "failed_vendors": list(failed),
        }

    def test_an_unreached_tenant_is_named_as_such(self):
        report = build_report(
            self._ctx([], failed=[{"vendor": "okta", "vendor_name": "Okta",
                                   "error": "okta apps list failed: 401",
                                   "kind": "probe"}]),
            RunConfig(dry_run=True),
        )
        self.assertIn("INCOMPLETE ASSESSMENT", report)
        self.assertIn("tenant not reached", report)
        self.assertIn("401", report)
        self.assertIn("revoked or expired API token", report)

    def test_a_crash_and_an_unreached_tenant_read_differently(self):
        report = build_report(
            self._ctx([], failed=[
                {"vendor": "a", "vendor_name": "Crashed", "error": "boom"},
                {"vendor": "b", "vendor_name": "Unreached", "error": "401",
                 "kind": "probe"},
            ]),
            RunConfig(dry_run=True),
        )
        self.assertIn("assessment failed", report)
        self.assertIn("tenant not reached", report)

    def test_stale_rows_are_counted_and_flagged(self):
        stale = _identity(vendor="okta", last_seen="2020-01-01", stale=True,
                          stale_reason="tenant not reached", stale_days=9)
        fresh = _identity(id="0oa2", name="Fresh App", vendor="okta",
                          last_seen=date.today().isoformat())
        report = build_report(self._ctx([stale, fresh]), RunConfig(dry_run=True))

        self.assertIn("1 of 2 identities below are LAST KNOWN", report)
        self.assertIn("**stale 9d**", report)
        self.assertIn("Why an identity goes stale", report)
        self.assertIn("tenant not reached", report)

    def test_a_fully_current_inventory_carries_no_warning(self):
        fresh = _identity(vendor="okta", last_seen=date.today().isoformat())
        report = build_report(self._ctx([fresh]), RunConfig(dry_run=True))
        self.assertNotIn("LAST KNOWN", report)
        self.assertNotIn("stale", report.split("## 9.")[0])

    def test_the_table_shows_when_each_identity_was_last_seen(self):
        fresh = _identity(vendor="okta", last_seen="2026-09-10")
        report = build_report(self._ctx([fresh]), RunConfig(dry_run=True))
        self.assertIn("Last seen", report)
        self.assertIn("2026-09-10", report)


class TestAnUnreachedTenantFailsTheRun(unittest.TestCase):
    """The regression: a revoked key used to exit 0 with a confident report."""

    def setUp(self):
        for name in ("data", "out", "pending_review"):
            shutil.rmtree(REPO / name, ignore_errors=True)
        self.addCleanup(lambda: [shutil.rmtree(REPO / n, ignore_errors=True)
                                 for n in ("data", "out", "pending_review")])

    def _work(self, vendor):
        from vra.collect import VendorWork

        return VendorWork(
            slug=vendor["slug"], vendor=vendor,
            probe_failed=True,
            probe_error="okta apps list failed: 401",
            log_line="0 NHI(s)",
            notes=["probe did not run: okta apps list failed: 401"],
        )

    def test_exit_code_is_not_zero(self):
        from unittest import mock

        from vra import cli

        vendor = {"vendor": "Okta", "slug": "okta", "tier": "high",
                  "probe": {"enabled": True}, "watch": {}, "ai_surface": []}
        with mock.patch.object(cli, "load_vendors", return_value=[vendor]), \
             mock.patch("vra.collect.collect_all", return_value=[self._work(vendor)]):
            with redirect_stdout(io.StringIO()):
                result = cli.assess(RunConfig(offline=True, dry_run=True))

        self.assertEqual(result.vendors_failed, 1)
        self.assertEqual(result.exit_code, 2,
                         "an unreached tenant must not report success")
        self.assertEqual(result.failed_vendors[0]["kind"], "probe")
        self.assertIn("401", result.error or "")

    def test_the_summary_json_records_the_run_as_incomplete(self):
        from unittest import mock

        from vra import cli

        vendor = {"vendor": "Okta", "slug": "okta", "tier": "high",
                  "probe": {"enabled": True}, "watch": {}, "ai_surface": []}
        with mock.patch.object(cli, "load_vendors", return_value=[vendor]), \
             mock.patch("vra.collect.collect_all", return_value=[self._work(vendor)]):
            with redirect_stdout(io.StringIO()):
                cli.assess(RunConfig(offline=True))

        blob = json.loads((REPO / "out" / "latest.json").read_text(encoding="utf-8"))
        self.assertFalse(blob["complete"])
        self.assertEqual(blob["failed_vendors"][0]["kind"], "probe")


if __name__ == "__main__":
    unittest.main()
