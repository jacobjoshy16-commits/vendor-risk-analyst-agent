"""Two defects found by an end-to-end run on a VM, and how they compounded.

1. A tenant probe that did not run closed the AIV-* findings resting on its
   evidence, as "condition no longer observed" — and restoring the probe never
   reopened them, because upsert preserves state. The existing guard covered
   only family == "nhi".

2. A missing local model set cfg.offline, which is also the kill-switch for the
   tenant probe, the artifact fetch and live discovery. So losing Ollama
   silently stopped the vendor API being read — which then triggered (1).
"""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import RunConfig  # noqa: E402
from vra.probe import run_probe  # noqa: E402
from vra.register import FindingStore  # noqa: E402


def _finding(fid="AIV-07-abc", family="aiv", state="open", **over):
    row = {
        "id": fid, "kind": "finding", "family": family, "vendor": "acme",
        "vendor_name": "Acme", "feature": "Copilot", "control_id": "AIV-07",
        "severity": "critical", "observed": {}, "state": state,
        "citation": "NIST SP 800-53 AC-3",
    }
    row.update(over)
    return row


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = FindingStore(Path(self.tmp.name) / "findings.json")


class TestAnUnverifiedVendorKeepsEveryFinding(_StoreCase):
    def test_holding_a_vendor_out_of_scope_protects_all_families(self):
        """The guard used to cover NHI-* only, so AIV-* findings closed."""
        self.store.upsert(_finding("AIV-07-abc", family="aiv"))
        self.store.upsert(_finding("NHI-01-def", family="nhi", control_id="NHI-01"))

        # A vendor whose probe did not run is held out of reconciliation.
        closed = self.store.reconcile(seen_ids=set(), vendor_slugs=set(),
                                      cfg=RunConfig(dry_run=True))
        self.assertEqual(closed, [])
        self.assertEqual(self.store.get("AIV-07-abc")["state"], "open")
        self.assertEqual(self.store.get("NHI-01-def")["state"], "open")

    def test_a_genuinely_resolved_finding_still_closes(self):
        """The fix must not make auto-close impossible."""
        self.store.upsert(_finding("AIV-07-abc"))
        closed = self.store.reconcile(seen_ids=set(), vendor_slugs={"acme"},
                                      cfg=RunConfig(dry_run=True))
        self.assertEqual(len(closed), 1)
        self.assertEqual(self.store.get("AIV-07-abc")["state"], "closed")


class TestAClosedFindingReopens(_StoreCase):
    def test_re_observing_a_closed_finding_reopens_it(self):
        self.store.upsert(_finding("AIV-07-abc"))
        self.store.reconcile(set(), {"acme"}, RunConfig(dry_run=True))
        self.assertEqual(self.store.get("AIV-07-abc")["state"], "closed")

        stored, is_new = self.store.upsert(_finding("AIV-07-abc"))
        self.assertFalse(is_new)
        self.assertEqual(stored["state"], "open", "the condition came back")
        self.assertTrue(stored["reopened_date"])
        self.assertNotIn("closed_date", stored)
        self.assertNotIn("closure_reason", stored)

    def test_the_reopen_is_recorded_in_the_history(self):
        self.store.upsert(_finding("AIV-07-abc"))
        self.store.reconcile(set(), {"acme"}, RunConfig(dry_run=True))
        self.store.upsert(_finding("AIV-07-abc"))

        notes = [h["note"] for h in self.store.get("AIV-07-abc")["state_history"]]
        self.assertIn("reopened: condition observed again", notes)

    def test_an_accepted_risk_is_a_human_decision_and_is_not_touched(self):
        stored, _ = self.store.upsert(_finding("AIV-07-abc"))
        stored["state"] = "accepted_risk"
        again, _ = self.store.upsert(_finding("AIV-07-abc"))
        self.assertEqual(again["state"], "accepted_risk")
        self.assertNotIn("reopened_date", again)

    def test_an_open_finding_is_not_marked_as_reopened(self):
        self.store.upsert(_finding("AIV-07-abc"))
        again, _ = self.store.upsert(_finding("AIV-07-abc"))
        self.assertEqual(again["state"], "open")
        self.assertNotIn("reopened_date", again)


class TestAutoClosureLeavesATrail(_StoreCase):
    def test_closing_a_finding_records_an_event(self):
        """A critical must not just vanish from the report."""
        self.store.upsert(_finding("AIV-07-abc"))
        self.store.reconcile(set(), {"acme"}, RunConfig(dry_run=True))

        events = [e for e in self.store.events if e["kind"] == "finding_auto_closed"]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["finding_id"], "AIV-07-abc")
        self.assertEqual(event["control_id"], "AIV-07")
        self.assertEqual(event["severity"], "critical")
        self.assertIn("no longer observed", event["reason"])
        self.assertTrue(event["timestamp"])

    def test_no_event_when_nothing_closes(self):
        self.store.upsert(_finding("AIV-07-abc"))
        self.store.reconcile({"AIV-07-abc"}, {"acme"}, RunConfig(dry_run=True))
        self.assertEqual(
            [e for e in self.store.events if e["kind"] == "finding_auto_closed"], []
        )


class TestAMissingModelDoesNotDisableTheNetwork(unittest.TestCase):
    VENDOR = {
        "vendor": "Acme", "slug": "acme",
        "probe": {"enabled": True, "mode": "live", "provider": "okta",
                  "base_url": "https://acme.okta.com"},
    }

    def test_offline_still_means_touch_no_network(self):
        result = run_probe(self.VENDOR, RunConfig(offline=True))
        self.assertFalse(result.ran)
        self.assertIn("offline mode", result.error)

    def test_a_missing_model_still_attempts_the_probe(self):
        """It may fail for a real reason — but not because Ollama is down."""
        result = run_probe(self.VENDOR, RunConfig(llm_unavailable=True))
        self.assertFalse(result.ran)
        self.assertNotIn("offline mode", result.error or "",
                         "a missing model must not read as 'no network'")

    def test_the_two_flags_are_independent(self):
        self.assertFalse(RunConfig(llm_unavailable=True).offline)
        self.assertFalse(RunConfig(llm_unavailable=True).llm_enabled)
        self.assertFalse(RunConfig(offline=True).llm_enabled)
        self.assertTrue(RunConfig().llm_enabled)

    def test_the_heuristic_backend_is_chosen_when_the_model_is_gone(self):
        from vra.llm import get_backend

        self.assertEqual(get_backend(RunConfig(llm_unavailable=True)).name,
                         "offline-heuristic")

    def test_probe_ollama_does_not_retry_a_model_already_known_absent(self):
        from vra.llm import probe_ollama

        self.assertFalse(probe_ollama(RunConfig(llm_unavailable=True)))

    def test_the_report_says_which_of_the_two_it_was(self):
        from vra.report import build_report

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ctx = {
            "vendors": [], "findings": [], "gaps": [], "triages": [], "probes": [],
            "parses": [], "nhis": [], "new_ids": set(), "closed": [],
            "store": FindingStore(Path(tmp.name) / "f.json"),
            "backend": "offline-heuristic", "events": [],
        }
        no_model = build_report(ctx, RunConfig(llm_unavailable=True, dry_run=True))
        self.assertIn("network live but no local model", no_model)

        no_network = build_report(ctx, RunConfig(offline=True, dry_run=True))
        self.assertIn("offline (no network)", no_network)


class TestTheTwoDefectsTogether(unittest.TestCase):
    """The compounding path the VM run actually hit."""

    def test_losing_the_model_does_not_close_a_critical(self):
        import shutil
        from unittest import mock

        from vra import cli

        for name in ("data", "out", "pending_review"):
            shutil.rmtree(REPO / name, ignore_errors=True)
        self.addCleanup(lambda: [shutil.rmtree(REPO / n, ignore_errors=True)
                                 for n in ("data", "out", "pending_review")])

        # Cycle 1: everything works, criticals are raised.
        with redirect_stdout(io.StringIO()):
            first = cli.assess(RunConfig(offline=True, snapshot_version="v2"))
        self.assertGreaterEqual(first.critical, 1)

        # Cycle 2: the model is gone. Nothing about the tenant changed.
        with mock.patch("vra.llm.probe_ollama", return_value=False):
            with redirect_stdout(io.StringIO()):
                second = cli.assess(RunConfig(snapshot_version="v2"))

        self.assertEqual(second.critical, first.critical,
                         "a missing model must not change the score")
        self.assertEqual(second.closed, 0, "and must not close anything")


if __name__ == "__main__":
    unittest.main()
