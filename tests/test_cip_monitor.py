"""Continuous monitoring: lifecycle, alerting, and the deployment gate.

The question these answer is whether the tool does anything, as opposed to
recomputing a report. A monitor has to remember, has to notice what changed,
and has to tell someone — and it has to stay quiet the rest of the time, or the
channel gets muted and the one alert that mattered is missed.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import cipalert  # noqa: E402
from vra.cipstate import STATE_CLOSED, STATE_OPEN, FindingStore  # noqa: E402

AS_OF = date(2026, 9, 21)


def record(fid="F1", control="CIP-31", severity="high", due="2026-10-21", **observed):
    return {
        "id": fid,
        "kind": "finding",
        "control_id": control,
        "citation": "CIP-003-9 R2 Part Attachment 1 Section 6",
        "severity": severity,
        "feature": f"SESS-{fid}",
        "vendor_name": "Cascade Grid Controls",
        "control_question": "Is a documented process in place to mitigate the risks of that access?",
        "observed": observed or {"low_impact_vendor_access_process": False,
                                 "substation_id": "MS-SUB-0412"},
        "remediation": "Document and implement the process.",
        "due_date": due,
    }


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = FindingStore(self.tmp / "findings.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_first_sighting_is_new_and_second_is_not(self):
        self.assertEqual(len(self.store.reconcile([record()], AS_OF).new), 1)
        second = self.store.reconcile([record()], AS_OF)
        self.assertEqual(second.new, [])
        self.assertEqual(len(second.still_open), 1)

    def test_a_finding_that_stops_appearing_is_resolved(self):
        self.store.reconcile([record()], AS_OF)
        delta = self.store.reconcile([], AS_OF)
        self.assertEqual(len(delta.resolved), 1)
        self.assertEqual(self.store.get("F1").state, STATE_CLOSED)

    def test_a_recurrence_reopens_and_is_announced_again(self):
        self.store.reconcile([record()], AS_OF)
        self.store.reconcile([], AS_OF)
        delta = self.store.reconcile([record()], AS_OF)
        self.assertEqual(len(delta.reopened), 1)
        self.assertEqual(self.store.get("F1").state, STATE_OPEN)
        self.assertFalse(self.store.get("F1").alerted_new, "a recurrence is news again")

    def test_the_due_date_is_anchored_to_first_sighting(self):
        """A finding re-seen every 15 minutes must still go overdue.

        If the deadline were recomputed from today each cycle, nothing would
        ever be late and the due date would be decorative.
        """
        self.store.reconcile([record(due="2026-10-21")], AS_OF)
        self.store.reconcile([record(due="2099-01-01")], date(2026, 10, 1))
        self.assertEqual(self.store.get("F1").due_date, "2026-10-21")

    def test_overdue_fires_once_not_every_cycle(self):
        self.store.reconcile([record()], AS_OF)
        late = date(2026, 11, 1)
        self.assertEqual(len(self.store.reconcile([record()], late).newly_overdue), 1)
        self.store.mark_alerted(self.store.open_findings(), overdue=True)
        self.assertEqual(self.store.reconcile([record()], late).newly_overdue, [])

    def test_state_survives_a_restart(self):
        self.store.reconcile([record()], AS_OF)
        self.store.save()
        reloaded = FindingStore(self.store.path).load()
        self.assertEqual(len(reloaded.open_findings()), 1)
        self.assertEqual(reloaded.reconcile([record()], AS_OF).new, [],
                         "a reloaded finding must not be announced as new")

    def test_a_corrupt_store_does_not_take_the_monitor_down(self):
        self.store.path.write_text("{ not json", encoding="utf-8")
        reloaded = FindingStore(self.store.path).load()
        self.assertEqual(reloaded.all(), [])


class Alerting(unittest.TestCase):
    def _tracked(self, n=1, **kw):
        store = FindingStore(Path(tempfile.mkdtemp()) / "f.json")
        store.reconcile([record(fid=f"F{i}", **kw) for i in range(n)], AS_OF)
        return store.open_findings()

    def test_the_alert_names_the_asset_and_the_requirement(self):
        alert = cipalert.for_new(self._tracked()[0], AS_OF)
        self.assertIn("MS-SUB-0412", alert.message)
        self.assertIn("CIP-003-9", alert.message)
        self.assertIn("2026-10-21", alert.message)

    def test_the_alert_does_not_call_the_vendor_non_compliant(self):
        """CIP-003-9 obliges the Responsible Entity, not the vendor.

        An alert reading "this vendor is not compliant with CIP-003-9" is wrong
        on the facts, and a compliance lead will say so.
        """
        alert = cipalert.for_new(self._tracked()[0], AS_OF)
        lowered = alert.message.lower()
        for phrase in ("vendor is not compliant", "vendor non-compliant",
                       "vendor violation", "vendor failed"):
            self.assertNotIn(phrase, lowered)

    def test_severity_routes_deterministically(self):
        self.assertEqual(
            cipalert.for_new(self._tracked(severity="critical")[0], AS_OF).route_to,
            cipalert.ROUTE_BY_SEVERITY["critical"])

    def test_many_findings_with_one_cause_become_one_alert(self):
        """131 relays running one substituted package is one incident."""
        alerts = cipalert.group_new(self._tracked(n=17), AS_OF)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].context["affected_count"], 17)
        self.assertIn("17 assets", alerts[0].message)

    def test_different_causes_stay_separate(self):
        a = self._tracked(n=2)
        b = self._tracked(n=2, control="CIP-33", session_disable_method=False)
        self.assertEqual(len(cipalert.group_new(a + b, AS_OF)), 2)

    def test_grouped_alerts_are_ordered_worst_first(self):
        low = self._tracked(n=1, severity="medium")
        high = self._tracked(n=5, severity="critical")
        alerts = cipalert.group_new(low + high, AS_OF)
        self.assertEqual(alerts[0].severity, "critical")

    def test_resolved_alerts_group_too(self):
        alerts = cipalert.group_resolved(self._tracked(n=9), AS_OF)
        self.assertEqual(len(alerts), 1)
        self.assertIn("9 assets", alerts[0].message)

    def test_alerts_append_to_a_readable_log(self):
        tmp = Path(tempfile.mkdtemp()) / "alerts.jsonl"
        try:
            cipalert.append([cipalert.for_new(self._tracked()[0], AS_OF)], tmp)
            cipalert.append([cipalert.for_new(self._tracked()[0], AS_OF)], tmp)
            lines = tmp.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2, "the log appends, never overwrites")
            parsed = json.loads(lines[0])
            for key in ("kind", "severity", "citation", "asset", "message", "route_to"):
                self.assertIn(key, parsed)
        finally:
            shutil.rmtree(tmp.parent, ignore_errors=True)

    def test_a_failed_webhook_is_reported_not_raised(self):
        """An alerting channel must never be able to take the monitor down."""
        code, detail = cipalert.post_webhook(
            [cipalert.for_new(self._tracked()[0], AS_OF)],
            "http://127.0.0.1:1/nope", timeout=1)
        self.assertEqual(code, 0)
        self.assertIn("failed", detail)


class DeploymentGate(unittest.TestCase):
    """The one place this tool enforces rather than reports."""

    @classmethod
    def setUpClass(cls):
        from vra.gridbuild import ONBOARDING_CLEAN, ONBOARDING_TAMPERED, build_onboarding

        cls.clean, cls.tampered = ONBOARDING_CLEAN, ONBOARDING_TAMPERED
        cls.dir = Path(tempfile.mkdtemp()) / "kestrel"
        cls.dir.mkdir(parents=True)
        build_onboarding(cls.dir, today=AS_OF)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir.parent, ignore_errors=True)

    def _verify(self, package_id):
        from vra.grid import load_estate

        estate = load_estate(self.dir, substations=1, today=AS_OF)
        return estate.verify_all(when=AS_OF)[package_id]

    def test_a_vendor_release_directory_can_be_gated_directly(self):
        """signing-key.yaml / releases.yaml, not keys.yaml / packages.yaml.

        The point of a gate is to check a package before it is anywhere near the
        estate, which means pointing it at what the vendor shipped.
        """
        from vra.grid import load_estate

        estate = load_estate(self.dir, substations=1, today=AS_OF)
        self.assertIn(self.clean, estate.packages)
        self.assertEqual(len(estate.registry), 1)

    def test_the_clean_release_passes_the_gate(self):
        result = self._verify(self.clean)
        self.assertTrue(result.integrity_verified)
        self.assertTrue(result.source_identity_verified)

    def test_the_substituted_release_is_blocked(self):
        result = self._verify(self.tampered)
        self.assertTrue(result.hash_match, "it must still pass the hash check")
        self.assertFalse(result.signature_verified)
        self.assertFalse(result.integrity_verified)

    def test_a_blocked_release_produces_an_actionable_alert(self):
        alert = cipalert.for_rejected_firmware(
            self._verify(self.tampered), package_id=self.tampered)
        self.assertEqual(alert.kind, cipalert.FIRMWARE_REJECTED)
        self.assertEqual(alert.severity, "critical")
        self.assertIn("BLOCKED", alert.message)
        self.assertIn("Do not deploy", alert.remediation)
        self.assertIn("computed_sha256", alert.context)
        self.assertIn("evidence", alert.context)


if __name__ == "__main__":
    unittest.main()
