"""What the tool actually says when an agent's privileges grow.

An entitlement change — a vendor agent that gained `users.manage` since the last
cycle — is the signal an annual review never sees, so it is the one thing the
report must not reduce to a number. These tests pin the alert, the control
citations attached to it, and the counts the console shows next to it.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import llm, webui  # noqa: E402
from vra.config import RunConfig  # noqa: E402
from vra.nhi import NHIInventory  # noqa: E402
from vra.register import FindingStore  # noqa: E402
from vra.report import build_report  # noqa: E402


def _agent(scopes):
    return {
        "id": "0oa1copilotagent01",
        "name": "Access Copilot",
        "display_name": "Access Copilot Agent",
        "principal": "copilot-agent",
        "kind": "agent_principal",
        "scopes": list(scopes),
        "write_scopes": [s for s in scopes if "manage" in s or "revoke" in s],
        "human_in_loop": False,
        "vendor_name": "Aegis Identity Cloud",
    }


class TestEntitlementChangeDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.inv = NHIInventory(Path(self.tmp.name) / "nhis.json")

    def test_gaining_a_write_scope_raises_an_event(self):
        self.inv.upsert_many("aegis", [_agent(["okta.users.read"])])
        _, events = self.inv.upsert_many(
            "aegis", [_agent(["okta.users.read", "okta.users.manage"])]
        )

        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["kind"], "entitlement_change")
        self.assertTrue(event["gained_write_scope"])
        self.assertEqual(event["added_scopes"], ["okta.users.manage"])
        self.assertEqual(event["removed_scopes"], [])

    def test_the_event_carries_what_the_report_needs_to_link_it(self):
        self.inv.upsert_many("aegis", [_agent(["okta.users.read"])])
        _, events = self.inv.upsert_many(
            "aegis", [_agent(["okta.users.read", "okta.users.manage"])]
        )
        event = events[0]
        # principal is what an NHI-* finding stores as its subject.
        self.assertEqual(event["principal"], "copilot-agent")
        self.assertEqual(event["nhi_kind"], "agent_principal")
        self.assertEqual(event["nhi_name"], "Access Copilot Agent")
        self.assertTrue(event["key"].startswith("aegis|"))
        self.assertNotEqual(event["previous_hash"], event["current_hash"])

    def test_losing_a_scope_is_recorded_but_is_not_a_write_gain(self):
        self.inv.upsert_many("aegis", [_agent(["okta.users.read", "okta.users.manage"])])
        _, events = self.inv.upsert_many("aegis", [_agent(["okta.users.read"])])

        self.assertEqual(len(events), 1)
        self.assertFalse(events[0]["gained_write_scope"])
        self.assertEqual(events[0]["removed_scopes"], ["okta.users.manage"])

    def test_an_unchanged_identity_raises_nothing(self):
        self.inv.upsert_many("aegis", [_agent(["okta.users.read"])])
        _, events = self.inv.upsert_many("aegis", [_agent(["okta.users.read"])])
        self.assertEqual(events, [])

    def test_reordered_scopes_are_not_a_change(self):
        self.inv.upsert_many("aegis", [_agent(["a.read", "b.read"])])
        _, events = self.inv.upsert_many("aegis", [_agent(["b.read", "a.read"])])
        self.assertEqual(events, [], "the entitlement hash is order-independent")

    def test_a_rename_does_not_look_like_a_new_identity(self):
        """Keyed by immutable id, so renaming must not fork the history."""
        self.inv.upsert_many("aegis", [_agent(["okta.users.read"])])
        renamed = _agent(["okta.users.read", "okta.users.manage"])
        renamed["name"] = "Access Copilot (renamed)"
        renamed["display_name"] = "Access Copilot Agent v2"
        _, events = self.inv.upsert_many("aegis", [renamed])

        self.assertEqual(len(self.inv.all()), 1, "a rename must not create a row")
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["gained_write_scope"])


class TestEntitlementAlertInTheReport(unittest.TestCase):
    def _ctx(self, events, findings=()):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return {
            "vendors": [{"vendor": "Aegis Identity Cloud", "slug": "aegis", "tier": "high"}],
            "findings": list(findings), "gaps": [], "triages": [], "probes": [],
            "parses": [], "nhis": [], "new_ids": set(), "closed": [],
            "store": FindingStore(Path(tmp.name) / "f.json"),
            "backend": "offline-heuristic", "events": events,
        }

    def _event(self, **over):
        base = {
            "kind": "entitlement_change", "vendor": "aegis",
            "vendor_name": "Aegis Identity Cloud", "key": "aegis|0oa1",
            "nhi_id": "0oa1", "nhi_name": "Access Copilot Agent",
            "principal": "copilot-agent", "nhi_kind": "agent_principal",
            "added_scopes": ["okta.users.manage"], "removed_scopes": [],
            "gained_write_scope": True, "previous_hash": "0608239f460bead0",
            "current_hash": "66d59ed8657ef9c0", "timestamp": "2026-09-10T16:00:00+00:00",
        }
        base.update(over)
        return base

    def _finding(self):
        return {
            "id": "NHI-01-abc", "kind": "finding", "family": "nhi", "vendor": "aegis",
            "vendor_name": "Aegis Identity Cloud", "feature": "Access Copilot",
            "subject": "copilot-agent", "control_id": "NHI-01", "severity": "critical",
            "citation": "NIST SP 800-53 AC-3; SOC 2 TSC CC6.1",
            "control_question": "?", "observed": {}, "state": "open", "evidence": [],
            "narrative": "The agent principal holds write scopes and acts without review.",
            "first_seen": "2026-09-10", "due_date": "2026-09-17",
            "owner": "CISO / Vendor Risk Lead",
            "remediation": "Revoke standing write scopes on the agent principal.",
            "compensating_control": "Alert on every write in the SIEM.",
            "poam": {
                "poam_id": "NHI-01-abc", "vendor": "Aegis Identity Cloud",
                "weakness": "NHI-01", "feature": "Access Copilot",
                "severity": "critical",
                "remediation_action": "Revoke standing write scopes.",
                "compensating_control": "Alert on every write in the SIEM.",
                "owner_role": "CISO / Vendor Risk Lead", "due_date": "2026-09-17",
                "status": "open",
                "citation": "NIST SP 800-53 AC-3; SOC 2 TSC CC6.1",
            },
        }

    def test_the_identity_and_scopes_are_named_not_counted(self):
        report = build_report(self._ctx([self._event()]), RunConfig(dry_run=True))
        self.assertIn("Entitlement changes on non-human identities", report)
        self.assertIn("Access Copilot Agent", report)
        self.assertIn("okta.users.manage", report)
        self.assertIn("gained write scope(s) this cycle", report)

    def test_the_change_cites_the_control_it_tripped(self):
        report = build_report(
            self._ctx([self._event()], findings=[self._finding()]), RunConfig(dry_run=True)
        )
        section = report.split("### 2.2")[0]
        self.assertIn("NHI-01", section)
        self.assertIn("NIST SP 800-53 AC-3", section)
        self.assertIn("SOC 2 TSC CC6.1", section)

    def test_a_change_that_tripped_nothing_says_so(self):
        report = build_report(self._ctx([self._event()]), RunConfig(dry_run=True))
        section = report.split("### 2.2")[0]
        self.assertIn("none", section)
        self.assertIn("recorded for the audit trail", section)

    def test_findings_on_a_different_identity_are_not_attributed(self):
        other = self._finding()
        other["subject"] = "some-other-principal"
        report = build_report(
            self._ctx([self._event()], findings=[other]), RunConfig(dry_run=True)
        )
        self.assertIn("recorded for the audit trail", report.split("### 2.2")[0])

    def test_a_quiet_cycle_says_so_explicitly(self):
        report = build_report(self._ctx([]), RunConfig(dry_run=True))
        self.assertIn("No identity gained or lost a scope", report)

    def test_a_scope_loss_is_not_reported_as_a_write_gain(self):
        event = self._event(added_scopes=[], removed_scopes=["okta.users.manage"],
                            gained_write_scope=False)
        report = build_report(self._ctx([event]), RunConfig(dry_run=True))
        section = report.split("### 2.2")[0]
        self.assertNotIn("gained write scope(s) this cycle", section)
        self.assertIn("Scopes removed", section)


class TestConsoleCounts(unittest.TestCase):
    """A gap is an unanswered question, not a control failure."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        data = Path(self.tmp.name)
        (data / "findings.json").write_text(json.dumps({"findings": [
            {"id": "a", "kind": "finding", "state": "open", "severity": "critical"},
            {"id": "b", "kind": "finding", "state": "open", "severity": "high"},
            {"id": "c", "kind": "gap", "state": "open", "severity": "info"},
            {"id": "d", "kind": "gap", "state": "open", "severity": "info"},
            {"id": "e", "kind": "gap", "state": "open", "severity": "info"},
            {"id": "f", "kind": "finding", "state": "closed", "severity": "high"},
        ]}), encoding="utf-8")
        patch = unittest.mock.patch.object(webui, "DATA_DIR", data)
        patch.start()
        self.addCleanup(patch.stop)

    def test_gaps_are_not_counted_as_open_findings(self):
        summary = webui._summary()
        self.assertEqual(summary["open_findings"], 2, "2 open findings, not 5 records")
        self.assertEqual(summary["gaps"], 3)
        self.assertEqual(summary["critical"], 1)

    def test_closed_records_are_excluded_from_both(self):
        summary = webui._summary()
        self.assertNotIn("f", [summary["open_findings"], summary["gaps"]])
        self.assertEqual(summary["open_findings"] + summary["gaps"], 5)


class TestEvidenceIsNotDuplicated(unittest.TestCase):
    def test_the_same_observation_is_listed_once(self):
        from vra.evaluate import dedupe_evidence

        excerpt = "tenant application 0oa1 principal=copilot-agent scopes=okta.users.manage"
        rows = [
            {"source": "in_tenant_probe", "excerpt": excerpt, "confidence": 1.0},
            {"source": "in_tenant_probe", "excerpt": excerpt, "confidence": 1.0},
            {"source": "subprocessors", "excerpt": excerpt, "confidence": 1.0},
        ]
        out = dedupe_evidence(rows)
        self.assertEqual(len(out), 2, "same source+excerpt collapses; a new source does not")
        self.assertEqual(out[0]["source"], "in_tenant_probe")
        self.assertEqual(out[1]["source"], "subprocessors")

    def test_order_is_preserved(self):
        from vra.evaluate import dedupe_evidence

        rows = [{"source": f"s{i}", "excerpt": f"e{i}"} for i in range(5)]
        self.assertEqual([r["source"] for r in dedupe_evidence(rows + rows)],
                         ["s0", "s1", "s2", "s3", "s4"])

    def test_an_nhi_finding_does_not_repeat_its_probe_line(self):
        from vra.evaluate import Assessment, Control
        from vra.nhi import assessments_to_records

        control = Control(id="NHI-01", question="q", frameworks=[], severity="critical")
        excerpt = "tenant application 0oa1 principal=copilot-agent"
        assessment = Assessment(
            kind="finding", vendor="aegis", vendor_name="Aegis", feature="Access Copilot",
            control=control, observed={}, reason="all failure conditions met",
            subject="copilot-agent",
            provenance={"human_in_loop": {"value": False,
                                          "provenance": "in_tenant_probe",
                                          "evidence": excerpt}},
        )
        findings, _ = assessments_to_records(
            [assessment], [],
            evidence_by_subject={"copilot-agent": [
                {"source": "in_tenant_probe", "excerpt": excerpt,
                 "change_type": "nhi_observation", "confidence": 1.0}
            ]},
        )
        self.assertEqual(len(findings[0]["evidence"]), 1)


class TestEndToEndAlerting(unittest.TestCase):
    """The whole path: baseline cycle, then the cycle where privileges grow."""

    def setUp(self):
        for name in ("data", "out", "pending_review"):
            shutil.rmtree(REPO / name, ignore_errors=True)
        self.addCleanup(lambda: [shutil.rmtree(REPO / n, ignore_errors=True)
                                 for n in ("data", "out", "pending_review")])

        # assess() writes a `state:` block back into every vendors/*.yaml, so a
        # non-dry-run cycle edits files a human owns. Snapshot and restore them
        # or running the suite leaves the working tree dirty.
        self._registers = {p: p.read_bytes() for p in (REPO / "vendors").glob("*.yaml")}
        self.addCleanup(self._restore_registers)

        llm.reset_cache()
        self.addCleanup(llm.reset_cache)

    def _restore_registers(self):
        for path, blob in self._registers.items():
            path.write_bytes(blob)
        for path in (REPO / "vendors").glob("*.yaml"):
            if path not in self._registers:
                path.unlink()  # a test that onboarded a vendor must not leave it

    def _cycle(self, snapshot):
        from vra.cli import assess

        with redirect_stdout(io.StringIO()):
            return assess(RunConfig(offline=True, snapshot_version=snapshot))

    def test_baseline_is_quiet_then_the_change_alerts_with_citations(self):
        baseline = self._cycle("v1")
        self.assertEqual(baseline.critical, 0, "the v1 baseline has no critical finding")

        changed = self._cycle("v2")
        self.assertGreaterEqual(changed.critical, 1)

        blob = json.loads((REPO / "out" / "latest.json").read_text(encoding="utf-8"))
        events = [e for e in blob["events"] if e["kind"] == "entitlement_change"]
        self.assertTrue(events, "the planted scope grant must raise an event")
        self.assertTrue(any(e["gained_write_scope"] for e in events))

        report = (REPO / "out" / "latest.md").read_text(encoding="utf-8")
        alert = report.split("### 2.2")[0]
        self.assertIn("Access Copilot Agent", alert)
        self.assertIn("okta.users.manage", alert)
        self.assertIn("NHI-01", alert)
        self.assertIn("AC-3", alert, "the alert must carry its 800-53 citation")
        self.assertIn("CC6.1", alert, "and its SOC 2 citation")

    def test_every_finding_in_the_poam_carries_a_citation(self):
        self._cycle("v1")
        self._cycle("v2")
        blob = json.loads((REPO / "data" / "findings.json").read_text(encoding="utf-8"))
        openf = [f for f in blob["findings"]
                 if f.get("kind") == "finding" and f.get("state") != "closed"]
        self.assertTrue(openf)
        for finding in openf:
            with self.subTest(control=finding["control_id"]):
                self.assertTrue(finding.get("citation"), "a finding with no citation is unusable")
                self.assertIn("800-53", finding["citation"])
                poam = finding.get("poam") or {}
                self.assertEqual(poam.get("citation"), finding["citation"])
                self.assertTrue(poam.get("due_date"))
                self.assertTrue(poam.get("owner_role"))


if __name__ == "__main__":
    unittest.main()
