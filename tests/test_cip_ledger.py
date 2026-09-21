"""Sealed baselines, drift detection, approvals, and the agent action ledger.

Verifying a package once says it was authentic then. These cover the part that
matters afterwards: whether the vendor's posture moved without anyone saying so,
and whether the agent's own behaviour can be audited.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.ledger import (  # noqa: E402
    CLAUSE_CHANGED,
    KEY_ADDED,
    KEY_FINGERPRINT_CHANGED,
    KEY_STATUS_CHANGED,
    PACKAGE_ADDED,
    PACKAGE_HASH_CHANGED,
    PACKAGE_REMOVED,
    AgentAction,
    BaselineStore,
    VendorPosture,
    agent_behaviour_summary,
    approve,
    detect_drift,
    load_approvals,
    mark_deliberate,
    read_actions,
    record_action,
)


def posture(**over):
    base = dict(
        packages={"P-1": {"sha256": "aaa", "signature": "sig1",
                          "signing_key_id": "k1", "version": "1.0"}},
        keys={"k1": {"fingerprint": "AAAA:BBBB:CCCC:DDDD", "status": "active"}},
        clauses={"software_integrity_clause": True},
    )
    base.update(over)
    return VendorPosture(vendor="Acme Controls", **base)


class Sealing(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = BaselineStore(self.tmp / "baselines.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_seal_records_the_posture_and_its_digest(self):
        record = self.store.seal(posture(), sealed_by="initial verification")
        self.assertEqual(record["seal_digest"], posture().digest)
        self.assertIn("sealed_at", record)
        self.assertEqual(record["sealed_by"], "initial verification")

    def test_a_seal_survives_a_restart(self):
        self.store.seal(posture(), sealed_by="x")
        self.store.save()
        reloaded = BaselineStore(self.store.path).load()
        self.assertEqual(reloaded.vendors(), ["Acme Controls"])

    def test_an_edited_baseline_no_longer_matches_itself(self):
        """A seal is only worth something if editing it is detectable."""
        self.store.seal(posture(), sealed_by="x")
        self.store.save()
        raw = json.loads(self.store.path.read_text())
        raw["baselines"]["Acme Controls"]["packages"]["P-1"]["sha256"] = "tampered"
        self.store.path.write_text(json.dumps(raw))
        self.assertTrue(BaselineStore(self.store.path).load().tampered("Acme Controls"))

    def test_an_untouched_baseline_is_not_flagged(self):
        self.store.seal(posture(), sealed_by="x")
        self.store.save()
        self.assertFalse(BaselineStore(self.store.path).load().tampered("Acme Controls"))


class DriftDetection(unittest.TestCase):
    def setUp(self):
        self.store = BaselineStore(Path(tempfile.mkdtemp()) / "b.json")
        self.store.seal(posture(), sealed_by="initial")
        self.baseline = self.store.get("Acme Controls")

    def _kinds(self, current):
        return {d.kind for d in detect_drift(current, self.baseline)}

    def test_an_unchanged_posture_produces_no_drift(self):
        """NEGATIVE CONTROL. Without this, every cycle would alert."""
        self.assertEqual(detect_drift(posture(), self.baseline), [])

    def test_a_republished_package_is_caught(self):
        """Same version, different bytes -- the case a version check misses."""
        changed = posture(packages={"P-1": {"sha256": "bbb", "signature": "sig1",
                                            "signing_key_id": "k1", "version": "1.0"}})
        self.assertIn(PACKAGE_HASH_CHANGED, self._kinds(changed))

    def test_a_rotated_key_is_caught_and_is_critical(self):
        changed = posture(keys={"k1": {"fingerprint": "ZZZZ:ZZZZ:ZZZZ:ZZZZ",
                                       "status": "active"}})
        drift = next(d for d in detect_drift(changed, self.baseline)
                     if d.kind == KEY_FINGERPRINT_CHANGED)
        self.assertEqual(drift.severity, "critical")

    def test_a_revoked_key_is_caught(self):
        changed = posture(keys={"k1": {"fingerprint": "AAAA:BBBB:CCCC:DDDD",
                                       "status": "revoked"}})
        self.assertIn(KEY_STATUS_CHANGED, self._kinds(changed))

    def test_an_added_package_is_drift(self):
        """An appearance nobody ordered is what establishing a position looks
        like. Only detecting modifications would miss it."""
        changed = posture(packages={
            **posture().packages,
            "P-2": {"sha256": "ccc", "signature": "s", "signing_key_id": "k1", "version": "2.0"}})
        self.assertIn(PACKAGE_ADDED, self._kinds(changed))

    def test_an_added_key_is_drift(self):
        changed = posture(keys={**posture().keys,
                                "k2": {"fingerprint": "EEEE:FFFF:0000:1111", "status": "active"}})
        self.assertIn(KEY_ADDED, self._kinds(changed))

    def test_a_removed_package_is_drift(self):
        self.assertIn(PACKAGE_REMOVED, self._kinds(posture(packages={})))

    def test_a_changed_contract_clause_is_drift(self):
        changed = posture(clauses={"software_integrity_clause": False})
        self.assertIn(CLAUSE_CHANGED, self._kinds(changed))

    def test_drift_is_ordered_worst_first(self):
        changed = posture(
            packages={**posture().packages,
                      "P-2": {"sha256": "c", "signature": "s", "signing_key_id": "k1", "version": "2"}},
            keys={"k1": {"fingerprint": "ZZZZ:ZZZZ:ZZZZ:ZZZZ", "status": "active"}})
        self.assertEqual(detect_drift(changed, self.baseline)[0].kind, KEY_FINGERPRINT_CHANGED)


class Approvals(unittest.TestCase):
    """'No changes until it is deliberate' -- deliberate means recorded."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "approvals.jsonl"
        store = BaselineStore(self.tmp / "b.json")
        store.seal(posture(), sealed_by="initial")
        self.baseline = store.get("Acme Controls")
        self.changed = posture(keys={"k1": {"fingerprint": "ZZZZ:ZZZZ:ZZZZ:ZZZZ",
                                            "status": "active"}})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_unapproved_drift_is_undeclared(self):
        drifts = mark_deliberate(detect_drift(self.changed, self.baseline), {})
        self.assertTrue(all(not d.deliberate for d in drifts))

    def test_an_approval_makes_a_change_deliberate(self):
        drift = detect_drift(self.changed, self.baseline)[0]
        approve(drift, who="analyst", why="vendor confirmed rotation by phone", path=self.log)
        marked = mark_deliberate(detect_drift(self.changed, self.baseline),
                                 load_approvals(self.log))
        self.assertTrue(marked[0].deliberate)
        self.assertEqual(marked[0].approval["approved_by"], "analyst")

    def test_approving_one_change_does_not_bless_the_next(self):
        """The key includes the after-value, so a second rotation is new drift.

        Otherwise one approval would permanently silence a whole class of change.
        """
        first = detect_drift(self.changed, self.baseline)[0]
        approve(first, who="analyst", why="confirmed", path=self.log)
        again = posture(keys={"k1": {"fingerprint": "9999:9999:9999:9999", "status": "active"}})
        marked = mark_deliberate(detect_drift(again, self.baseline), load_approvals(self.log))
        self.assertFalse(marked[0].deliberate)

    def test_an_approval_records_who_and_why(self):
        drift = detect_drift(self.changed, self.baseline)[0]
        approve(drift, who="J. Analyst", why="scheduled rotation", path=self.log)
        record = json.loads(self.log.read_text().strip())
        self.assertEqual(record["approved_by"], "J. Analyst")
        self.assertEqual(record["reason"], "scheduled rotation")
        self.assertIn("approved_at", record)

    def test_the_approval_log_appends(self):
        for drift in detect_drift(self.changed, self.baseline):
            approve(drift, who="a", why="b", path=self.log)
            approve(drift, who="a", why="b", path=self.log)
        self.assertGreaterEqual(len(self.log.read_text().strip().splitlines()), 2)


class AgentActionLedger(unittest.TestCase):
    """Entergy's Item 1A names AI-driven threats. A tool that puts an AI in the
    decision path has to be able to say what the AI did."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "actions.jsonl"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, **over):
        action = AgentAction(task="firmware_disposition", backend="ollama",
                             model="qwen2.5:7b-instruct", input_digest="d1",
                             disposition="block", risk="critical", confidence=0.9,
                             reasoning="signature invalid", subject="PKG-1")
        for k, v in over.items():
            setattr(action, k, v)
        record_action(action, self.log)
        return action

    def test_an_action_is_recorded_with_what_it_decided(self):
        self._write()
        rows = read_actions(self.log)
        self.assertEqual(len(rows), 1)
        for key in ("task", "backend", "model", "input_digest",
                    "disposition", "risk", "confidence", "at"):
            self.assertIn(key, rows[0])

    def test_the_ledger_is_append_only(self):
        self._write()
        self._write(disposition="allow")
        self.assertEqual(len(read_actions(self.log)), 2)

    def test_inputs_are_digested_not_stored(self):
        """The brief is large and reproducible. What matters for an audit is
        whether the agent saw the same inputs, which a digest answers."""
        self._write()
        self.assertEqual(read_actions(self.log)[0]["input_digest"], "d1")
        self.assertNotIn("prompt", read_actions(self.log)[0])

    def test_behaviour_is_summarised_per_model_build(self):
        """A model that starts allowing what it used to block is the thing a
        security team needs to see."""
        self._write(model="qwen2.5:7b-instruct", disposition="block")
        self._write(model="qwen2.5:3b", disposition="allow")
        summary = agent_behaviour_summary(read_actions(self.log))
        self.assertEqual(summary["actions"], 2)
        self.assertIn("ollama/qwen2.5:3b", summary["by_model"])
        self.assertIn("ollama/qwen2.5:7b-instruct", summary["by_model"])

    def test_the_same_inputs_getting_different_answers_is_flagged(self):
        self._write(input_digest="same", disposition="block")
        self._write(input_digest="same", disposition="allow")
        self.assertEqual(agent_behaviour_summary(read_actions(self.log))["inconsistent_repeats"], 1)

    def test_consistent_repeats_are_not_flagged(self):
        self._write(input_digest="same", disposition="block")
        self._write(input_digest="same", disposition="block")
        self.assertEqual(agent_behaviour_summary(read_actions(self.log))["inconsistent_repeats"], 0)

    def test_schema_failures_are_counted(self):
        self._write(schema_ok=False, disposition="escalate")
        self.assertEqual(agent_behaviour_summary(read_actions(self.log))["schema_failures"], 1)

    def test_a_judgment_converts_to_a_ledger_entry(self):
        from vra.analyst_cip import Judgment, ReasoningBrief
        from vra.ledger import action_from_judgment

        brief = ReasoningBrief(package_id="PKG-9", vendor="Acme")
        judgment = Judgment(disposition="block", risk="high", reasoning="because",
                            confidence=0.7, backend="ollama", model="qwen2.5:7b-instruct", ok=True)
        action = action_from_judgment(judgment, subject="PKG-9", brief=brief)
        self.assertEqual(action.disposition, "block")
        self.assertEqual(action.model, "qwen2.5:7b-instruct")
        self.assertTrue(action.input_digest, "the brief must be digested for replay")


if __name__ == "__main__":
    unittest.main()
