"""The model as analyst: it reasons, and the code's output is one of its inputs.

procure.py is the other shape -- model extracts, code adjudicates -- because
"is this clause present" is a fact. This is a judgement: given the crypto
result, the vendor's history and the blast radius, what should happen to this
package. These tests cover what the model is given, what it may decide, and
what happens when it and the rule engine disagree.
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

from vra.analyst_cip import (  # noqa: E402
    DECIDE_BOTH,
    DECIDE_CODE,
    DECIDE_MODEL,
    Judgment,
    ReasoningBrief,
    _schema,
    build_brief,
    decide,
    judge,
)
from vra.config import RunConfig  # noqa: E402
from vra.grid import load_estate  # noqa: E402
from vra.gridbuild import TAMPERED_PACKAGE, build  # noqa: E402

AS_OF = date(2026, 9, 21)


class TheBriefCarriesWhatTheCodeFound(unittest.TestCase):
    """A model asked "is this safe" with only the bytes has nothing to reason
    with. The brief is what makes a small model useful."""

    @classmethod
    def setUpClass(cls):
        cls.grid = Path(tempfile.mkdtemp()) / "grid"
        build(cls.grid, today=AS_OF)
        cls.estate = load_estate(cls.grid, substations=600, today=AS_OF)
        cls.results = cls.estate.verify_all(when=AS_OF)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.grid.parent, ignore_errors=True)

    def _brief(self, package_id=TAMPERED_PACKAGE):
        return build_brief(self.estate.packages[package_id],
                           self.results[package_id], estate=self.estate)

    def test_the_brief_carries_the_cryptographic_result(self):
        brief = self._brief()
        self.assertTrue(brief.hash_match)
        self.assertFalse(brief.signature_verified)
        self.assertFalse(brief.integrity_verified)
        self.assertTrue(brief.verification_log)

    def test_the_brief_carries_blast_radius_from_the_inventory(self):
        brief = self._brief()
        self.assertGreater(brief.deployed_on_devices, 0)
        self.assertGreater(brief.substations, 0)
        self.assertEqual(
            brief.deployed_on_devices,
            sum(1 for d in self.estate.deployments if d["package_id"] == TAMPERED_PACKAGE))

    def test_the_brief_carries_vendor_history_when_a_store_is_given(self):
        from vra.cipstate import FindingStore

        store = FindingStore(Path(tempfile.mkdtemp()) / "f.json")
        store.reconcile([{
            "id": "P1", "kind": "finding", "control_id": "CIP-02",
            "citation": "CIP-010-4 R1 Part 1.6.1", "severity": "critical",
            "feature": "old", "vendor_name": "Sentinel Protective Systems",
            "control_question": "q", "observed": {}, "due_date": "2026-01-01",
        }], AS_OF)
        brief = build_brief(self.estate.packages[TAMPERED_PACKAGE],
                            self.results[TAMPERED_PACKAGE],
                            estate=self.estate, store=store)
        self.assertEqual(brief.vendor_prior_findings, 1)
        self.assertEqual(brief.vendor_prior_signature_failures, 1)

    def test_the_prompt_is_labelled_lines_not_json(self):
        """A 4B model reasons better over short labelled facts than over a
        nested object, and braces cost tokens the facts could use."""
        text = self._brief().as_prompt()
        self.assertNotIn("{", text)
        for label in ("CRYPTOGRAPHIC VERIFICATION", "BLAST RADIUS",
                      "VENDOR HISTORY", "RULE ENGINE VERDICT"):
            self.assertIn(label, text)

    def test_the_prompt_states_the_rule_engine_verdict_as_input(self):
        """The code's conclusion is evidence the model weighs, not a
        conclusion hidden from it."""
        self.assertIn("RULE ENGINE VERDICT: BLOCK", self._brief().as_prompt())

    def test_a_clean_package_briefs_as_allow(self):
        clean = next(p for p in self.results if p != TAMPERED_PACKAGE)
        self.assertEqual(self._brief(clean).deterministic_verdict, "allow")


class WhoDecides(unittest.TestCase):
    """--decision selects the authority. All three modes must actually work."""

    def setUp(self):
        self.rules_block = ReasoningBrief(package_id="X", vendor="V")
        self.rules_block.deterministic_verdict = "block"
        self.rules_allow = ReasoningBrief(package_id="Y", vendor="V")
        self.rules_allow.deterministic_verdict = "allow"
        self.says_allow = Judgment(disposition="allow", risk="low",
                                   reasoning="r", backend="gemma3:4b")
        self.says_block = Judgment(disposition="block", risk="high",
                                   reasoning="r", backend="gemma3:4b")

    def test_model_mode_lets_the_model_overrule_the_rules(self):
        """The point of the mode. If this fails, the model is decorative."""
        d = decide(self.rules_block, self.says_allow, mode=DECIDE_MODEL)
        self.assertEqual(d.disposition, "allow")
        self.assertIn("model", d.decided_by)

    def test_model_mode_lets_the_model_block_what_the_rules_pass(self):
        """The more valuable direction: the model sees what the rules do not
        encode -- history, blast radius, a pattern across releases."""
        d = decide(self.rules_allow, self.says_block, mode=DECIDE_MODEL)
        self.assertEqual(d.disposition, "block")

    def test_code_mode_ignores_the_model(self):
        self.assertEqual(
            decide(self.rules_block, self.says_allow, mode=DECIDE_CODE).disposition, "block")

    def test_both_mode_takes_the_stricter_side_either_way(self):
        """Not the code overruling the model: the same rule in both
        directions, so the model can stop something the rules would pass."""
        self.assertEqual(
            decide(self.rules_block, self.says_allow, mode=DECIDE_BOTH).disposition, "block")
        self.assertEqual(
            decide(self.rules_allow, self.says_block, mode=DECIDE_BOTH).disposition, "block")

    def test_agreement_on_allow_allows(self):
        d = decide(self.rules_allow, self.says_allow, mode=DECIDE_BOTH)
        self.assertEqual(d.disposition, "allow")
        self.assertFalse(d.blocks)
        self.assertFalse(d.disagreement)

    def test_disagreement_is_surfaced_not_hidden(self):
        """Either the model saw context the rules do not encode, or it got it
        wrong. Both are worth knowing."""
        self.assertTrue(decide(self.rules_block, self.says_allow, mode=DECIDE_BOTH).disagreement)

    def test_escalate_blocks_the_pipeline(self):
        d = decide(self.rules_allow,
                   Judgment(disposition="escalate", risk="high", reasoning="r"),
                   mode=DECIDE_MODEL)
        self.assertTrue(d.blocks, "a held package must not deploy while it is held")


class ModelOutputIsValidated(unittest.TestCase):
    """A 4B model returns prose, code fences and partial objects. call_json
    retries with the rejection reason, so the schema has to name the problem."""

    def test_an_unknown_disposition_is_rejected(self):
        self.assertIsNotNone(_schema({"disposition": "maybe", "risk": "high", "reasoning": "r"}))

    def test_an_unknown_risk_is_rejected(self):
        self.assertIsNotNone(_schema({"disposition": "block", "risk": "very bad", "reasoning": "r"}))

    def test_a_decision_without_reasoning_is_rejected(self):
        self.assertIsNotNone(_schema({"disposition": "block", "risk": "high", "reasoning": "  "}))

    def test_out_of_range_confidence_is_rejected(self):
        self.assertIsNotNone(_schema(
            {"disposition": "block", "risk": "high", "reasoning": "r", "confidence": 7}))

    def test_a_well_formed_judgment_is_accepted(self):
        self.assertIsNone(_schema({
            "disposition": "block", "risk": "critical",
            "reasoning": "signature invalid against the active key",
            "recommended_actions": ["quarantine"], "confidence": 0.9}))

    def test_a_model_that_fails_escalates_rather_than_allowing(self):
        """No usable answer must never become an allow."""
        from vra.llm import LLMResult

        import vra.analyst_cip as analyst

        original = analyst.call_json
        analyst.call_json = lambda **kw: LLMResult(
            False, {}, "not json", "ollama", "gemma3:4b", 3, "no JSON object found")
        try:
            cfg = RunConfig(offline=False)
            cfg.llm_unavailable = False
            result = judge(ReasoningBrief(package_id="X", vendor="V"), cfg)
            self.assertEqual(result.disposition, "escalate")
            self.assertFalse(result.ok)
        finally:
            analyst.call_json = original


class OfflineStandIn(unittest.TestCase):
    """So CI and a laptop with no Ollama exercise the same path."""

    def test_a_clean_package_is_allowed(self):
        brief = ReasoningBrief(package_id="X", vendor="V",
                               integrity_verified=True, source_identity_verified=True)
        result = judge(brief, RunConfig(offline=True))
        self.assertEqual(result.disposition, "allow")
        self.assertEqual(result.backend, "offline-heuristic")

    def test_hash_match_with_a_bad_signature_is_blocked(self):
        brief = ReasoningBrief(package_id="X", vendor="V", hash_match=True,
                               signature_verified=False, integrity_verified=False,
                               deployed_on_devices=131, high_impact_devices=12)
        result = judge(brief, RunConfig(offline=True))
        self.assertEqual(result.disposition, "block")
        self.assertEqual(result.risk, "critical")
        self.assertIn("131", result.reasoning)

    def test_the_stand_in_is_always_labelled(self):
        result = judge(ReasoningBrief(package_id="X", vendor="V"), RunConfig(offline=True))
        self.assertEqual(result.backend, "offline-heuristic")


class ProcureCallsTheModelCorrectly(unittest.TestCase):
    """The live-model path in procure.py was unreachable in tests because they
    all run offline, and it passed positional arguments to a keyword-only
    function. It would have raised TypeError on the first real call."""

    def test_call_json_is_invoked_with_keywords_and_a_schema(self):
        import inspect

        from vra.llm import call_json
        from vra.procure import extract_procurement

        for name, param in inspect.signature(call_json).parameters.items():
            self.assertEqual(param.kind, inspect.Parameter.KEYWORD_ONLY, name)
        source = inspect.getsource(extract_procurement)
        self.assertIn("system=SYSTEM", source)
        self.assertIn("schema_check=_clause_schema", source)

    def test_the_clause_schema_rejects_what_a_small_model_returns(self):
        from vra.procure import _clause_schema

        self.assertIsNotNone(_clause_schema({}))
        self.assertIsNotNone(_clause_schema({"present": "yes"}))
        self.assertIsNotNone(_clause_schema({"present": True, "quote": ""}))
        self.assertIsNone(_clause_schema({"present": True, "quote": "Supplier shall notify..."}))


if __name__ == "__main__":
    unittest.main()
