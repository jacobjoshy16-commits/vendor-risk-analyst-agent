"""End-to-end: enter a vendor, detect its procurement process, verify firmware.

This is the back-to-back test. It runs the sequence a supply chain analyst
performs -- read the contract, establish which CIP-013 obligations it addresses,
register the vendor's signing key, verify each release by SHA-256 and then
Ed25519 -- and asserts on what the code was and was not allowed to conclude.

The assertions that carry weight are the refusals. It is easy to build something
that reads a contract and produces findings. The question is whether it declines
to produce one when it cannot evidence it.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.cip import load_cip_controls  # noqa: E402
from vra.config import RunConfig  # noqa: E402
from vra.gridbuild import (  # noqa: E402
    ONBOARDING_CLEAN,
    ONBOARDING_TAMPERED,
    ONBOARDING_VENDOR,
    build_onboarding,
)
from vra.onboard_cip import onboard_vendor  # noqa: E402
from vra.procure import (  # noqa: E402
    CLAUSE_TARGETS,
    SourceDocument,
    adjudicate,
    ExtractedClaim,
    extract_procurement,
    load_documents,
    verify_quote,
)

AS_OF = date(2026, 9, 21)
DOCS = REPO / "sandbox" / "procurement" / "kestrel-grid"


class QuoteVerification(unittest.TestCase):
    """The boundary between 'a model said so' and 'a control failed'."""

    def setUp(self):
        self.docs = [SourceDocument(
            name="msa.txt", path="msa.txt",
            text=("9.1 Incident Notification. Supplier shall notify Customer's designated "
                  "security contact of any Security Incident affecting the products or "
                  "services provided under this Agreement within twenty-four (24) hours."),
        )]

    def test_a_verbatim_quote_verifies(self):
        ok, src = verify_quote(
            "Supplier shall notify Customer's designated security contact of any "
            "Security Incident affecting the products or services provided",
            self.docs)
        self.assertTrue(ok)
        self.assertEqual(src, "msa.txt")

    def test_reflowed_whitespace_still_verifies(self):
        """Contract text wraps; a model reflows. Rejecting on whitespace would
        push correct extractions into the review queue until nobody reads it."""
        ok, _ = verify_quote(
            "Supplier   shall notify\n  Customer's designated security contact of any "
            "Security  Incident affecting the products or services provided",
            self.docs)
        self.assertTrue(ok)

    def test_a_paraphrase_does_not_verify(self):
        """The whole point. A plausible summary is not evidence."""
        ok, _ = verify_quote(
            "The supplier is required to inform the customer about security incidents "
            "within one day of becoming aware of them.",
            self.docs)
        self.assertFalse(ok)

    def test_an_invented_clause_does_not_verify(self):
        ok, _ = verify_quote(
            "Supplier shall indemnify Customer against all regulatory penalties arising "
            "from any failure of the supplied equipment.",
            self.docs)
        self.assertFalse(ok)

    def test_a_short_fragment_cannot_verify(self):
        """'Supplier shall' appears in every contract ever written."""
        for fragment in ("Supplier shall", "notify Customer", "within 24 hours"):
            ok, _ = verify_quote(fragment, self.docs)
            self.assertFalse(ok, f"{fragment!r} should be too short to evidence anything")


class AdjudicationRules(unittest.TestCase):
    """The two non-negotiable rules, tested directly."""

    def setUp(self):
        self.docs = [SourceDocument(
            name="msa.txt", path="msa.txt",
            text=("Supplier shall publish a cryptographic signature generated with "
                  "Supplier's code signing key together with a SHA-256 digest of the "
                  "released artifact for every release supplied under this Agreement."),
        )]

    def _claim(self, field_name, present, quote):
        return ExtractedClaim(field=field_name, requirement="CIP-013 R1.2.x",
                              present=present, quote=quote, confidence=0.9)

    def test_absence_never_becomes_a_failure(self):
        """RULE 1. An absence has no text, so it cannot be evidenced.

        If this ever inverts, a model that simply failed to find a clause in a
        90-page contract would fail the vendor on it.
        """
        claim = self._claim("contract.access_termination_notice_clause", False, "")
        adjudicate([claim], self.docs, critical_fields=set())
        self.assertEqual(claim.tier, "proposed")
        self.assertIsNone(claim.applied_value, "absence must never apply False")
        self.assertIn("absence", claim.withheld_reason.lower())

    def test_verified_presence_below_critical_is_applied(self):
        # The field is software_integrity_clause because that is what this quote
        # is actually about. It previously said vulnerability_disclosure_clause,
        # which the new relevance check correctly rejects: the quote is genuine
        # but it answers a different obligation. critical_fields is empty here so
        # the ceiling does not fire and this tests the applied path.
        claim = self._claim(
            "contract.software_integrity_clause", True,
            "Supplier shall publish a cryptographic signature generated with "
            "Supplier's code signing key together with a SHA-256 digest")
        adjudicate([claim], self.docs, critical_fields=set())
        self.assertEqual(claim.tier, "extracted")
        self.assertTrue(claim.applied_value)

    def test_critical_field_is_withheld_even_when_verified(self):
        """RULE 2. Verification proves the text exists, not that scope was read
        right. A definition in a struck exhibit quotes perfectly."""
        claim = self._claim(
            "contract.software_integrity_clause", True,
            "Supplier shall publish a cryptographic signature generated with "
            "Supplier's code signing key together with a SHA-256 digest")
        adjudicate([claim], self.docs,
                   critical_fields={"contract.software_integrity_clause"})
        self.assertTrue(claim.quote_verified)
        self.assertEqual(claim.tier, "proposed")
        self.assertIsNone(claim.applied_value)
        self.assertIn("critical", claim.withheld_reason.lower())

    def test_unverifiable_quote_is_withheld(self):
        claim = self._claim(
            "contract.incident_notification_clause", True,
            "Supplier warrants that no vulnerability shall ever exist in the supplied "
            "equipment for the duration of this Agreement.")
        adjudicate([claim], self.docs, critical_fields=set())
        self.assertFalse(claim.quote_verified)
        self.assertEqual(claim.tier, "proposed")

    def test_the_ceiling_is_read_from_the_control_set(self):
        """Re-rating a control in YAML must move the extraction ceiling too."""
        from vra.procure import critical_fields_from_controls

        controls = load_cip_controls()
        fields = critical_fields_from_controls(controls)
        self.assertIn("contract.software_integrity_clause", fields)
        for control in controls:
            if control.severity == "critical":
                continue
            for cond in control.fails_when:
                if cond.get("field", "").startswith("contract."):
                    self.assertNotIn(cond["field"], fields)


class EndToEndOnboarding(unittest.TestCase):
    """The full sequence against the real sandbox documents."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.vendor_dir = cls.tmp / "kestrel-grid"
        shutil.copytree(DOCS, cls.vendor_dir)
        build_onboarding(cls.vendor_dir, today=AS_OF)
        cls.result = onboard_vendor(
            ONBOARDING_VENDOR, cls.vendor_dir,
            RunConfig(offline=True),
            slug="kestrel-grid", impact_rating="high",
            controls=load_cip_controls(), when=AS_OF,
            pending_review_root=cls.tmp / "pending_review",
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # --- step 1-2: documents and detection --------------------------------
    def test_it_read_both_vendor_documents(self):
        self.assertEqual(
            sorted(self.result.extraction.documents),
            ["msa-excerpt.txt", "security-questionnaire.txt"],
        )

    def test_it_examined_every_clause_target(self):
        self.assertEqual(len(self.result.extraction.claims), len(CLAUSE_TARGETS))

    def test_it_found_the_clauses_that_are_really_there(self):
        found = {c.field for c in self.result.extraction.claims if c.present}
        for expected in (
            "contract.incident_notification_clause",
            "contract.incident_coordination_clause",
            "contract.vulnerability_disclosure_clause",
            "contract.software_integrity_clause",
            "contract.remote_access_coordination_clause",
            "contract.vendor_transition_clause",
        ):
            self.assertIn(expected, found)

    def test_every_quote_it_offered_was_located_in_a_document(self):
        for claim in self.result.extraction.claims:
            if claim.present:
                self.assertTrue(
                    claim.quote_verified,
                    f"{claim.field} quote was not found in the source",
                )
                self.assertIn(claim.source_document, self.result.extraction.documents)

    def test_the_absent_clause_was_not_invented(self):
        """R1.2.3 is genuinely missing. Questionnaire A9 discusses offboarding
        but commits the vendor to nothing, which is the trap."""
        claim = next(c for c in self.result.extraction.claims
                     if c.field == "contract.access_termination_notice_clause")
        self.assertFalse(claim.present)
        self.assertEqual(claim.quote, "")

    # --- step 3: refusals --------------------------------------------------
    def test_the_absent_clause_became_a_gap_not_a_failure(self):
        record = self.result.vendor_record["contract"]
        self.assertNotIn("access_termination_notice_clause", record)
        failed = {f.control.id for f in self.result.findings}
        self.assertNotIn("CIP-10", failed, "R1.2.3 must not fail on a model's say-so")
        self.assertIn("CIP-10", {g.control.id for g in self.result.gaps})

    def test_the_critical_clause_was_withheld_from_the_register(self):
        record = self.result.vendor_record["contract"]
        self.assertNotIn("software_integrity_clause", record)
        self.assertIn("CIP-12", {g.control.id for g in self.result.gaps})

    def test_withheld_claims_were_queued_for_a_human(self):
        self.assertIsNotNone(self.result.pending_review_path)
        self.assertTrue(self.result.pending_review_path.is_file())
        import json

        queued = json.loads(self.result.pending_review_path.read_text())
        fields = {item["field"] for item in queued["items"]}
        self.assertIn("contract.software_integrity_clause", fields)
        self.assertIn("contract.access_termination_notice_clause", fields)
        for item in queued["items"]:
            self.assertTrue(item["withheld_reason"], "a queued item must say why")

    def test_applied_claims_reached_the_register(self):
        record = self.result.vendor_record["contract"]
        self.assertTrue(record.get("incident_notification_clause"))
        self.assertTrue(record.get("vulnerability_disclosure_clause"))
        self.assertTrue(record.get("remote_access_coordination_clause"))

    # --- step 4-5: the crypto ---------------------------------------------
    def test_the_vendor_key_was_registered_and_fingerprinted(self):
        keys = self.result.key_registry.all()
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].vendor, ONBOARDING_VENDOR)
        self.assertRegex(keys[0].fingerprint, r"^[0-9A-F]{4}(:[0-9A-F]{4}){3}$")
        self.assertTrue(keys[0].fingerprint_confirmed_out_of_band)

    def test_sha256_was_computed_for_every_release(self):
        self.assertEqual(len(self.result.verified), 2)
        for r in self.result.verified.values():
            self.assertTrue(r.artifact_present)
            self.assertRegex(r.computed_sha256, r"^[0-9a-f]{64}$")

    def test_the_clean_release_is_accepted(self):
        """NEGATIVE CONTROL for the onboarding path."""
        r = self.result.verified[ONBOARDING_CLEAN]
        self.assertTrue(r.hash_match)
        self.assertTrue(r.signature_verified)
        self.assertTrue(r.source_identity_verified)
        self.assertTrue(r.integrity_verified)

    def test_the_tampered_release_passes_sha256_and_fails_ed25519(self):
        """Both halves must be true or the test proves nothing."""
        r = self.result.verified[ONBOARDING_TAMPERED]
        self.assertTrue(r.hash_match, "the hash check must pass — that is the point")
        self.assertFalse(r.signature_verified)
        self.assertFalse(r.integrity_verified)
        self.assertFalse(r.source_identity_verified)

    def test_verification_order_is_hash_then_signature(self):
        """The evidence log must read in the order the work was done, or it is
        not a record of what happened."""
        evidence = self.result.verified[ONBOARDING_TAMPERED].evidence
        joined = " || ".join(evidence)
        self.assertLess(
            joined.index("computed SHA-256"), joined.index("Ed25519 verify"),
            "SHA-256 must be computed before the signature is checked",
        )

    # --- step 6: scoring ---------------------------------------------------
    def test_only_the_tampered_release_raises_cip010_findings(self):
        firmware = [f for f in self.result.findings if f.control.id in ("CIP-01", "CIP-02")]
        self.assertEqual(len(firmware), 2, "one R1.6.1 and one R1.6.2 finding")
        for f in firmware:
            self.assertIn(ONBOARDING_TAMPERED,
                          (f.provenance.get("firmware_verification") or {}).get("value", ""))

    def test_the_clean_release_produced_no_finding(self):
        for f in self.result.findings:
            prov = (f.provenance.get("firmware_verification") or {}).get("value", "")
            self.assertNotEqual(prov, ONBOARDING_CLEAN)

    def test_clauses_it_verified_produced_passes_not_gaps(self):
        passed = {cid for cid, cov in self.result.coverage.items() if cov.passed and not cov.gapped}
        for control_id in ("CIP-08", "CIP-11", "CIP-13", "CIP-28"):
            self.assertIn(control_id, passed, f"{control_id} should pass on a verified clause")

    def test_coverage_accounting_holds_on_the_onboarding_path(self):
        for cid, cov in self.result.coverage.items():
            self.assertEqual(cov.applicable, cov.passed + cov.failed + cov.gapped, cid)

    def test_the_crosswalk_control_sees_the_registered_key(self):
        """CIP-30 links the R1.2.5 contract obligation to a key actually held.

        It is skipped here because the integrity clause was withheld for
        ratification -- which is correct: you cannot assess the quality of a
        clause you have not accepted.
        """
        self.assertEqual(self.result.coverage["CIP-30"].applicable, 0)


class ExtractionIsNotTrustedBlindly(unittest.TestCase):
    """The extractor must behave the same whether the text is friendly or not."""

    def test_a_document_with_no_clauses_yields_no_applied_claims(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "empty.txt").write_text(
                "This agreement concerns the supply of office furniture. "
                "Delivery shall occur within ninety days of order confirmation. "
                "Payment terms are net thirty days from invoice date.",
                encoding="utf-8")
            result = extract_procurement(
                "Furniture Co", "furniture-co",
                load_documents(tmp), RunConfig(offline=True),
                controls=load_cip_controls())
            self.assertEqual(result.applied, [], "nothing in this document is a CIP-013 clause")
            self.assertEqual(result.register_contract_block(), {})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_an_unreadable_document_is_reported_not_skipped(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "scanned.pdf").write_bytes(b"%PDF-1.4 not really a pdf")
            result = extract_procurement(
                "Opaque Co", "opaque-co",
                load_documents(tmp), RunConfig(offline=True),
                controls=load_cip_controls())
            self.assertIn("scanned.pdf", result.unreadable_documents)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()


class PrioritizedReadingCannotChangeTheVerdict(unittest.TestCase):
    """Machine context steers attention. It must not steer the outcome.

    The footprint tells the model what the vendor supplies and whether a signing
    key is already held, and reorders the obligations so the highest-stakes ones
    are read first. That is an efficiency mechanism. The moment a large footprint
    made a claim easier to accept, the footprint would be an input to a decision
    — which is the boundary this whole design exists to hold.
    """

    def setUp(self):
        from vra.procure import VendorFootprint

        self.docs = load_documents(DOCS)
        self.controls = load_cip_controls()
        self.big = VendorFootprint(
            vendor="Kestrel Grid Systems", devices=3400, substations=1200,
            high_impact_devices=231, medium_impact_devices=584,
            deployments=3400, packages=6, publishes_signing_key=True,
            trusted_key_ids=["kestrel-grid-2026"],
        )
        self.small = VendorFootprint(
            vendor="Kestrel Grid Systems", devices=2, substations=1,
            high_impact_devices=0, medium_impact_devices=0,
            deployments=2, packages=1, publishes_signing_key=False,
        )

    def _run(self, footprint):
        return extract_procurement(
            "Kestrel Grid Systems", "kestrel-grid", self.docs,
            RunConfig(offline=True), controls=self.controls, footprint=footprint)

    def test_the_adjudicated_result_is_identical_under_opposite_footprints(self):
        """The assertion that matters."""
        big = {(c.field, c.tier, c.applied_value, c.quote_verified) for c in self._run(self.big).claims}
        small = {(c.field, c.tier, c.applied_value, c.quote_verified) for c in self._run(self.small).claims}
        none = {(c.field, c.tier, c.applied_value, c.quote_verified) for c in self._run(None).claims}
        self.assertEqual(big, small)
        self.assertEqual(big, none)

    def test_the_register_block_is_identical_under_opposite_footprints(self):
        self.assertEqual(
            self._run(self.big).register_contract_block(),
            self._run(self.small).register_contract_block(),
        )

    def test_the_reading_order_does_change(self):
        """If it never reordered, the feature would be doing nothing."""
        from vra.procure import reading_order

        self.assertNotEqual(
            [t["field"] for t in reading_order(self.small)],
            [t["field"] for t in reading_order(None)],
        )

    def test_a_vendor_with_no_key_is_asked_about_integrity_first(self):
        """No key held means CIP-010 R1.6.1 is unevaluable for every release
        this vendor ships, so whether the contract even obliges one is the most
        useful thing to establish."""
        from vra.procure import reading_order

        order = [t["field"] for t in reading_order(self.small)]
        self.assertEqual(order[0], "contract.software_integrity_clause")
        self.assertIn("contract.key_rotation_notice_clause", order[:3])

    def test_every_obligation_is_still_read(self):
        """Prioritisation reorders. It must never skip: a silently dropped
        obligation is a coverage gap the report cannot see."""
        from vra.procure import CLAUSE_TARGETS, reading_order

        for footprint in (self.big, self.small, None):
            self.assertEqual(
                {t["field"] for t in reading_order(footprint)},
                {t["field"] for t in CLAUSE_TARGETS},
            )
        self.assertEqual(len(self._run(self.small).claims), len(CLAUSE_TARGETS))

    def test_the_footprint_context_states_facts_not_conclusions(self):
        """The model is told where it is, not what to find."""
        text = self.big.as_prompt_context().lower()
        for leading in ("should", "must", "likely", "probably", "expect to find",
                        "therefore", "compliant", "violation"):
            self.assertNotIn(leading, text, f"footprint context editorialises: {leading!r}")


class AQuoteMustBeAboutTheObligationItAnswers(unittest.TestCase):
    """Regression: quote verification alone is not enough.

    Found by driving the live model path against a fake Ollama that returned the
    same genuine sentence for every obligation. The quote verified -- it really
    was in the document -- and the claim was applied, so the register gained a
    CIP-013 R1.2.3 clause the contract does not contain.

    The offline heuristic never exposed this because it finds quotes BY keyword,
    so its quotes are topically relevant by construction. Only a model that
    behaved badly showed the hole.
    """

    def setUp(self):
        self.docs = load_documents(DOCS)
        # A real sentence from the MSA. It is about incident notification
        # (R1.2.1) and nothing else.
        self.incident_quote = (
            "Supplier shall notify Customer's designated security contact of any "
            "Security Incident affecting the products or services provided under "
            "this Agreement")

    def _claim(self, field_name, requirement, quote):
        return ExtractedClaim(field=field_name, requirement=requirement,
                              present=True, quote=quote, confidence=0.9)

    def test_a_real_quote_about_the_wrong_obligation_is_withheld(self):
        """THE BUG. The quote is genuine; it answers a different question."""
        claim = self._claim("contract.access_termination_notice_clause",
                            "CIP-013 R1.2.3", self.incident_quote)
        adjudicate([claim], self.docs, critical_fields=set())
        self.assertTrue(claim.quote_verified, "the quote really is in the document")
        self.assertEqual(claim.tier, "proposed")
        self.assertIsNone(claim.applied_value)
        self.assertIn("obligation asked", claim.withheld_reason)

    def test_the_same_quote_reused_across_obligations_withholds_all_of_them(self):
        """One sentence can answer at most one obligation. Rather than guess
        which, none is treated as evidenced."""
        claims = [
            self._claim("contract.incident_notification_clause", "R1.2.1", self.incident_quote),
            self._claim("contract.incident_coordination_clause", "R1.2.2", self.incident_quote),
        ]
        adjudicate(claims, self.docs, critical_fields=set())
        for claim in claims:
            self.assertEqual(claim.tier, "proposed")
            self.assertIn("more than one obligation", claim.withheld_reason)

    def test_the_correct_quote_for_the_correct_obligation_still_applies(self):
        """NEGATIVE CONTROL. The fix must not reject good extractions."""
        claim = self._claim("contract.incident_notification_clause",
                            "CIP-013 R1.2.1", self.incident_quote)
        adjudicate([claim], self.docs, critical_fields=set())
        self.assertEqual(claim.tier, "extracted")
        self.assertTrue(claim.applied_value)

    def test_relevance_is_checked_against_the_same_table_the_extractor_uses(self):
        """OFFLINE_SIGNATURES does double duty: it drives the offline extractor
        and checks a model's quote for topical relevance. One table, so the two
        paths cannot drift apart."""
        from vra.procure import OFFLINE_SIGNATURES, quote_is_relevant

        self.assertTrue(quote_is_relevant("contract.incident_notification_clause",
                                          self.incident_quote))
        self.assertFalse(quote_is_relevant("contract.access_termination_notice_clause",
                                           self.incident_quote))
        for target in CLAUSE_TARGETS:
            self.assertIn(target["field"], OFFLINE_SIGNATURES,
                          f"{target['field']} has no relevance signature")

    def test_a_field_with_no_signature_is_not_failed_on_relevance(self):
        """Absent a signature there is nothing to check against, and inventing a
        failure would be worse than not checking."""
        from vra.procure import quote_is_relevant

        self.assertTrue(quote_is_relevant("contract.some_future_clause", "anything at all"))

    def test_the_real_sandbox_extraction_is_unaffected(self):
        """The offline extractor's own output must still pass the new checks."""
        result = extract_procurement(
            "Kestrel Grid Systems", "kestrel-grid", self.docs,
            RunConfig(offline=True), controls=load_cip_controls())
        for claim in result.applied:
            self.assertNotIn("obligation asked", claim.withheld_reason)
        self.assertGreaterEqual(len(result.applied), 5,
                                "the genuine clauses must still be applied")
