"""Validation suite for the NERC CIP module.

This is the "does it actually work" half of the audit deliverable. The other
half is the evidence pack, which shows what a run examined; this shows the
detector discriminates rather than simply alarming.

The load-bearing tests are the negative controls. A detector that only ever
fires proves nothing: "it found the bad firmware" is unfalsifiable unless the
same run stays silent on fourteen good ones. So every positive test here has a
negative twin.
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

from vra.cip import assess_estate, citations_verified, load_cip_controls  # noqa: E402
from vra.cipcrypto import (  # noqa: E402
    KEY_ACTIVE,
    KEY_REVOKED,
    KeyRegistry,
    derive_demo_keypair,
    encode_public_key,
    key_fingerprint,
    sha256_bytes,
    sign_blob,
    verify_package,
    verify_signature,
)
from vra.evidence import build_pack, render_html, render_markdown  # noqa: E402
from vra.grid import load_estate  # noqa: E402
from vra.gridbuild import TAMPERED_PACKAGE, build  # noqa: E402

AS_OF = date(2026, 9, 20)


class CryptoIsReal(unittest.TestCase):
    """The verification must be a cryptographic fact, not a stored field.

    If these pass while `signature_verified` is read from YAML, the whole
    project is a mockup. They are written to fail in that case.
    """

    def setUp(self):
        self.priv, self.pub = derive_demo_keypair("unit-test-vendor")
        self.encoded = encode_public_key(self.pub)
        self.blob = b"\x7fFWIMG" + b"relay firmware payload" * 200

    def test_a_valid_signature_verifies(self):
        sig = sign_blob(self.priv, self.blob)
        self.assertTrue(verify_signature(self.encoded, sig, self.blob))

    def test_flipping_one_byte_breaks_the_signature(self):
        """The single most important assertion in this file."""
        sig = sign_blob(self.priv, self.blob)
        for index in (0, len(self.blob) // 2, len(self.blob) - 1):
            tampered = bytearray(self.blob)
            tampered[index] ^= 0x01  # one bit, not one field
            self.assertFalse(
                verify_signature(self.encoded, sig, bytes(tampered)),
                f"signature still verified after flipping a bit at offset {index}",
            )

    def test_another_vendors_key_does_not_verify(self):
        sig = sign_blob(self.priv, self.blob)
        _, other = derive_demo_keypair("some-other-vendor")
        self.assertFalse(verify_signature(encode_public_key(other), sig, self.blob))

    def test_malformed_signature_returns_false_rather_than_raising(self):
        """An attacker-supplied value must not crash an estate-wide run."""
        for junk in ("", "not base64!!", "AAAA", "x" * 500):
            self.assertFalse(verify_signature(self.encoded, junk, self.blob))

    def test_fingerprint_is_stable_and_key_specific(self):
        self.assertEqual(key_fingerprint(self.encoded), key_fingerprint(self.encoded))
        _, other = derive_demo_keypair("some-other-vendor")
        self.assertNotEqual(key_fingerprint(self.encoded), key_fingerprint(encode_public_key(other)))


class PackageVerificationSemantics(unittest.TestCase):
    """CIP-010 R1.6.1 vs R1.6.2, and the hash-is-not-enough judgement."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.priv, pub = derive_demo_keypair("semantics-vendor")
        self.registry = KeyRegistry([
            {
                "key_id": "k1",
                "vendor": "Semantics Controls",
                "public_key": encode_public_key(pub),
                "status": KEY_ACTIVE,
            }
        ])
        self.blob = b"\x7fFWIMG genuine build" * 100
        (self.tmp / "fw.bin").write_bytes(self.blob)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _package(self, **over):
        pkg = {
            "package_id": "TEST-1.0",
            "vendor": "Semantics Controls",
            "artifact": "fw.bin",
            "published_sha256": sha256_bytes(self.blob),
            "signature": sign_blob(self.priv, self.blob),
            "signing_key_id": "k1",
        }
        pkg.update(over)
        return pkg

    def test_clean_package_passes_both_parts(self):
        """NEGATIVE CONTROL. A correct package must produce nothing."""
        r = verify_package(self._package(), self.registry, root=self.tmp, when=AS_OF)
        self.assertTrue(r.hash_match)
        self.assertTrue(r.signature_verified)
        self.assertTrue(r.source_identity_verified, "R1.6.1 should pass")
        self.assertTrue(r.integrity_verified, "R1.6.2 should pass")

    def test_matching_hash_does_not_rescue_a_bad_signature(self):
        """The planted scenario, in miniature.

        The attacker controls the mirror, so they substitute the binary and the
        published hash together. They cannot forge the signature. A process that
        checks only the hash returns green; R1.6 must not.
        """
        substituted = b"\x7fFWIMG substituted build" * 100
        (self.tmp / "fw.bin").write_bytes(substituted)
        pkg = self._package(published_sha256=sha256_bytes(substituted))  # hash updated too
        r = verify_package(pkg, self.registry, root=self.tmp, when=AS_OF)
        self.assertTrue(r.hash_match, "the hash check should pass — that is the point")
        self.assertFalse(r.signature_verified)
        self.assertFalse(r.source_identity_verified)
        self.assertFalse(r.integrity_verified, "hash alone must not satisfy R1.6.2")

    def test_revoked_key_fails_source_identity_despite_valid_signature(self):
        revoked = KeyRegistry([
            {
                "key_id": "k1",
                "vendor": "Semantics Controls",
                "public_key": self.registry.get("k1").public_key,
                "status": KEY_REVOKED,
            }
        ])
        r = verify_package(self._package(), revoked, root=self.tmp, when=AS_OF)
        self.assertTrue(r.signature_verified, "the maths is still valid")
        self.assertFalse(r.signing_key_trusted)
        self.assertFalse(r.source_identity_verified, "a revoked key establishes no source")

    def test_unknown_signer_is_not_trusted(self):
        r = verify_package(
            self._package(signing_key_id="never-registered"),
            self.registry, root=self.tmp, when=AS_OF,
        )
        self.assertFalse(r.signature_verified)
        self.assertFalse(r.signing_key_trusted)
        self.assertEqual(r.signing_key_status, "unknown")

    def test_hash_only_vendor_is_marked_as_the_weaker_check(self):
        r = verify_package(
            {
                "package_id": "T", "vendor": "No Key Co", "artifact": "fw.bin",
                "published_sha256": sha256_bytes(self.blob),
            },
            KeyRegistry([]), root=self.tmp, when=AS_OF,
        )
        self.assertEqual(r.verification_strength, "hash_only")
        self.assertTrue(r.integrity_verified)
        self.assertIsNone(r.source_identity_verified, "no key means source is unevaluable")

    def test_missing_artifact_is_unevaluable_not_passing(self):
        r = verify_package(
            self._package(artifact="does-not-exist.bin"),
            self.registry, root=self.tmp, when=AS_OF,
        )
        self.assertFalse(r.artifact_present)
        self.assertIsNone(r.integrity_verified, "a missing binary must never read as a pass")


class EstateDetection(unittest.TestCase):
    """End to end over the real sandbox estate."""

    @classmethod
    def setUpClass(cls):
        cls.grid = Path(tempfile.mkdtemp()) / "grid"
        build(cls.grid, today=AS_OF)
        cls.controls = load_cip_controls()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.grid.parent, ignore_errors=True)

    def _run(self, substations=300):
        estate = load_estate(self.grid, substations=substations, today=AS_OF)
        return (estate, *assess_estate(estate, self.controls, when=AS_OF))

    def test_exactly_one_package_fails_verification(self):
        """NEGATIVE CONTROL at estate scale.

        Fourteen good packages must stay silent while one fires. If this ever
        reports more than one, the detector is producing false positives and no
        number it prints can be trusted.
        """
        _, _, _, verified, _ = self._run()
        failing = sorted(
            p for p, r in verified.items()
            if r.integrity_verified is not True or r.source_identity_verified is not True
        )
        self.assertEqual(failing, [TAMPERED_PACKAGE])

    def test_the_tampered_package_passes_the_hash_check(self):
        """If this ever fails, the demo has lost its point."""
        _, _, _, verified, _ = self._run()
        r = verified[TAMPERED_PACKAGE]
        self.assertTrue(r.hash_match)
        self.assertFalse(r.signature_verified)

    def test_firmware_findings_all_trace_to_the_tampered_package(self):
        _, findings, _, _, _ = self._run()
        firmware = [f for f in findings if f.control.id in ("CIP-01", "CIP-02")]
        self.assertTrue(firmware, "expected firmware findings")
        for f in firmware:
            self.assertIn(
                TAMPERED_PACKAGE,
                (f.provenance.get("firmware_verification") or {}).get("value", ""),
            )

    def test_low_impact_assets_are_scoped_out_not_passed(self):
        """CIP-002 applicability. ~89% of the estate is low impact.

        A run that ignored this would raise CIP-013 and CIP-010 findings across
        the whole estate, almost all of them wrong.
        """
        estate, _, _, _, coverage = self._run()
        cov = coverage["CIP-01"]
        low = sum(1 for d in estate.deployments if d["impact_rating"] == "low")
        self.assertEqual(cov.in_population, len(estate.deployments))
        self.assertEqual(cov.in_population - cov.applicable, low)
        self.assertGreater(low, cov.applicable, "the estate should be mostly low impact")

    def test_coverage_accounts_for_every_applicable_subject(self):
        """Nothing may be silently skipped: applicable == pass + fail + gap."""
        _, _, _, _, coverage = self._run()
        for cid, cov in coverage.items():
            self.assertEqual(
                cov.applicable, cov.passed + cov.failed + cov.gapped,
                f"{cid} loses subjects between applicability and outcome",
            )

    def test_every_finding_carries_a_nerc_citation_and_no_other_framework(self):
        _, findings, gaps, _, _ = self._run()
        self.assertTrue(findings)
        for a in findings + gaps:
            self.assertTrue(a.control.citation.startswith("CIP-"), a.control.citation)
            for fw in a.control.frameworks:
                self.assertEqual(fw["name"], "NERC CIP")

    def test_run_is_deterministic(self):
        """Same seed, same date, same answer. An audit artifact that moves
        between runs cannot be reconciled with the one filed last quarter."""
        a = self._run()[1]
        b = self._run()[1]
        self.assertEqual(sorted(x.id for x in a), sorted(x.id for x in b))

    def test_severity_comes_from_yaml_only(self):
        _, findings, _, _, _ = self._run()
        by_id = {c.id: c for c in self.controls}
        for f in findings:
            self.assertEqual(f.control.severity, by_id[f.control.id].severity)


class ControlSetIntegrity(unittest.TestCase):
    """Structural rules the control set must keep."""

    def setUp(self):
        self.controls = load_cip_controls()

    def test_every_control_cites_nerc_with_a_pinned_requirement(self):
        for c in self.controls:
            self.assertTrue(c.frameworks, f"{c.id} cites nothing")
            for fw in c.frameworks:
                self.assertEqual(fw.get("name"), "NERC CIP", c.id)
                for key in ("standard", "version", "requirement", "part"):
                    self.assertTrue(str(fw.get(key, "")).strip(), f"{c.id} missing {key}")

    def test_every_citation_carries_a_human_verification_checkpoint(self):
        """The field must exist. Whether it is true is a human's job.

        This asserts the checkpoint is present, not that it has been used --
        failing the build on unverified citations would leave the repo red from
        the first commit. The evidence pack and the CLI both surface the count
        loudly instead.
        """
        for c in self.controls:
            for fw in c.frameworks:
                self.assertIn("citation_verified", fw, c.id)
                self.assertIn("citation_verified_by", fw, c.id)

    def test_no_control_cites_nist_or_soc2(self):
        """The NERC set is deliberately single-framework."""
        for c in self.controls:
            self.assertNotIn("800-53", c.citation)
            self.assertNotIn("CC6", c.citation)
            self.assertNotIn("TSC", c.citation)

    def test_every_control_has_remediation_and_a_known_severity(self):
        for c in self.controls:
            self.assertTrue(c.remediation.strip(), f"{c.id} has no remediation")
            self.assertIn(c.severity, ("critical", "high", "medium", "low"), c.id)

    def test_cip013_controls_are_scoped_to_high_and_medium_impact(self):
        """CIP-013 attaches to high and medium impact BES Cyber Systems."""
        for c in self.controls:
            if not any(f.get("standard") == "CIP-013" for f in c.frameworks):
                continue
            scoping = [
                cond for cond in c.applies_when
                if cond.get("field") in ("impact_rating", "supplies_impact_rating")
            ]
            self.assertTrue(scoping, f"{c.id} is unscoped by impact rating")
            self.assertEqual(scoping[0].get("in"), ["high", "medium"], c.id)

    def test_citation_counter_matches_the_file(self):
        ok, total = citations_verified(self.controls)
        self.assertEqual(total, sum(len(c.frameworks) for c in self.controls))
        self.assertLessEqual(ok, total)


class EvidencePack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grid = Path(tempfile.mkdtemp()) / "grid"
        build(cls.grid, today=AS_OF)
        controls = load_cip_controls()
        estate = load_estate(cls.grid, substations=200, today=AS_OF)
        findings, gaps, verified, coverage = assess_estate(estate, controls, when=AS_OF)
        cls.pack = build_pack(estate, controls, findings, gaps, verified, coverage, when=AS_OF)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.grid.parent, ignore_errors=True)

    def test_pack_never_claims_compliance(self):
        """A tool that asserts compliance is selling a liability."""
        text = (render_markdown(self.pack) + render_html(self.pack)).lower()
        for phrase in ("is compliant", "fully compliant", "compliance achieved",
                       "certifies compliance", "guarantees compliance"):
            self.assertNotIn(phrase, text)

    def test_pack_declares_the_data_is_synthetic(self):
        for rendered in (render_markdown(self.pack), render_html(self.pack)):
            self.assertIn("SYNTHETIC", rendered.upper())

    def test_pack_warns_while_citations_are_unverified(self):
        self.assertGreater(self.pack["citations_unverified"], 0)
        self.assertIn("not verified", render_markdown(self.pack).lower())
        self.assertIn("not verified", render_html(self.pack).lower())

    def test_every_requirement_reports_a_denominator(self):
        for req in self.pack["requirements"]:
            self.assertIn("in_population", req["coverage"])
            self.assertGreaterEqual(req["coverage"]["in_population"], req["coverage"]["applicable"])

    def test_firmware_exceptions_carry_the_computed_hash_as_evidence(self):
        firmware = [r for r in self.pack["requirements"]
                    if r["control_id"] == "CIP-01" and r["exception_count"]]
        self.assertTrue(firmware, "expected CIP-01 exceptions in the sandbox estate")
        evidence = firmware[0]["root_causes"][0]["evidence"]
        self.assertIn("computed SHA-256", evidence)
        self.assertIn("Ed25519 verify", evidence)

    def test_exceptions_are_grouped_to_one_root_cause(self):
        firmware = [r for r in self.pack["requirements"] if r["control_id"] == "CIP-01"][0]
        self.assertEqual(len(firmware["root_causes"]), 1)
        self.assertEqual(firmware["root_causes"][0]["affected"], firmware["exception_count"])

    def test_html_escapes_rendered_values(self):
        self.assertNotIn("<script>", render_html(self.pack))


if __name__ == "__main__":
    unittest.main()


class LowImpactVendorAccessScoping(unittest.TestCase):
    """CIP-003-9 Attachment 1 Section 6 — the population CIP-013 does not cover.

    The earlier scoping treated high and medium impact as the whole story. These
    tests pin the correction: vendor remote access has a wider population than
    CIP-013, and the two must not be collapsed in either direction.
    """

    @classmethod
    def setUpClass(cls):
        cls.grid = Path(tempfile.mkdtemp()) / "grid"
        build(cls.grid, today=AS_OF)
        cls.controls = load_cip_controls()
        cls.estate = load_estate(cls.grid, substations=600, today=AS_OF)
        cls.findings, cls.gaps, _, cls.coverage = assess_estate(
            cls.estate, cls.controls, when=AS_OF
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.grid.parent, ignore_errors=True)

    def _cip003(self):
        return [c for c in self.controls
                if any(f.get("standard") == "CIP-003" for f in c.frameworks)]

    def test_cip003_controls_exist_and_target_low_impact(self):
        controls = self._cip003()
        self.assertTrue(controls, "CIP-003-9 Section 6 controls are missing")
        for c in controls:
            scope = {cond.get("field"): cond for cond in c.applies_when}
            self.assertEqual(scope["impact_rating"].get("equals"), "low", c.id)
            self.assertTrue(
                scope["allows_vendor_electronic_remote_access"].get("equals"),
                f"{c.id} must only apply where vendor access is actually allowed",
            )

    def test_low_impact_assets_with_vendor_access_are_assessed(self):
        """The whole point of the correction: these used not to exist."""
        expected = sum(
            1 for a in self.estate.access_sessions
            if a.get("impact_rating") == "low"
            and a.get("allows_vendor_electronic_remote_access")
        )
        self.assertGreater(expected, 0, "the estate should generate low impact vendor access")
        for control in self._cip003():
            self.assertEqual(self.coverage[control.id].applicable, expected, control.id)

    def test_low_impact_without_vendor_access_stays_out_of_scope(self):
        """Not every low impact asset is swept in. Only those with a path."""
        low_total = sum(1 for s in self.estate.substations if s["impact_rating"] == "low")
        for control in self._cip003():
            self.assertLess(
                self.coverage[control.id].applicable, low_total,
                f"{control.id} must not apply to every low impact asset",
            )

    def test_cip013_still_excludes_low_impact(self):
        """The correction must not leak upward. CIP-013 did not change."""
        for control in self.controls:
            if not any(f.get("standard") == "CIP-013" for f in control.frameworks):
                continue
            scoping = [c for c in control.applies_when
                       if c.get("field") in ("impact_rating", "supplies_impact_rating")]
            self.assertTrue(scoping, control.id)
            self.assertEqual(scoping[0].get("in"), ["high", "medium"], control.id)

    def test_the_two_populations_are_different(self):
        """A vendor-access population identical to the CIP-013 population would
        mean the correction did nothing."""
        cip003_pop = self.coverage["CIP-31"].applicable
        cip005_pop = self.coverage["CIP-16"].applicable
        self.assertNotEqual(cip003_pop, cip005_pop)

    def test_no_control_cites_cip015(self):
        """CIP-015-1 is approved but not enforceable until 1 October 2028.

        Citing it would be claiming an obligation that does not yet apply, which
        is the same class of error as citing a superseded revision.
        """
        for control in self.controls:
            for framework in control.frameworks:
                self.assertNotEqual(framework.get("standard"), "CIP-015", control.id)
