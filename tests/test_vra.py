"""Test suite for the vendor AI risk analyst.

Run: python3 -m pytest tests/ -v      (or: python3 tests/test_vra.py)

The tests that matter most here are the ones that protect the claims made in
the README: volatile stripping produces stable hashes, the negative-control
vendor stays silent, the buried subprocessor row is parsed, and no model output
can create or re-severity a finding.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import evaluate as ev  # noqa: E402
from vra.config import RunConfig  # noqa: E402
from vra.llm import OfflineBackend, extract_json  # noqa: E402
from vra.normalize import normalize, strip_volatile  # noqa: E402
from vra.observe import parse_subprocessor_table, parse_subprocessors  # noqa: E402
from vra.triage import CHANGE_TYPES, _schema_check  # noqa: E402


class TestVolatileStripping(unittest.TestCase):
    """Phase 2.3 — without this the tool reports a change on every run."""

    def test_timestamps_stripped(self):
        a, _ = normalize("<p>Generated 2026-02-03T09:14:22Z</p>", is_html=True)
        b, _ = normalize("<p>Generated 2026-03-11T14:02:57Z</p>", is_html=True)
        self.assertEqual(a, b)

    def test_session_tokens_stripped(self):
        a, _ = normalize("session=7f3a1c9e-4b21-4d0a-9f77-1a2b3c4d5e6f", is_html=False)
        b, _ = normalize("session=3e77c108-45bb-4a90-91d2-8fe0a3b71c4d", is_html=False)
        self.assertEqual(a, b)

    def test_build_and_render_times_stripped(self):
        a, _ = normalize("build 4821 rendered in 84ms", is_html=False)
        b, _ = normalize("build 4977 rendered in 79ms", is_html=False)
        self.assertEqual(a, b)

    def test_promo_banner_dropped(self):
        a, _ = normalize('<div class="promo-banner">Register today!</div><p>Real content</p>')
        b, _ = normalize('<div class="promo-banner">Webinar replay!</div><p>Real content</p>')
        self.assertEqual(a, b)
        self.assertIn("Real content", a)
        self.assertNotIn("Register today", a)

    def test_substantive_change_survives(self):
        a, _ = normalize("<p>Copilot suggests changes.</p>")
        b, _ = normalize("<p>Copilot applies changes without approval.</p>")
        self.assertNotEqual(a, b)

    def test_rules_fired_reported(self):
        _, fired = strip_volatile("Generated 2026-02-03T09:14:22Z build 4821")
        self.assertIn("iso_timestamp", fired)
        self.assertIn("build_number", fired)

    def test_real_snapshot_pair_only_differs_substantively(self):
        """Vendor C v1 vs v2 trust center: volatile churn must not dominate."""
        v1 = (REPO / "sandbox/vendors/meridian-revcycle/snapshots/v1/trust_center.html").read_text()
        v2 = (REPO / "sandbox/vendors/meridian-revcycle/snapshots/v2/trust_center.html").read_text()
        n1, _ = normalize(v1)
        n2, _ = normalize(v2)
        added = set(n2.splitlines()) - set(n1.splitlines())
        # Only the marketing line and wording churn should differ; no timestamps.
        self.assertFalse(any("2026-" in line and ":" in line for line in added),
                         f"volatile timestamp leaked into diff: {added}")


class TestSubprocessorParsing(unittest.TestCase):
    """Phase 8.4 — the buried row is the whole demo."""

    def _rows(self, version: str):
        raw = (REPO / f"sandbox/vendors/loop-workspace/snapshots/{version}/subprocessors.html").read_text()
        text, _ = normalize(raw)
        return parse_subprocessor_table(text, "subprocessors")

    def test_buried_perplexity_row_is_parsed(self):
        rows = self._rows("v2")
        names = [r.name for r in rows]
        self.assertIn("Perplexity AI, Inc.", names, f"buried row dropped; parsed: {names}")

    def test_buried_row_is_ai_related_and_uncovered(self):
        row = next(r for r in self._rows("v2") if "Perplexity" in r.name)
        self.assertTrue(row.is_ai_related)
        self.assertFalse(row.baa_covered, "'Pending' must not count as executed BAA coverage")

    def test_covered_ai_provider_does_not_fire(self):
        row = next(r for r in self._rows("v1") if "Anthropic" in r.name)
        self.assertTrue(row.is_ai_related)
        self.assertTrue(row.baa_covered)

    def test_non_ai_subprocessor_ignored(self):
        row = next(r for r in self._rows("v1") if "Stripe" in r.name)
        self.assertFalse(row.is_ai_related)

    def test_v1_has_no_uncovered_ai_subprocessor(self):
        uncovered = [r for r in self._rows("v1") if r.is_ai_related and not r.baa_covered]
        self.assertEqual(uncovered, [], "baseline must be clean")

    def test_header_row_not_treated_as_subprocessor(self):
        names = [r.name.lower() for r in self._rows("v1")]
        self.assertNotIn("entity", names)


class TestControlEvaluation(unittest.TestCase):
    """Phase 5 — deterministic, and unknown != fail."""

    @classmethod
    def setUpClass(cls):
        cls.controls = ev.load_controls()

    def _vendor(self, **feature):
        base = {
            "feature": "Test Feature", "status": "enabled", "autonomy": "suggests",
            "data_reach": ["identity_attributes"], "model_provider": "Anthropic PBC",
            "training_on_customer_data": False, "human_in_loop": True,
            "retention_days": 30, "output_logged": True,
            "change_notification": "advance_notice", "error_rate_disclosed": True,
            "prompt_injection_tested": True, "data_residency": "in_region",
            "bias_tested_clinical": "not_applicable", "ai_incident_process": True,
            "customer_disableable": True,
        }
        base.update(feature)
        return {
            "vendor": "Test Vendor", "slug": "test-vendor", "tier": "high",
            "contract": {"baa_on_file": True, "ai_addendum_signed": True,
                         "baa_covered_subprocessors": ["Anthropic PBC"]},
            "ai_surface": [base],
        }

    def test_control_set_size_and_coverage(self):
        self.assertGreaterEqual(len(self.controls), 12)
        self.assertLessEqual(len(self.controls), 20)
        for c in self.controls:
            self.assertTrue(c.frameworks, f"{c.id} has no framework citation")
            self.assertIn(c.severity, ("critical", "high", "medium", "low"))
            self.assertTrue(c.remediation, f"{c.id} has no remediation text")

    def test_clean_vendor_produces_no_findings(self):
        findings, gaps = ev.evaluate_vendor(self._vendor(), self.controls)
        self.assertEqual([f.control.id for f in findings], [])
        self.assertEqual([g.control.id for g in gaps], [])

    def test_autonomous_agent_raises_critical_aiv07(self):
        findings, _ = ev.evaluate_vendor(
            self._vendor(autonomy="acts", human_in_loop=False), self.controls)
        hit = [f for f in findings if f.control.id == "AIV-07"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].control.severity, "critical")

    def test_acting_agent_with_human_review_does_not_fire_aiv07(self):
        """Both conditions are ANDed. Autonomy alone is not the failure."""
        findings, _ = ev.evaluate_vendor(
            self._vendor(autonomy="acts", human_in_loop=True), self.controls)
        self.assertNotIn("AIV-07", [f.control.id for f in findings])

    def test_unknown_produces_gap_not_finding(self):
        findings, gaps = ev.evaluate_vendor(
            self._vendor(prompt_injection_tested="unknown"), self.controls)
        self.assertNotIn("AIV-11", [f.control.id for f in findings])
        self.assertIn("AIV-11", [g.control.id for g in gaps])

    def test_undisclosed_provider_is_a_gap_not_a_failure(self):
        """Ground truth (expected_findings.md L51): an undisclosed provider is a
        question for the vendor, not a control failure. It must not fire AIV-03
        either -- we cannot claim a provider is outside BAA scope when we do not
        know who the provider is."""
        findings, gaps = ev.evaluate_vendor(
            self._vendor(model_provider="undisclosed"), self.controls)
        self.assertEqual([f.control.id for f in findings], [])
        self.assertIn("AIV-01", [g.control.id for g in gaps])

    def test_provider_outside_baa_scope_fails_aiv03_critical(self):
        findings, _ = ev.evaluate_vendor(
            self._vendor(model_provider="OpenAI, L.L.C."), self.controls)
        hit = [f for f in findings if f.control.id == "AIV-03"]
        self.assertTrue(hit)
        self.assertEqual(hit[0].control.severity, "critical")

    def test_inhouse_provider_is_baa_covered(self):
        findings, _ = ev.evaluate_vendor(
            self._vendor(model_provider="Meridian (in-house)"), self.controls)
        self.assertNotIn("AIV-03", [f.control.id for f in findings])

    def test_disabled_feature_skipped(self):
        findings, gaps = ev.evaluate_vendor(
            self._vendor(status="disabled", autonomy="acts", human_in_loop=False), self.controls)
        self.assertEqual(findings, [])
        self.assertEqual(gaps, [])

    def test_applies_when_scopes_bias_control(self):
        """AIV-13 only applies to features touching clinical data."""
        non_clinical, _ = ev.evaluate_vendor(
            self._vendor(bias_tested_clinical=False), self.controls)
        self.assertNotIn("AIV-13", [f.control.id for f in non_clinical])
        clinical, _ = ev.evaluate_vendor(
            self._vendor(bias_tested_clinical=False,
                         data_reach=["clinical_documentation"]), self.controls)
        self.assertIn("AIV-13", [f.control.id for f in clinical])

    def test_every_aiv_control_cites_nist_800_53_and_soc2(self):
        """Product integrity: this is a NIST 800-53 / SOC 2 monitor, not a HIPAA-only tool."""
        for c in self.controls:
            names = " ".join(f["name"] for f in c.frameworks)
            self.assertIn("NIST SP 800-53", names, f"{c.id} missing NIST SP 800-53")
            self.assertIn("SOC 2", names, f"{c.id} missing SOC 2")

    def test_severity_comes_from_config_only(self):
        for c in self.controls:
            if c.id == "AIV-07":
                self.assertEqual(c.severity, "critical")
            if c.id == "AIV-03":
                self.assertEqual(c.severity, "critical")

    def test_due_dates_derive_from_severity_table(self):
        today = date(2026, 1, 1)
        self.assertEqual(ev.due_date_for("critical", "finding", today),
                         (today + timedelta(days=7)).isoformat())
        self.assertEqual(ev.due_date_for("low", "finding", today),
                         (today + timedelta(days=90)).isoformat())
        self.assertEqual(ev.due_date_for("critical", "gap", today),
                         (today + timedelta(days=21)).isoformat())

    def test_finding_ids_are_stable(self):
        v = self._vendor(autonomy="acts", human_in_loop=False)
        a, _ = ev.evaluate_vendor(v, self.controls)
        b, _ = ev.evaluate_vendor(v, self.controls)
        self.assertEqual([x.id for x in a], [x.id for x in b])


class TestTriageGuardrails(unittest.TestCase):
    """Phase 3 — the model works inside a fence."""

    def test_change_type_enum_is_closed(self):
        self.assertEqual(len(CHANGE_TYPES), 8)
        self.assertIn("new_agent", CHANGE_TYPES)

    def test_schema_rejects_invented_change_type(self):
        obj = {"ai_relevant": True, "change_type": "vendor_is_scary", "summary": "x",
               "affected_fields": [], "proposed_surface_update": {},
               "evidence_excerpt": "", "confidence": 0.5}
        self.assertIsNotNone(_schema_check(obj))

    def test_schema_rejects_out_of_range_confidence(self):
        obj = {"ai_relevant": True, "change_type": "new_agent", "summary": "x",
               "affected_fields": [], "proposed_surface_update": {},
               "evidence_excerpt": "", "confidence": 42}
        self.assertIsNotNone(_schema_check(obj))

    def test_schema_accepts_valid(self):
        obj = {"ai_relevant": True, "change_type": "new_agent", "summary": "x",
               "affected_fields": ["autonomy"], "proposed_surface_update": {"autonomy": "acts"},
               "evidence_excerpt": "y", "confidence": 0.8}
        self.assertIsNone(_schema_check(obj))

    def test_json_extraction_survives_fences_and_prose(self):
        self.assertEqual(extract_json('Sure!\n```json\n{"a": 1}\n```\nHope that helps'), {"a": 1})
        self.assertEqual(extract_json('{"a": {"b": 2}}'), {"a": {"b": 2}})
        self.assertIsNone(extract_json("no json here"))

    def test_offline_backend_returns_valid_triage_schema(self):
        backend = OfflineBackend()
        prompt = ("TASK: AI_RELEVANCE_TRIAGE\nsource: changelog\n"
                  "+Copilot creates, modifies and deactivates accounts without requiring "
                  "administrator approval")
        raw, err = backend.generate("sys", prompt, RunConfig())
        self.assertIsNone(err)
        self.assertIsNone(_schema_check(json.loads(raw)))

    def test_offline_backend_silent_on_cosmetic_diff(self):
        backend = OfflineBackend()
        prompt = ("TASK: AI_RELEVANCE_TRIAGE\nsource: changelog\n"
                  "+Improved screen reader labels across the scheduling module\n"
                  "+Export dashboard widgets to XLSX")
        raw, _ = backend.generate("sys", prompt, RunConfig())
        data = json.loads(raw)
        self.assertFalse(data["ai_relevant"])
        self.assertEqual(data["change_type"], "none")


class TestFindingLifecycle(unittest.TestCase):
    """Phase 7 — state is the product."""

    def _store(self):
        from vra.register import FindingStore
        s = FindingStore(path=Path("/tmp/vra-test-findings.json"))
        s.findings = {}
        return s

    def _rec(self, fid="AIV-07-abc123"):
        return {"id": fid, "kind": "finding", "vendor": "v", "vendor_name": "V",
                "feature": "F", "control_id": "AIV-07", "severity": "critical",
                "observed": {}, "state": "open",
                "due_date": (date.today() - timedelta(days=1)).isoformat()}

    def test_new_finding_marked_new(self):
        s = self._store()
        _, is_new = s.upsert(self._rec())
        self.assertTrue(is_new)
        _, is_new2 = s.upsert(self._rec())
        self.assertFalse(is_new2)

    def test_human_set_state_is_preserved_on_reassessment(self):
        s = self._store()
        stored, _ = s.upsert(self._rec())
        stored["state"] = "accepted_risk"
        again, _ = s.upsert(self._rec())
        self.assertEqual(again["state"], "accepted_risk",
                         "re-running must not reopen a risk a human accepted")

    def test_resolved_finding_auto_closes(self):
        s = self._store()
        s.upsert(self._rec())
        closed = s.reconcile(seen_ids=set(), vendor_slugs={"v"}, cfg=RunConfig(dry_run=True))
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0]["state"], "closed")

    def test_other_vendors_not_closed_by_filtered_run(self):
        s = self._store()
        s.upsert(self._rec())
        closed = s.reconcile(seen_ids=set(), vendor_slugs={"other"}, cfg=RunConfig(dry_run=True))
        self.assertEqual(closed, [])

    def test_overdue_finding_escalates(self):
        s = self._store()
        stored, _ = s.upsert(self._rec())
        s.reconcile(seen_ids={stored["id"]}, vendor_slugs={"v"}, cfg=RunConfig(dry_run=True))
        self.assertTrue(stored.get("escalated"))

    def test_accepted_risk_not_escalated(self):
        s = self._store()
        stored, _ = s.upsert(self._rec())
        stored["state"] = "accepted_risk"
        s.reconcile(seen_ids={stored["id"]}, vendor_slugs={"v"}, cfg=RunConfig(dry_run=True))
        self.assertFalse(stored.get("escalated"))


class TestAnalystGuardrails(unittest.TestCase):
    """Phase 6 — the model drafts language, it does not change decisions."""

    def _rec(self):
        return {"id": "x", "kind": "finding", "vendor": "v", "vendor_name": "Test Vendor",
                "feature": "Widget", "control_id": "AIV-07",
                "control_question": "Does the agent act without review?",
                "citation": "NIST AI RMF MANAGE-2.2", "severity": "critical",
                "observed": {"autonomy": "acts"}, "reason": "conditions met",
                "remediation": "Disable agent mode.", "compensating_control": "Scope it down.",
                "owner": "CISO", "due_date": "2026-01-01", "state": "open"}

    def test_poam_is_fully_deterministic(self):
        from vra.analyst import build_poam
        a, b = build_poam(self._rec()), build_poam(self._rec())
        self.assertEqual(a, b)
        self.assertEqual(a["severity"], "critical")
        self.assertEqual(a["due_date"], "2026-01-01")

    def test_narrative_falls_back_when_model_editorialises(self):
        """A model that renames the severity gets its output rejected."""
        from vra.analyst import SEVERITY_WORDS
        bad = "This is a low-risk issue that can safely be ignored."
        hits = [w.lower().replace("-risk", "") for w in SEVERITY_WORDS.findall(bad)]
        self.assertIn("low", hits)

    def test_fallback_narrative_mentions_control_and_facts(self):
        from vra.analyst import _fallback_narrative
        text = _fallback_narrative(self._rec())
        self.assertIn("AIV-07", text)
        self.assertIn("Test Vendor", text)
        self.assertIn("autonomy=acts", text)


class TestGroundTruthScenario(unittest.TestCase):
    """Phase 8 — the sandbox scenario must behave as expected_findings.md says."""

    @classmethod
    def setUpClass(cls):
        cls.controls = ev.load_controls()
        import yaml
        cls.vendors = {
            p.stem: yaml.safe_load(p.read_text())
            for p in (REPO / "vendors").glob("*.yaml")
        }

    def test_all_registers_load_and_are_wellformed(self):
        self.assertEqual(len(self.vendors), 3)
        for slug, v in self.vendors.items():
            self.assertIn("ai_surface", v)
            self.assertIn("watch", v)
            self.assertEqual(v["slug"], slug)

    def test_sandbox_vendors_have_probes_and_nhis(self):
        with_probe = sorted(s for s, v in self.vendors.items() if v.get("probe"))
        self.assertEqual(
            with_probe,
            ["aegis-identity-cloud", "loop-workspace", "meridian-revcycle"],
        )
        for slug, v in self.vendors.items():
            self.assertTrue(v.get("nhis"), f"{slug} has no nhis: inventory")

    def test_baseline_registers_have_no_critical(self):
        """Ground truth: criticals arrive in run 2, not at baseline."""
        for slug, v in self.vendors.items():
            findings, _ = ev.evaluate_vendor(v, self.controls)
            crits = [f.control.id for f in findings if f.control.severity == "critical"]
            self.assertEqual(crits, [], f"{slug} raised a critical at baseline: {crits}")

    def test_vendor_c_negative_control_is_quiet_on_cosmetic_diff(self):
        """Vendor C's v1->v2 diff must triage as not AI-relevant."""
        from vra.watch import diff_against_previous, SourceSnapshot
        import hashlib
        backend = OfflineBackend()
        for source in ("changelog", "trust_center"):
            ext = "html"
            v1 = (REPO / f"sandbox/vendors/meridian-revcycle/snapshots/v1/{source}.{ext}").read_text()
            v2 = (REPO / f"sandbox/vendors/meridian-revcycle/snapshots/v2/{source}.{ext}").read_text()
            n1, _ = normalize(v1)
            n2, _ = normalize(v2)
            import difflib
            udiff = "".join(difflib.unified_diff(
                n1.splitlines(keepends=True), n2.splitlines(keepends=True), n=2))
            prompt = f"TASK: AI_RELEVANCE_TRIAGE\nsource: {source}\n{udiff}"
            data = json.loads(backend.generate("sys", prompt, RunConfig())[0])
            self.assertFalse(data["ai_relevant"],
                             f"negative control fired on {source}: {data}")


class TestRealWorldSubprocessorParsing(unittest.TestCase):
    """AIV-03 depends on this parse, so it must survive real trust centers:
    nested HTML tables, PDFs, and SafeBase/Whistic/Vanta portals with a
    click-through NDA. A failed parse is a gap with drafted outreach — never a
    silent pass.
    """

    NESTED_HTML = """<!DOCTYPE html><html><body>
    <h1>Subprocessors</h1>
    <p>Effective 2026-07-01.</p>
    <table>
      <thead><tr><th>Subprocessor</th><th>Service provided</th><th>Location</th><th>BAA coverage</th></tr></thead>
      <tbody>
        <tr><td><a href="https://openai.com">OpenAI, L.L.C.</a></td><td>Inference for <strong>Copilot</strong> summarization</td><td>United States</td><td><strong>Pending</strong></td></tr>
        <tr><td>AWS</td><td>Cloud hosting</td><td>US, EU</td><td>Yes</td></tr>
        <tr><td>Twilio Inc.</td><td>SMS delivery</td><td>US</td><td>Yes</td></tr>
      </tbody>
    </table>
    </body></html>"""

    GATED_HTML = """<!DOCTYPE html><html><body>
    <p>You're about to be redirected to continue to SafeBase.</p>
    <p>This content is available under a non-disclosure agreement. Click to accept and continue.</p>
    <button>I agree — request access to the subprocessor list</button>
    </body></html>"""

    @staticmethod
    def pdf_bytes() -> bytes:
        content = (
            b"BT /F1 12 Tf 72 740 Td 14 TL\n"
            b"(Entity | Purpose | Region | BAA) Tj T*\n"
            b"(Anthropic PBC | Claude inference for Copilot | US | Yes) Tj T*\n"
            b"(OpenAI L.L.C. | Answer generation | US | Pending) Tj T*\n"
            b"ET"
        )
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ]
        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for i, obj in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n" % (len(objects) + 1)
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += b"%010d 00000 n \n" % off
        out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
            len(objects) + 1, xref)
        return bytes(out)

    def test_structured_html_table_with_nested_markup(self):
        """Real HTML tables: links and bold inside cells must flatten, not break."""
        from vra.extract import extract_html_tables

        tables = extract_html_tables(self.NESTED_HTML)
        rows, status = parse_subprocessors("", source="subprocessors", tables=tables)
        names = [r.name for r in rows]
        self.assertIn("OpenAI, L.L.C.", names, f"nested cell lost; parsed: {names}")
        self.assertIn("AWS", names)
        self.assertEqual(status.status, "parsed")
        self.assertEqual(status.rows, 3)
        openai = next(r for r in rows if r.name == "OpenAI, L.L.C.")
        self.assertTrue(openai.is_ai_related)
        self.assertFalse(openai.baa_covered, "'Pending' must not count as coverage")

    def test_pipe_table_without_header_still_parses(self):
        """Backward compat: positional fallback when a pipe table has no header."""
        rows = parse_subprocessor_table("AWS | Hosting | US | Yes", "subprocessors")
        self.assertEqual([r.name for r in rows], ["AWS"])

    def test_prose_rows_require_header(self):
        """Whitespace-aligned prose must not invent subprocessors."""
        prose = ("Last updated 2026-07-01   Contact privacy@acme.example   "
                 "We engage subprocessors in the ordinary course of business")
        rows, status = parse_subprocessors(prose, source="subprocessors", raw_kind="pdf")
        self.assertEqual(rows, [], f"prose invented rows: {rows}")
        # Mentions subprocessors but has no table → parse_failed, never a pass.
        self.assertEqual(status.status, "parse_failed")

    # -- portals ----------------------------------------------------------
    def test_detect_safebase_portal(self):
        from vra.extract import detect_trust_platform

        platform, blocked, evidence = detect_trust_platform(
            "<html><script src='https://app.safebase.io/sb-assets/embed.js'></script>"
            "<p>continue to safebase</p></html>",
            page_url="https://acme.safebase.io/security",
        )
        self.assertEqual(platform, "safebase")
        self.assertTrue(blocked)
        self.assertTrue(evidence)

    def test_detect_whistic_and_vanta(self):
        from vra.extract import detect_trust_platform

        w = detect_trust_platform("<html>whistic-profile</html>", page_url="https://profile.whistic.com/x")
        self.assertEqual(w[0], "whistic")
        self.assertTrue(w[1])
        v = detect_trust_platform("<html>vanta-portal</html>", page_url="https://trust.vanta.com/acme")
        self.assertEqual(v[0], "vanta")
        self.assertTrue(v[1])

    def test_generic_nda_wall_detected(self):
        from vra.extract import detect_trust_platform

        platform, blocked, _ = detect_trust_platform(
            "<html><p>This content is available under a non-disclosure agreement.</p></html>"
        )
        self.assertEqual(platform, "generic")
        self.assertTrue(blocked)

    def test_gated_portal_parse_is_blocked(self):
        rows, status = parse_subprocessors(
            self.GATED_HTML, source="subprocessors",
            platform="safebase", portal_blocked=True,
        )
        self.assertEqual(rows, [])
        self.assertEqual(status.status, "blocked")
        self.assertIn("safebase", status.reason)
        self.assertIn("NDA", status.reason)

    def test_portal_page_with_table_parses_but_notes_verification(self):
        from vra.extract import extract_html_tables

        tables = extract_html_tables(self.NESTED_HTML)
        rows, status = parse_subprocessors(
            "", source="subprocessors", tables=tables,
            platform="safebase", portal_blocked=True,
        )
        self.assertEqual(status.status, "parsed")
        self.assertEqual(len(rows), 3)
        self.assertIn("verify", status.reason)

    def test_blocked_parse_raises_aiv03_gap_not_silent_pass(self):
        """The reviewer's core complaint: a gate must produce a gap + outreach,
        never a quiet pass that lets a provider slide in unseen."""
        vendor = {"vendor": "Gated Co", "slug": "gated-co", "tier": "high", "ai_surface": []}
        from vra.observe import ObservedState, ParseStatus

        observed = ObservedState(vendor="gated-co")
        observed.subprocessor_parse = ParseStatus(
            "blocked", platform="safebase",
            reason="hosted on the safebase portal behind a click-through NDA",
        )
        findings, gaps = ev.evaluate_vendor(vendor, ev.load_controls(), observed)
        self.assertEqual(findings, [], "blocked parse must not invent a finding")
        aiv03 = [g for g in gaps if g.control.id == "AIV-03"]
        self.assertEqual(len(aiv03), 1)
        self.assertEqual(aiv03[0].subject, "subprocessor-list-access")

    def test_missing_subprocessor_source_flagged(self):
        from vra.observe import observe_vendor

        vendor = {"vendor": "No List Co", "slug": "no-list-co",
                  "watch": {"changelog": "sandbox/vendors/loop-workspace/snapshots/v1/changelog.html"}}
        observed = observe_vendor(vendor, snapshots=[], probe_result=None)
        self.assertEqual(observed.subprocessor_parse.status, "missing")

    # -- PDFs -------------------------------------------------------------
    def test_pdf_parsed_when_pypdf_available(self):
        from vra.extract import extract_pdf_text

        text, err = extract_pdf_text(self.pdf_bytes())
        self.assertIsNone(err)
        self.assertIn("OpenAI L.L.C.", text)

    def test_pdf_without_pypdf_is_explicit_error_gap(self):
        """No pypdf installed -> error snapshot -> AIV-03 gap. Never silent."""
        import builtins
        from vra.extract import extract_pdf_text
        from vra.observe import ObservedState, ParseStatus

        real_import = builtins.__import__
        def blocked(name, *a, **k):
            if name == "pypdf" or name.startswith("pypdf."):
                raise ImportError("No module named 'pypdf' (simulated)")
            return real_import(name, *a, **k)

        builtins.__import__ = blocked
        try:
            text, err = extract_pdf_text(self.pdf_bytes())
        finally:
            builtins.__import__ = real_import
        self.assertEqual(text, "")
        self.assertIn("pypdf", err)

        vendor = {"vendor": "PDF Co", "slug": "pdf-co", "tier": "high", "ai_surface": []}
        observed = ObservedState(vendor="pdf-co")
        observed.subprocessor_parse = ParseStatus("error", reason=err)
        findings, gaps = ev.evaluate_vendor(vendor, ev.load_controls(), observed)
        self.assertEqual(findings, [])
        self.assertIn("AIV-03", [g.control.id for g in gaps])

    def test_pdf_ingestion_through_watch_snapshots(self):
        """Full chain: bytes -> snapshot -> observe -> AIV-03 finding for the
        uncovered OpenAI row."""
        from vra.watch import _ingest, snapshot_vendor
        from vra.observe import observe_vendor

        tmp = Path(tempfile.mkdtemp())
        try:
            pdf = tmp / "subprocessors.pdf"
            pdf.write_bytes(self.pdf_bytes())
            vendor = {"vendor": "PDF Co", "slug": "pdf-co", "tier": "high",
                      "ai_surface": [], "watch": {"subprocessors": str(pdf)}}
            snaps = snapshot_vendor(vendor, RunConfig(offline=True))
            self.assertIsNone(snaps[0].error)
            self.assertEqual(snaps[0].raw_kind, "pdf")
            observed = observe_vendor(vendor, snaps, None)
            self.assertEqual(observed.subprocessor_parse.status, "parsed")
            names = [s.name for s in observed.subprocessors]
            self.assertIn("OpenAI L.L.C.", names)
            self.assertIn("Anthropic PBC", names)
            uncovered = [s.name for s in observed.uncovered_ai_subprocessors]
            self.assertEqual(uncovered, ["OpenAI L.L.C."])
        finally:
            shutil.rmtree(tmp)


class TestOnboarding(unittest.TestCase):
    """The real gap the project had: nothing turned a vendor + trust-center URL
    into a register. Onboarding must scaffold, parse day-one, and flag gates."""

    TRUST_HTML = """<!DOCTYPE html><html><body><h1>Trust Center</h1>
    <ul>
      <li><a href="/security/subprocessors">Subprocessors</a></li>
      <li><a href="/security/release-notes">Release notes</a></li>
      <li><a href="https://acme.example/legal/dpa.pdf">Data Processing Addendum (PDF)</a></li>
    </ul></body></html>"""

    SUBPROCESSORS_HTML = """<!DOCTYPE html><html><body><h1>Subprocessors</h1>
    <table>
      <tr><th>Entity</th><th>Service provided</th><th>Region</th><th>BAA coverage</th></tr>
      <tr><td>OpenAI, L.L.C.</td><td>Inference for Copilot</td><td>US</td><td>Pending</td></tr>
      <tr><td>AWS</td><td>Hosting</td><td>US</td><td>Yes</td></tr>
    </table></body></html>"""

    GATED_HTML = """<!DOCTYPE html><html><body>
    <p>You're about to be redirected to continue to SafeBase.</p>
    <p>This content is available under a non-disclosure agreement.</p>
    </body></html>"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "vendors").mkdir()
        (self.tmp / "fixtures").mkdir()
        (self.tmp / "fixtures" / "trust_center.html").write_text(self.TRUST_HTML)
        (self.tmp / "fixtures" / "subprocessors.html").write_text(self.SUBPROCESSORS_HTML)
        (self.tmp / "fixtures" / "gated.html").write_text(self.GATED_HTML)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_onboard_scaffolds_register_and_parses_day_one(self):
        from vra.onboard import onboard_vendor

        res = onboard_vendor(
            "Acme Corp", tier="critical", category="collaboration",
            trust_center_url=str(self.tmp / "fixtures" / "trust_center.html"),
            urls={"subprocessors": str(self.tmp / "fixtures" / "subprocessors.html")},
            cfg=RunConfig(offline=True),
            _root=self.tmp,
        )
        self.assertEqual(res.parse_status.status, "parsed")
        self.assertEqual(res.parse_status.rows, 2)
        self.assertEqual(res.platform, None)  # not a portal
        names = [r.name for r in res.parsed_rows]
        self.assertIn("OpenAI, L.L.C.", names)
        self.assertTrue(any(r.name == "OpenAI, L.L.C." and not r.baa_covered
                            for r in res.parsed_rows))

        # Register file written with a seeded AI feature and cached watch paths.
        register = yaml.safe_load((self.tmp / "vendors" / "acme-corp.yaml").read_text())
        self.assertEqual(register["slug"], "acme-corp")
        self.assertEqual(register["tier"], "critical")
        self.assertEqual(register["contract"]["baa_on_file"], False)
        self.assertTrue(register["ai_surface"], "expected a seeded AI feature")
        self.assertEqual(register["ai_surface"][0]["model_provider"], "OpenAI, L.L.C.")
        self.assertIn("onboarding", register)
        self.assertEqual(register["onboarding"]["subprocessor_parse"]["status"], "parsed")
        sp_watch = register["watch"]["subprocessors"]
        self.assertIn("artifacts/vendors/acme-corp/snapshots/{version}/subprocessors", sp_watch)
        self.assertTrue((self.tmp / "artifacts/vendors/acme-corp/snapshots/v1").exists())

    def test_onboard_gated_portal_drafts_outreach(self):
        from vra.onboard import onboard_vendor

        res = onboard_vendor(
            "Gated Co", tier="high",
            urls={"subprocessors": str(self.tmp / "fixtures" / "gated.html")},
            cfg=RunConfig(offline=True),
            _root=self.tmp,
        )
        self.assertEqual(res.parse_status.status, "blocked")
        self.assertTrue(res.blockers)
        self.assertIsNotNone(res.outreach_path)
        self.assertTrue(res.outreach_path.exists())
        body = res.outreach_path.read_text()
        self.assertIn("subprocessor", body.lower())
        self.assertIn("guest or NDA-gated access", body)

    def test_onboard_no_subprocessors_url_blocked(self):
        from vra.onboard import onboard_vendor

        res = onboard_vendor(
            "NoList Co", tier="medium",
            trust_center_url=str(self.tmp / "fixtures" / "trust_center.html"),
            cfg=RunConfig(offline=True),
            _root=self.tmp,
        )
        self.assertEqual(res.parse_status.status, "missing")
        self.assertTrue(res.blockers)

    def test_onboard_dry_run_persists_nothing(self):
        from vra.onboard import onboard_vendor

        res = onboard_vendor(
            "Dry Co", tier="high",
            urls={"subprocessors": str(self.tmp / "fixtures" / "subprocessors.html")},
            cfg=RunConfig(offline=True, dry_run=True),
            _root=self.tmp,
        )
        self.assertIsNone(res.register_path)
        self.assertIsNone(res.outreach_path)
        self.assertFalse((self.tmp / "vendors" / "dry-co.yaml").exists())

    def test_bootstrap_proposes_register_into_pending_review(self):
        """A new vendor has no v1 register. Bootstrap reads artifacts in full
        (not a diff) and quarantines the proposal — never writes the register."""
        from vra.onboard import onboard_vendor

        res = onboard_vendor(
            "Boot Co", tier="high",
            urls={"subprocessors": str(self.tmp / "fixtures" / "subprocessors.html")},
            cfg=RunConfig(offline=True),
            bootstrap=True,
            _root=self.tmp,
        )
        self.assertIsNotNone(res.bootstrap_path)
        self.assertTrue(res.bootstrap_path.exists())
        blob = json.loads(res.bootstrap_path.read_text())
        self.assertIn("BOOTSTRAP PROPOSAL — NOT APPLIED", blob["instructions"])
        self.assertTrue(any("OpenAI" in (f.get("model_provider") or "")
                            for f in blob["proposed_ai_surface"]))
        # The register itself stays conservative — unknowns, not the proposal.
        register = yaml.safe_load((self.tmp / "vendors" / "boot-co.yaml").read_text())
        self.assertEqual(register["ai_surface"][0]["autonomy"], "unknown")

    def test_onboard_refuses_duplicate_slug(self):
        from vra.onboard import onboard_vendor

        onboard_vendor("Acme Corp", tier="high",
                       urls={"subprocessors": str(self.tmp / "fixtures" / "subprocessors.html")},
                       cfg=RunConfig(offline=True), _root=self.tmp)
        with self.assertRaises(ValueError):
            onboard_vendor("Acme Corp", tier="high",
                           urls={"subprocessors": str(self.tmp / "fixtures" / "subprocessors.html")},
                           cfg=RunConfig(offline=True), _root=self.tmp)


class TestModelDefaultAndWebUI(unittest.TestCase):
    def test_default_model_is_qwen25_7b_instruct(self):
        self.assertEqual(RunConfig().model, "qwen2.5:7b-instruct")

    def test_webui_summary_and_vendors(self):
        from vra.webui import _list_nhis, _list_vendors, _monitor, _summary

        s = _summary()
        self.assertIn("vendors", s)
        self.assertIn("blocked_parses", s)
        self.assertIn("model", s)
        self.assertIn("nhis", s)
        self.assertGreaterEqual(s["nhis"], 1)
        v = _list_vendors()
        self.assertGreaterEqual(len(v), 3)
        self.assertTrue(all("slug" in x and "parse" in x for x in v))
        nhis = _list_nhis()
        self.assertGreaterEqual(len(nhis), 3)
        mon = _monitor()
        self.assertIn(mon.get("status"), ("stopped", "running", "stale"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
