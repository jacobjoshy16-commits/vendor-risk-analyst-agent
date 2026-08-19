"""Parser vs. the five public pages the review named.

These fixtures are structurally faithful copies of Slack / Atlassian / Zoom /
Notion / Datadog subprocessors pages (see sandbox/real_world/README.md).
AIV-03 is only as good as this parse. A failed parse must be ``parse_failed``,
never a silent pass.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.evaluate import evaluate_vendor, load_controls  # noqa: E402
from vra.extract import extract_html_tables  # noqa: E402
from vra.observe import ObservedState, ParseStatus, parse_subprocessors  # noqa: E402

REAL = REPO / "sandbox" / "real_world"


def _parse_html(rel: str):
    raw = (REAL / rel).read_text(encoding="utf-8")
    tables = extract_html_tables(raw)
    return parse_subprocessors(raw, source="subprocessors", tables=tables, raw_kind="html")


class TestRealWorldVendorPages(unittest.TestCase):
    def test_datadog_classic_vendor_country_purpose_table(self):
        rows, status = _parse_html("datadog/subprocessors.html")
        self.assertEqual(status.status, "parsed", status.reason)
        names = [r.name for r in rows]
        self.assertIn("Amazon Web Services, Inc.", names)
        self.assertIn("Anthropic, PBC", names)
        self.assertIn("OpenAI, LLC", names)
        openai = next(r for r in rows if r.name == "OpenAI, LLC")
        self.assertTrue(openai.is_ai_related)
        self.assertEqual(openai.region, "United States")

    def test_zoom_name_purpose_location_table(self):
        rows, status = _parse_html("zoom/subprocessors.html")
        self.assertEqual(status.status, "parsed", status.reason)
        names = [r.name for r in rows]
        for expected in ("Amazon Web Services", "Anthropic", "OpenAI", "Perplexity", "Eleven Labs Inc."):
            self.assertIn(expected, names, f"missed {expected}; got {names}")
        anth = next(r for r in rows if r.name == "Anthropic")
        self.assertTrue(anth.is_ai_related)
        self.assertIn("United States", anth.region)

    def test_notion_multiple_classic_tables(self):
        rows, status = _parse_html("notion/subprocessors.html")
        self.assertEqual(status.status, "parsed", status.reason)
        names = [r.name for r in rows]
        for expected in ("AWS", "Anthropic", "OpenAI", "Fireworks", "X.AI LLC"):
            self.assertIn(expected, names, f"missed {expected}; got {names}")
        self.assertTrue(next(r for r in rows if r.name == "OpenAI").is_ai_related)

    def test_atlassian_labeled_cells_not_pipe_sandbox(self):
        """Atlassian does not publish Entity|Purpose|Location. Labeled cells."""
        rows, status = _parse_html("atlassian/subprocessors.html")
        self.assertEqual(status.status, "parsed", status.reason)
        names = [r.name for r in rows]
        self.assertIn("Amazon Web Services, Inc.", names)
        self.assertIn("Databricks, Inc.", names)
        self.assertIn("Twilio Inc.", names)
        self.assertNotIn("Hosting and Infrastructure Service Providers", names)
        aws = next(r for r in rows if "Amazon Web Services" in r.name)
        self.assertIn("Cloud hosting", aws.purpose)
        self.assertTrue(aws.region)

    def test_slack_salesforce_pdf_text(self):
        text = (REAL / "slack/subprocessors.txt").read_text(encoding="utf-8")
        rows, status = parse_subprocessors(text, source="subprocessors", raw_kind="pdf")
        self.assertEqual(status.status, "parsed", status.reason)
        names = [r.name for r in rows]
        self.assertIn("Amazon Web Services, Inc.", names)
        self.assertIn("OpenAI, L.L.C.", names)
        self.assertIn("Anthropic PBC", names)
        self.assertTrue(next(r for r in rows if "OpenAI" in r.name).is_ai_related)

    def test_js_shell_is_parse_failed_not_silent_pass(self):
        rows, status = _parse_html("notion/js_shell.html")
        self.assertEqual(rows, [])
        self.assertEqual(status.status, "parse_failed")
        vendor = {"vendor": "Notion", "slug": "notion", "tier": "high", "ai_surface": []}
        observed = ObservedState(vendor="notion")
        observed.subprocessor_parse = status
        findings, gaps = evaluate_vendor(vendor, load_controls(), observed)
        self.assertEqual(findings, [], "a failed parse must not invent a finding")
        self.assertIn("AIV-03", [g.control.id for g in gaps])
        self.assertEqual(gaps[0].subject, "subprocessor-list-access")


if __name__ == "__main__":
    unittest.main(verbosity=2)
