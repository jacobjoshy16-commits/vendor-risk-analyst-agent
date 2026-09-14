"""Cross-plane linking: semantics first, then the scaling guard.

Matching two NHIs is exact-token equality, never a similarity score, which is
what lets the linker use an inverted index instead of comparing every identity
against every other one. These tests pin both halves of that: the linking
decisions themselves, and the fact that a portfolio far larger than the
README's "~20 vendors / ~60 identities" still finishes.
"""

from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.nhi import (  # noqa: E402
    PortfolioIndex,
    discover_nhis,
    link_cross_plane,
    match_keys,
    same_identity,
    tag_cross_vendor,
)


class _Probe:
    def __init__(self, rows):
        self.ran = True
        self.nhis = rows


class TestMatchKeysMirrorSameIdentity(unittest.TestCase):
    """match_keys is the index's view of same_identity. They must not drift."""

    CASES = [
        ({"id": "0oa1b2c3d4"}, {"app_id": "0oa1b2c3d4"}, True, "same id, different field"),
        ({"id": "short"}, {"id": "short"}, False, "id under 6 chars is not quotable"),
        ({"id": "unknown"}, {"id": "unknown"}, False, "placeholder ids never match"),
        ({"principal": "svc@acme"}, {"principal": "SVC@ACME"}, True, "principal is case-insensitive"),
        ({"principal": "abc"}, {"principal": "abc"}, False, "principal under 4 chars"),
        ({"name": "Loop Sync"}, {"name": "loop sync"}, True, "name is case-insensitive"),
        ({"name": "bot"}, {"name": "bot"}, False, "name under 5 chars"),
        ({"name": "Loop Sync"}, {"principal": "Loop Sync"}, False, "different fields do not cross"),
        ({}, {}, False, "two empty records are not the same identity"),
    ]

    def test_agreement(self):
        for a, b, expected, why in self.CASES:
            with self.subTest(why=why):
                self.assertEqual(same_identity(a, b), expected, why)
                self.assertEqual(bool(match_keys(a) & match_keys(b)), expected, why)


class TestCrossPlaneLinking(unittest.TestCase):
    def test_same_principal_on_two_vendors_is_linked(self):
        idp = {"id": "0oa1b2c3d4", "name": "Loop Provisioner", "idp": "okta"}
        product = {"id": "0oa1b2c3d4", "name": "Loop Provisioner", "idp": "atlassian"}
        link_cross_plane({"okta-org": [idp], "loop": [product]})

        self.assertTrue(idp["cross_plane"])
        self.assertTrue(product["cross_plane"])
        self.assertEqual(idp["also_seen_on"], ["loop"])
        self.assertEqual(product["also_seen_on"], ["okta-org"])

    def test_idp_side_takes_the_product_vendor_as_home(self):
        """Observation on the product plane satisfies NHI-06 without YAML."""
        idp = {"id": "0oa1b2c3d4", "idp": "okta"}
        product = {"id": "0oa1b2c3d4", "idp": "atlassian"}
        link_cross_plane({"okta-org": [idp], "loop": [product]})

        self.assertTrue(idp["declared"])
        self.assertEqual(idp["home_vendor"], "loop")
        self.assertTrue(idp["cross_vendor"])

    def test_two_non_idp_planes_both_count_as_declared(self):
        a = {"id": "0oa1b2c3d4", "idp": "atlassian"}
        b = {"id": "0oa1b2c3d4", "idp": "slack"}
        link_cross_plane({"atl": [a], "slack": [b]})
        self.assertTrue(a["declared"])
        self.assertTrue(b["declared"])

    def test_home_vendor_is_first_match_in_portfolio_order(self):
        idp = {"id": "0oa1b2c3d4", "idp": "okta"}
        first = {"id": "0oa1b2c3d4", "idp": "atlassian"}
        second = {"id": "0oa1b2c3d4", "idp": "slack"}
        link_cross_plane({"okta-org": [idp], "aaa": [first], "zzz": [second]})

        self.assertEqual(idp["home_vendor"], "aaa", "the earlier vendor wins")
        self.assertEqual(idp["also_seen_on"], ["aaa", "zzz"])

    def test_identities_inside_one_vendor_are_not_linked(self):
        a = {"id": "0oa1b2c3d4", "idp": "okta"}
        b = {"id": "0oa1b2c3d4", "idp": "okta"}
        link_cross_plane({"okta-org": [a, b]})
        self.assertNotIn("cross_plane", a)
        self.assertNotIn("cross_plane", b)

    def test_distinct_identities_are_left_alone(self):
        a = {"id": "0oa1b2c3d4", "name": "Alpha Agent", "idp": "okta"}
        b = {"id": "9zz8y7x6w5", "name": "Beta Agent", "idp": "atlassian"}
        link_cross_plane({"okta-org": [a], "loop": [b]})
        self.assertNotIn("cross_plane", a)
        self.assertNotIn("also_seen_on", b)


class TestPortfolioIndex(unittest.TestCase):
    def test_declaring_slugs_are_in_portfolio_order(self):
        portfolio = [
            {"slug": "aaa", "vendor": "Aaa Corp", "nhis": [{"id": "0oa1b2c3d4"}]},
            {"slug": "zzz", "vendor": "Zzz Corp", "nhis": [{"id": "0oa1b2c3d4"}]},
        ]
        index = PortfolioIndex(portfolio)
        self.assertEqual(index.declaring_slugs({"id": "0oa1b2c3d4"}), ["aaa", "zzz"])

    def test_home_by_name_skips_the_tenant_itself(self):
        portfolio = [
            {"slug": "loop-workspace", "vendor": "Loop Workspace", "nhis": []},
            {"slug": "aegis", "vendor": "Aegis", "nhis": []},
        ]
        index = PortfolioIndex(portfolio)
        self.assertEqual(index.home_by_name("loop-workspace-sync", exclude="aegis"),
                         "loop-workspace")
        self.assertIsNone(index.home_by_name("loop-workspace-sync",
                                             exclude="loop-workspace"))

    def test_empty_portfolio_is_marked_empty(self):
        self.assertTrue(PortfolioIndex(None).empty)
        self.assertTrue(PortfolioIndex([]).empty)

    def test_tag_cross_vendor_builds_its_own_index_when_not_given_one(self):
        portfolio = [{"slug": "loop", "vendor": "Loop", "nhis": [{"id": "0oa1b2c3d4"}]}]
        nhi = {"id": "0oa1b2c3d4", "orphan": True, "source": "observed"}
        tag_cross_vendor(nhi, {"slug": "aegis"}, portfolio)
        self.assertTrue(nhi["declared"])
        self.assertEqual(nhi["home_vendor"], "loop")


class TestRegisterOverlayMatching(unittest.TestCase):
    def test_register_row_pairs_with_the_first_matching_observation(self):
        vendor = {
            "slug": "acme", "vendor": "Acme",
            "nhis": [{"id": "0oa1b2c3d4", "name": "Agent", "owner": "platform@acme"}],
        }
        observed = [
            {"id": "zzz9y8x7w6", "name": "Other"},
            {"id": "0oa1b2c3d4", "name": "Agent", "scopes": ["users.manage"]},
        ]
        rows = discover_nhis(vendor, _Probe(observed), portfolio=[vendor])

        merged = next(r for r in rows if r.get("owner") == "platform@acme")
        self.assertEqual(merged["source"], "register+observed")
        self.assertEqual(merged["scopes"], ["users.manage"], "observed overlays register")
        self.assertFalse(merged["orphan"])

    def test_unmatched_observation_is_an_orphan(self):
        vendor = {"slug": "acme", "vendor": "Acme", "nhis": []}
        rows = discover_nhis(vendor, _Probe([{"id": "0oa1b2c3d4", "name": "Ghost"}]),
                             portfolio=[vendor])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["orphan"])
        self.assertEqual(rows[0]["source"], "observed")


class TestLinkingScalesPastTheDocumentedPortfolio(unittest.TestCase):
    """The pairwise linker was O(V^2 * N^2): ~1s at 20x60, ~18s at 50x100.

    The bound below is deliberately loose — it is a guard against the quadratic
    form returning, not a benchmark. The old implementation could not finish
    this input in any reasonable time.
    """

    def test_twenty_thousand_identities_link_quickly(self):
        vendors, per_vendor = 100, 200
        shared = [{"id": f"shared-{i}", "name": f"Shared Agent {i}", "idp": "okta"}
                  for i in range(10)]
        by_vendor = {
            f"vendor-{v}": (
                [{"id": f"id-{v}-{j}", "principal": f"p-{v}-{j}",
                  "name": f"Name {v} {j}", "idp": "atlassian"} for j in range(per_vendor)]
                + [dict(row) for row in shared]
            )
            for v in range(vendors)
        }
        total = sum(len(rows) for rows in by_vendor.values())
        self.assertGreater(total, 20_000)

        started = time.perf_counter()
        link_cross_plane(by_vendor)
        elapsed = time.perf_counter() - started
        self.assertLess(elapsed, 15.0, f"linking {total} identities took {elapsed:.1f}s")

        # And it still did the work: the shared rows are linked across vendors.
        first = by_vendor["vendor-0"]
        linked = [r for r in first if r.get("cross_plane")]
        self.assertEqual(len(linked), len(shared))
        self.assertEqual(len(linked[0]["also_seen_on"]), vendors - 1)


if __name__ == "__main__":
    unittest.main()
