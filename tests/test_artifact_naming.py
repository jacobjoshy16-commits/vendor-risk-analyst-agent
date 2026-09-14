"""Artifacts are stamped to the second — two in one second must both survive.

A report, a pending-review proposal, and a snapshot set are each evidence. The
second one written in a given second used to silently take the first one's
filename, and the earlier evidence was gone.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import report as report_mod  # noqa: E402
from vra.config import RunConfig, reserve_path  # noqa: E402


class _FrozenClock(datetime):
    """Every call lands in the same second, which is the case under test."""

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return datetime(2026, 9, 11, 12, 0, 0, tzinfo=tz or timezone.utc)


class TestReservePath(unittest.TestCase):
    def test_a_taken_name_gets_a_suffix_not_a_silent_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            wanted = Path(tmp) / "vendor-ai-risk-20260911T120000Z.md"
            first = reserve_path(wanted)
            first.write_text("first run", encoding="utf-8")
            second = reserve_path(wanted)
            second.write_text("second run", encoding="utf-8")
            third = reserve_path(wanted)

            self.assertEqual(first, wanted)
            self.assertNotEqual(second, first)
            self.assertNotEqual(third, second)
            self.assertEqual(first.read_text(encoding="utf-8"), "first run")
            self.assertEqual(second.read_text(encoding="utf-8"), "second run")
            self.assertTrue(second.name.endswith(".md"), second.name)

    def test_directories_are_reserved_the_same_way(self):
        with tempfile.TemporaryDirectory() as tmp:
            wanted = Path(tmp) / "20260911T120000Z"
            first = reserve_path(wanted, directory=True)
            (first / "marker.txt").write_text("baseline", encoding="utf-8")
            second = reserve_path(wanted, directory=True)

            self.assertNotEqual(first, second)
            self.assertTrue(second.is_dir())
            self.assertEqual((first / "marker.txt").read_text(encoding="utf-8"), "baseline")
            # Lexical sort still orders them, so `previous_snapshot_dir` picks
            # the newer set.
            self.assertEqual(sorted([second, first]), [first, second])

    def test_the_newest_of_a_dozen_same_second_sets_is_the_one_sorting_last(self):
        """`previous_snapshot_dir` sorts by name, so `-9` must not beat `-12`."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "acme"
            made = [
                reserve_path(root / "20260911T120000Z", directory=True) for _ in range(12)
            ]
            newest = sorted(p for p in root.iterdir() if p.is_dir())[-1]
            self.assertEqual(newest, made[-1], "sorting picked a stale baseline")

    def test_a_later_second_still_sorts_after_a_suffixed_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "acme"
            reserve_path(root / "20260911T120000Z", directory=True)
            suffixed = reserve_path(root / "20260911T120000Z", directory=True)
            later = reserve_path(root / "20260911T120001Z", directory=True)
            self.assertEqual(sorted([later, suffixed])[-1], later)


class TestReportsDoNotOverwriteEachOther(unittest.TestCase):
    def _ctx(self) -> dict:
        return {
            "backend": "test",
            "findings": [],
            "gaps": [],
            "triages": [],
            "probes": [],
            "failed_vendors": [],
            "parses": [],
            "nhis": [],
            "events": [],
        }

    def test_two_assessments_in_the_same_second_keep_both_reports(self):
        real_datetime = report_mod.datetime
        with tempfile.TemporaryDirectory() as tmp:
            cfg = RunConfig(out_dir=Path(tmp))
            report_mod.datetime = _FrozenClock  # type: ignore[assignment]
            try:
                first = report_mod.write_report("# first assessment", self._ctx(), cfg)
                second = report_mod.write_report("# second assessment", self._ctx(), cfg)
            finally:
                report_mod.datetime = real_datetime  # type: ignore[assignment]

            assert first is not None and second is not None
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text(encoding="utf-8"), "# first assessment")
            self.assertEqual(second.read_text(encoding="utf-8"), "# second assessment")
            # latest.md is a pointer, not history: it may be replaced.
            self.assertEqual(
                (Path(tmp) / "latest.md").read_text(encoding="utf-8"), "# second assessment"
            )
            history = sorted(p.name for p in Path(tmp).glob("vendor-ai-risk-*.md"))
            self.assertEqual(len(history), 2, history)

    def test_a_poll_that_changed_nothing_keeps_no_second_copy(self):
        """Only the header moves between unchanged cycles — 2 lines of 635."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = RunConfig(out_dir=Path(tmp))
            body = "# assessment\n\n**Generated:** 2026-09-11 12:00 UTC  \nfindings: 3"
            first = report_mod.write_report(body, self._ctx(), cfg)
            repeat = report_mod.write_report(
                body.replace("12:00", "12:15"), self._ctx(), cfg
            )

            self.assertIsNotNone(first)
            self.assertIsNone(repeat, "an unchanged cycle keeps no historical copy")
            self.assertEqual(len(list(Path(tmp).glob("vendor-ai-risk-*.md"))), 1)
            # latest.md still moves, so the current view is never stale.
            self.assertIn("12:15", (Path(tmp) / "latest.md").read_text(encoding="utf-8"))

    def test_a_real_change_is_still_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = RunConfig(out_dir=Path(tmp))
            report_mod.write_report("# assessment\n\nfindings: 3", self._ctx(), cfg)
            changed = report_mod.write_report("# assessment\n\nfindings: 4", self._ctx(), cfg)

            self.assertIsNotNone(changed)
            self.assertEqual(len(list(Path(tmp).glob("vendor-ai-risk-*.md"))), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
