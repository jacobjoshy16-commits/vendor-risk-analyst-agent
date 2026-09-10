"""The event log is bounded without losing the record that a permission moved.

data/nhis.json holds current state only, so an entitlement_change event is the
only place the tool records that an agent ever gained a scope. That makes
"delete the old ones" the wrong default: aged events are archived out of the
hot store, and destroying them takes an explicit, confirmed purge.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import RunConfig  # noqa: E402
from vra.register import FindingStore  # noqa: E402


def _event(days_ago: float, **over):
    stamp = datetime.now(timezone.utc) - timedelta(days=days_ago)
    row = {
        "id": f"entitlement:acme|agent:{days_ago}",
        "kind": "entitlement_change", "family": "nhi",
        "vendor": "acme", "vendor_name": "Acme", "nhi_id": "agent-1",
        "nhi_name": "Access Copilot", "principal": "copilot",
        "added_scopes": ["okta.users.manage"], "removed_scopes": [],
        "gained_write_scope": True, "timestamp": stamp.isoformat(),
    }
    row.update(over)
    return row


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / "events"
        self.store = FindingStore(self.root / "findings.json")

    def roll(self, **kw):
        kw.setdefault("archive_dir", self.archive)
        return self.store.roll_events(**kw)


class TestRetentionWindow(_StoreCase):
    def test_recent_events_stay_hot(self):
        for age in (1, 10, 45, 89):
            self.store.record_event(_event(age))
        self.assertEqual(self.roll(retention_days=90), 0)
        self.assertEqual(len(self.store.events), 4)

    def test_aged_events_are_archived(self):
        self.store.record_event(_event(5))
        self.store.record_event(_event(200))
        self.store.record_event(_event(400))

        moved = self.roll(retention_days=90)
        self.assertEqual(moved, 2)
        self.assertEqual(len(self.store.events), 1)
        self.assertEqual(len(FindingStore.archived_events(self.archive)), 2)

    def test_nothing_is_lost_in_the_move(self):
        for age in range(0, 400, 7):
            self.store.record_event(_event(age))
        total = len(self.store.events)

        self.roll(retention_days=90)
        recovered = len(self.store.events) + len(FindingStore.archived_events(self.archive))
        self.assertEqual(recovered, total, "every event must still exist somewhere")

    def test_the_hot_ceiling_bounds_a_burst_inside_the_window(self):
        """A busy week must not defeat the window-based bound."""
        for i in range(500):
            self.store.record_event(_event(1, id=f"burst-{i}"))
        moved = self.roll(retention_days=90, hot_max=100)
        self.assertEqual(moved, 400)
        self.assertEqual(len(self.store.events), 100)

    def test_the_ceiling_archives_the_oldest_first(self):
        for age in (1, 2, 3, 4, 5):
            self.store.record_event(_event(age, id=f"age-{age}"))
        self.roll(retention_days=90, hot_max=2)
        kept = {e["id"] for e in self.store.events}
        self.assertEqual(kept, {"age-1", "age-2"}, "the newest two stay hot")

    def test_an_empty_log_is_a_no_op(self):
        self.assertEqual(self.roll(), 0)
        self.assertFalse(self.archive.exists())


class TestArchiveLayout(_StoreCase):
    def test_events_are_filed_by_month(self):
        self.store.record_event(_event(400, timestamp="2025-03-14T10:00:00+00:00"))
        self.store.record_event(_event(400, timestamp="2025-04-02T10:00:00+00:00"))
        self.roll(retention_days=90)

        names = sorted(p.name for p in self.archive.glob("*.jsonl"))
        self.assertEqual(names, ["events-2025-03.jsonl", "events-2025-04.jsonl"])

    def test_a_later_roll_appends_rather_than_overwriting(self):
        self.store.record_event(_event(400, id="first",
                                       timestamp="2025-03-14T10:00:00+00:00"))
        self.roll(retention_days=90)
        self.store.record_event(_event(400, id="second",
                                       timestamp="2025-03-20T10:00:00+00:00"))
        self.roll(retention_days=90)

        ids = {e["id"] for e in FindingStore.archived_events(self.archive)}
        self.assertEqual(ids, {"first", "second"})

    def test_an_unparseable_timestamp_is_archived_not_dropped(self):
        self.store.record_event(_event(1, id="broken", timestamp="not-a-date"))
        moved = self.roll(retention_days=90)

        self.assertEqual(moved, 1, "an undateable event counts as ancient")
        self.assertTrue((self.archive / "events-unknown.jsonl").exists())
        self.assertEqual(
            [e["id"] for e in FindingStore.archived_events(self.archive)], ["broken"]
        )

    def test_a_corrupt_archive_line_does_not_break_reading(self):
        self.store.record_event(_event(400, id="good",
                                       timestamp="2025-03-14T10:00:00+00:00"))
        self.roll(retention_days=90)
        with (self.archive / "events-2025-03.jsonl").open("a", encoding="utf-8") as fh:
            fh.write("{not json\n\n")

        rows = FindingStore.archived_events(self.archive)
        self.assertEqual([e["id"] for e in rows], ["good"])


class TestEvidenceIsNeverTradedForSpace(_StoreCase):
    def test_a_failed_archive_write_keeps_everything_hot(self):
        """A bounded file is not worth a lost audit record."""
        self.store.record_event(_event(400, id="precious"))
        blocked = self.root / "blocked"
        blocked.write_text("I am a file, not a directory", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            moved = self.store.roll_events(retention_days=90, archive_dir=blocked)

        self.assertEqual(moved, 0)
        self.assertEqual(len(self.store.events), 1, "the event stays hot")
        self.assertEqual(self.store.events[0]["id"], "precious")

    def test_save_rolls_automatically(self):
        """Every persist is the systemic point where the log gets bounded."""
        import unittest.mock

        from vra import register as regmod

        for age in (1, 200, 300):
            self.store.record_event(_event(age, id=f"e-{age}"))
        with unittest.mock.patch.object(regmod, "EVENTS_ARCHIVE_DIR", self.archive):
            self.store.save(RunConfig())

        blob = json.loads((self.root / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(len(blob["events"]), 1)
        self.assertEqual(blob["meta"]["events_archived_total"], 2)
        self.assertEqual(len(FindingStore.archived_events(self.archive)), 2)

    def test_dry_run_archives_nothing(self):
        self.store.record_event(_event(400))
        self.store.save(RunConfig(dry_run=True))
        self.assertEqual(len(self.store.events), 1)
        self.assertFalse(self.archive.exists())


class TestPurgeRequiresIntent(_StoreCase):
    def _purge(self, before, *, confirmed):
        from vra import events as ev

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = ev.purge(before, confirmed=confirmed, cfg=RunConfig(),
                            archive_dir=self.archive,
                            findings_path=self.root / "findings.json")
        return code, buf.getvalue()

    def _persist(self, *events, force_archive=False):
        """Persist events. force_archive drives them all into the archive,
        so a test does not depend on where today falls relative to the window."""
        for event in events:
            self.store.record_event(event)
        if force_archive:
            self.store.roll_events(retention_days=-1, archive_dir=self.archive)
        else:
            self.store.roll_events(archive_dir=self.archive)
        self.store.save(RunConfig())

    def _surviving_ids(self):
        remaining = FindingStore(self.root / "findings.json")
        return {e["id"] for e in remaining.events} | {
            e["id"] for e in FindingStore.archived_events(self.archive)
        }

    def test_without_confirmation_nothing_is_destroyed(self):
        self._persist(_event(400, id="old", timestamp="2025-01-01T00:00:00+00:00"))

        code, out = self._purge("2026-01-01", confirmed=False)
        self.assertEqual(code, 1)
        self.assertIn("PERMANENTLY DELETE", out)
        self.assertIn("only record", out)
        self.assertEqual(self._surviving_ids(), {"old"})

    def test_the_warning_counts_write_scope_gains(self):
        self._persist(
            _event(400, id="a", timestamp="2025-01-01T00:00:00+00:00",
                   gained_write_scope=True),
            _event(400, id="b", timestamp="2025-01-02T00:00:00+00:00",
                   gained_write_scope=False),
        )
        _, out = self._purge("2026-01-01", confirmed=False)
        self.assertIn("2 event(s)", out)
        self.assertIn("1 of them record an identity GAINING a write scope", out)

    def test_a_bad_date_is_refused(self):
        code, _ = self._purge("last tuesday", confirmed=True)
        self.assertEqual(code, 2)

    def test_nothing_to_purge_is_not_an_error(self):
        self._persist(_event(1, id="recent"))
        code, out = self._purge("2000-01-01", confirmed=True)
        self.assertEqual(code, 0)
        self.assertIn("nothing recorded before", out)
        self.assertEqual(self._surviving_ids(), {"recent"})

    def test_confirmed_purge_deletes_only_what_is_older(self):
        self._persist(
            _event(1, id="keep"),
            _event(400, id="drop", timestamp="2025-01-01T00:00:00+00:00"),
        )
        code, out = self._purge("2026-01-01", confirmed=True)
        self.assertEqual(code, 0)
        self.assertIn("purged", out)
        self.assertEqual(self._surviving_ids(), {"keep"})

    def test_purge_clears_the_archive_too_not_just_the_hot_store(self):
        self._persist(
            _event(400, id="archived-old", timestamp="2025-01-01T00:00:00+00:00"),
            _event(400, id="archived-newer", timestamp="2026-08-01T00:00:00+00:00"),
            force_archive=True,
        )
        self.assertEqual(len(FindingStore.archived_events(self.archive)), 2)

        self._purge("2026-01-01", confirmed=True)
        surviving = {e["id"] for e in FindingStore.archived_events(self.archive)}
        self.assertEqual(surviving, {"archived-newer"})


if __name__ == "__main__":
    unittest.main()
