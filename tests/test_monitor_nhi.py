"""Tests for the autonomous monitor and multi-vendor NHI inventory."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import evaluate as ev  # noqa: E402
from vra.config import RunConfig  # noqa: E402


class TestNHIInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from vra.nhi import load_nhi_controls

        cls.controls = load_nhi_controls()
        cls.vendors = {
            p.stem: yaml.safe_load(p.read_text())
            for p in (REPO / "vendors").glob("*.yaml")
        }

    def test_nhi_control_set_is_separate_from_aiv(self):
        ids = [c.id for c in self.controls]
        self.assertEqual(len(ids), 8)
        self.assertTrue(all(i.startswith("NHI-") for i in ids))
        aiv = ev.load_controls()
        self.assertTrue(all(c.id.startswith("AIV-") for c in aiv))
        self.assertLessEqual(len(aiv), 20)

    def test_discover_merges_register_and_probe_across_vendors(self):
        from vra.nhi import discover_nhis
        from vra.probe import run_probe

        portfolio = list(self.vendors.values())
        aegis = self.vendors["aegis-identity-cloud"]
        probe = run_probe(aegis, RunConfig(snapshot_version="v1", offline=True))
        self.assertTrue(probe.ran)
        nhis = discover_nhis(aegis, probe, portfolio=portfolio)
        principals = {n.get("principal") for n in nhis}
        self.assertIn("copilot-assist", principals)
        loop = next(n for n in nhis if n.get("principal") == "loop-provisioning")
        self.assertTrue(loop["cross_vendor"])
        self.assertEqual(loop["home_vendor"], "loop-workspace")
        self.assertTrue(loop["declared"])
        self.assertFalse(loop["orphan"])

    def test_baseline_nhis_raise_no_critical(self):
        from vra.nhi import discover_nhis, evaluate_nhis
        from vra.probe import run_probe

        portfolio = list(self.vendors.values())
        for slug, vendor in self.vendors.items():
            probe = run_probe(vendor, RunConfig(snapshot_version="v1", offline=True))
            nhis = discover_nhis(vendor, probe, portfolio=portfolio)
            findings, _ = evaluate_nhis(vendor, nhis, self.controls)
            crits = [f.control.id for f in findings if f.control.severity == "critical"]
            self.assertEqual(crits, [], f"{slug} raised NHI critical at baseline: {crits}")

    def test_agent_mode_write_scopes_fire_nhi01(self):
        from vra.nhi import discover_nhis, evaluate_nhis
        from vra.probe import run_probe

        aegis = self.vendors["aegis-identity-cloud"]
        probe = run_probe(aegis, RunConfig(snapshot_version="v2", offline=True))
        nhis = discover_nhis(aegis, probe, portfolio=list(self.vendors.values()))
        agent = next(n for n in nhis if n.get("app_id") == "0oa1copilotagent01")
        self.assertTrue(agent.get("write_scopes"))
        self.assertEqual(agent.get("human_in_loop"), False)
        findings, _ = evaluate_nhis(aegis, nhis, self.controls)
        self.assertIn("NHI-01", [f.control.id for f in findings])

    def test_orphan_identity_fires_nhi04(self):
        from vra.nhi import discover_nhis, evaluate_nhis
        from vra.probe import ProbeResult

        vendor = {"vendor": "Solo Co", "slug": "solo-co", "tier": "high", "nhis": []}
        probe = ProbeResult(
            vendor="solo-co",
            ran=True,
            mode="fixture",
            nhis=[{
                "id": "orphan-1",
                "app_id": "orphan-1",
                "name": "Shadow Bot",
                "kind": "agent_principal",
                "status": "active",
                "principal": "shadow-bot",
                "scopes": ["users.read"],
                "write_scopes": [],
                "source": "observed",
                "evidence": "tenant application orphan-1",
            }],
        )
        nhis = discover_nhis(vendor, probe, portfolio=[vendor])
        self.assertTrue(nhis[0]["orphan"])
        findings, _ = evaluate_nhis(vendor, nhis, self.controls)
        self.assertIn("NHI-04", [f.control.id for f in findings])

    def test_undeclared_cross_vendor_fires_nhi06(self):
        from vra.nhi import discover_nhis, evaluate_nhis
        from vra.probe import ProbeResult

        host = {"vendor": "Host IdP", "slug": "host-idp", "tier": "critical", "nhis": []}
        other = {"vendor": "Guest SaaS", "slug": "guest-saas", "tier": "high", "nhis": []}
        probe = ProbeResult(
            vendor="host-idp", ran=True, mode="fixture",
            nhis=[{
                "id": "guest-bot", "app_id": "guest-bot", "name": "Guest SaaS bot",
                "kind": "oauth_app", "status": "active", "principal": "guest-provisioning",
                "scopes": ["users.read"], "write_scopes": [], "source": "observed",
                "evidence": "tenant application guest-bot",
            }],
        )
        nhis = discover_nhis(host, probe, portfolio=[host, other])
        guest = nhis[0]
        self.assertTrue(guest["cross_vendor"])
        self.assertFalse(guest["declared"])
        findings, _ = evaluate_nhis(host, nhis, self.controls)
        self.assertIn("NHI-06", [f.control.id for f in findings])

    def test_unknown_owner_is_gap_not_finding(self):
        from vra.nhi import evaluate_nhis

        vendor = {"vendor": "X", "slug": "x", "tier": "high"}
        nhi = {
            "id": "bot", "name": "Bot", "kind": "service_account", "status": "active",
            "principal": "bot", "owner": "unknown", "last_rotated": "2026-06-01",
            "human_in_loop": True, "autonomy": "n/a", "output_logged": True,
            "scopes": [], "write_scopes": [], "source": "register", "orphan": False,
            "cross_vendor": False, "declared": True,
        }
        findings, gaps = evaluate_nhis(vendor, [nhi], self.controls)
        self.assertNotIn("NHI-02", [f.control.id for f in findings])
        self.assertIn("NHI-02", [g.control.id for g in gaps])

    def test_disabled_identity_with_write_scopes_fires_nhi07(self):
        from vra.nhi import evaluate_nhis

        vendor = {"vendor": "X", "slug": "x", "tier": "high"}
        nhi = {
            "id": "old", "name": "Old Agent", "kind": "oauth_app", "status": "disabled",
            "principal": "old-agent", "owner": "SecOps", "last_rotated": "2026-06-01",
            "human_in_loop": True, "autonomy": "n/a", "output_logged": True,
            "scopes": ["users.manage"], "write_scopes": ["users.manage"],
            "source": "register", "orphan": False, "cross_vendor": False, "declared": True,
        }
        findings, _ = evaluate_nhis(vendor, [nhi], self.controls)
        self.assertEqual([f.control.id for f in findings], ["NHI-07"])

    def test_suggests_with_write_scopes_fires_nhi08(self):
        from vra.nhi import evaluate_nhis

        vendor = {"vendor": "X", "slug": "x", "tier": "high"}
        nhi = {
            "id": "copilot", "name": "Copilot", "kind": "agent_principal", "status": "active",
            "principal": "copilot", "owner": "IdOps", "last_rotated": "2026-06-01",
            "human_in_loop": True, "autonomy": "suggests", "output_logged": True,
            "scopes": ["users.manage"], "write_scopes": ["users.manage"],
            "source": "register", "orphan": False, "cross_vendor": False, "declared": True,
        }
        findings, _ = evaluate_nhis(vendor, [nhi], self.controls)
        self.assertIn("NHI-08", [f.control.id for f in findings])
        self.assertNotIn("NHI-01", [f.control.id for f in findings])

    def test_inventory_persists_and_ages(self):
        from vra.nhi import NHIInventory

        tmp = Path(tempfile.mkdtemp()) / "nhis.json"
        try:
            inv = NHIInventory(path=tmp)
            rec = inv.upsert("v", {
                "id": "a", "app_id": "a", "name": "A", "kind": "oauth_app",
                "principal": "a", "vendor_name": "V",
            })
            self.assertEqual(rec["key"], "v|a")
            inv.save(RunConfig(dry_run=False))
            again = NHIInventory(path=tmp)
            self.assertEqual(len(again.all()), 1)
            self.assertEqual(again.all()[0]["first_seen"], rec["first_seen"])
        finally:
            shutil.rmtree(tmp.parent, ignore_errors=True)


class TestMonitorDaemon(unittest.TestCase):
    def test_parse_interval(self):
        from vra.monitor import parse_interval

        self.assertEqual(parse_interval("90"), 90)
        self.assertEqual(parse_interval("15m"), 900)
        self.assertEqual(parse_interval("1h"), 3600)
        self.assertEqual(parse_interval(30), 30)
        with self.assertRaises(ValueError):
            parse_interval("0")
        with self.assertRaises(ValueError):
            parse_interval("nope")

    def test_lock_rejects_live_pid_and_steals_stale(self):
        from vra.monitor import MonitorLock, pid_alive

        self.assertTrue(pid_alive(os.getpid()))
        tmp = Path(tempfile.mkdtemp())
        try:
            lock = MonitorLock(tmp / "monitor.lock")
            self.assertTrue(lock.acquire())
            other = MonitorLock(tmp / "monitor.lock")
            # A different live PID must not be stolen. PID 1 is init/systemd.
            (tmp / "monitor.lock").write_text("1", encoding="utf-8")
            self.assertTrue(pid_alive(1))
            self.assertFalse(other.acquire())
            # Dead PID is stolen.
            (tmp / "monitor.lock").write_text("99999999", encoding="utf-8")
            self.assertTrue(other.acquire())
            other.release()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_status_marks_dead_pid_stale(self):
        from vra.monitor import MonitorStatus, read_status

        tmp = Path(tempfile.mkdtemp()) / "monitor.json"
        try:
            st = MonitorStatus(tmp)
            st.data.update({"status": "running", "pid": 99999999})
            st.write()
            blob = read_status(tmp)
            self.assertEqual(blob["status"], "stale")
        finally:
            tmp.unlink(missing_ok=True)

    def test_interruptible_sleep_honours_stop(self):
        from vra.monitor import interruptible_sleep

        ev = threading.Event()
        ev.set()
        started = time.monotonic()
        self.assertFalse(interruptible_sleep(30, ev, tick=0.05))
        self.assertLess(time.monotonic() - started, 2)

    def test_identical_snapshots_are_not_rewritten(self):
        from vra.watch import snapshot_vendor, snapshots_unchanged

        vendor = yaml.safe_load((REPO / "vendors/meridian-revcycle.yaml").read_text())
        cfg = RunConfig(offline=True, snapshot_version="v1", dry_run=True)
        snaps = snapshot_vendor(vendor, cfg)
        self.assertTrue(all(not s.error for s in snaps))
        self.assertFalse(snapshots_unchanged(snaps, None))

    def test_once_cycle_writes_status(self):
        from vra.monitor import MonitorStatus, run_cycle

        status = MonitorStatus(Path(tempfile.mkdtemp()) / "monitor.json")
        try:
            cfg = RunConfig(
                offline=True, snapshot_version="v1", dry_run=True,
                fail_on_critical=False, vendors=["meridian-revcycle"],
            )
            payload = run_cycle(cfg, status)
            self.assertIn(payload.get("exit_code"), (0, 1))
            self.assertGreaterEqual(payload.get("vendor_count"), 1)
            self.assertGreaterEqual(payload.get("nhi_count"), 1)
            self.assertEqual(status.data["cycles_completed"], 1)
            self.assertIsNotNone(status.data["last_cycle"])
        finally:
            status.path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
