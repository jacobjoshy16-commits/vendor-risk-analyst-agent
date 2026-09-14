"""The register belongs to the human; machine state does not live in it.

Two separations are pinned here. Machine bookkeeping (last_assessed, snapshot
hashes) is written to data/, never back into a YAML somebody authored. And the
demo registers that ship with this repo sit apart from the ones `vra connect`
writes, so connecting a real vendor cannot collide with a fixture.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import register as reg  # noqa: E402
from vra.config import RunConfig  # noqa: E402
from vra.register import RegistryState, load_vendors, register_dirs  # noqa: E402

SANDBOX_REGISTERS = REPO / "sandbox" / "registers"
USER_REGISTERS = REPO / "vendors"


class TestRegisterDirectoriesAreSeparate(unittest.TestCase):
    def test_the_demo_registers_ship_outside_the_user_directory(self):
        shipped = sorted(p.stem for p in SANDBOX_REGISTERS.glob("*.yaml"))
        self.assertEqual(
            shipped,
            ["aegis-identity-cloud", "loop-workspace", "meridian-revcycle"],
        )

    def test_the_user_directory_holds_no_shipped_register(self):
        """A fixture in vendors/ would be committed, or shadow a real vendor."""
        tracked = {p.stem for p in SANDBOX_REGISTERS.glob("*.yaml")}
        present = {p.stem for p in USER_REGISTERS.glob("*.yaml")}
        self.assertEqual(tracked & present, set())

    def test_both_directories_are_loaded(self):
        slugs = {v["slug"] for v in load_vendors(RunConfig())}
        self.assertIn("aegis-identity-cloud", slugs)

    def test_a_user_register_shadows_a_demo_one_with_the_same_slug(self):
        with tempfile.TemporaryDirectory() as tmp:
            user = Path(tmp) / "vendors"
            user.mkdir()
            (user / "meridian-revcycle.yaml").write_text(
                yaml.safe_dump({
                    "vendor": "My Own Meridian", "slug": "meridian-revcycle",
                    "tier": "low",
                }),
                encoding="utf-8",
            )
            with unittest.mock.patch.object(reg, "VENDORS_DIR", user):
                loaded = {v["slug"]: v for v in load_vendors(RunConfig())}
        self.assertEqual(loaded["meridian-revcycle"]["vendor"], "My Own Meridian")
        self.assertEqual(loaded["meridian-revcycle"]["tier"], "low")

    def test_a_missing_user_directory_is_not_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.object(reg, "VENDORS_DIR", Path(tmp) / "nope"):
                self.assertEqual(len(load_vendors(RunConfig())), 3)

    def test_the_user_directory_is_overridable(self):
        self.assertIn(USER_REGISTERS, register_dirs())
        self.assertIn(SANDBOX_REGISTERS, register_dirs())
        self.assertLess(
            register_dirs().index(SANDBOX_REGISTERS),
            register_dirs().index(USER_REGISTERS),
            "the user directory must come last so it wins",
        )


class TestRegistryState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "registry_state.json"

    def test_records_and_reloads(self):
        state = RegistryState(self.path)
        state.record("acme", hashes={"changelog": "abc123"})
        state.save(RunConfig())

        reloaded = RegistryState(self.path)
        self.assertEqual(reloaded.get("acme")["snapshot_hashes"], {"changelog": "abc123"})
        self.assertTrue(reloaded.get("acme")["last_assessed"])

    def test_dry_run_writes_nothing(self):
        state = RegistryState(self.path)
        state.record("acme", hashes={"changelog": "abc123"})
        state.save(RunConfig(dry_run=True))
        self.assertFalse(self.path.exists())

    def test_a_legacy_state_block_is_carried_forward(self):
        """Upgrading from the in-register format must not lose history."""
        state = RegistryState(self.path)
        state.adopt_legacy([{
            "slug": "acme",
            "state": {"last_assessed": "2026-01-01T00:00:00+00:00",
                      "snapshot_hashes": {"dpa": "deadbeef"}},
        }])
        self.assertEqual(state.get("acme")["snapshot_hashes"], {"dpa": "deadbeef"})
        self.assertTrue(state.get("acme")["migrated_from_register"])

    def test_legacy_adoption_never_overwrites_newer_state(self):
        state = RegistryState(self.path)
        state.record("acme", hashes={"dpa": "current"})
        state.adopt_legacy([{"slug": "acme", "state": {"snapshot_hashes": {"dpa": "old"}}}])
        self.assertEqual(state.get("acme")["snapshot_hashes"], {"dpa": "current"})

    def test_an_empty_legacy_block_is_ignored(self):
        state = RegistryState(self.path)
        state.adopt_legacy([{"slug": "acme", "state": {"last_assessed": None,
                                                       "snapshot_hashes": {}}}])
        self.assertEqual(state.vendors, {})

    def test_a_corrupt_file_is_survivable(self):
        self.path.write_text("{not json", encoding="utf-8")
        self.assertEqual(RegistryState(self.path).vendors, {})

    def test_a_format_change_invalidates_the_file(self):
        self.path.write_text(json.dumps({"version": 0, "vendors": {"a": {}}}),
                             encoding="utf-8")
        self.assertEqual(RegistryState(self.path).vendors, {})


class TestAssessLeavesRegistersAlone(unittest.TestCase):
    """The regression this split exists to prevent."""

    def setUp(self):
        for name in ("data", "out", "pending_review"):
            shutil.rmtree(REPO / name, ignore_errors=True)
        self.addCleanup(lambda: [shutil.rmtree(REPO / n, ignore_errors=True)
                                 for n in ("data", "out", "pending_review")])

    def test_two_cycles_do_not_touch_a_single_register_byte(self):
        from vra.cli import assess

        before = {p: p.read_bytes()
                  for d in register_dirs() if d.is_dir()
                  for p in d.glob("*.yaml")}
        self.assertTrue(before, "there should be registers to protect")

        for snapshot in ("v1", "v2"):
            with redirect_stdout(io.StringIO()):
                assess(RunConfig(offline=True, snapshot_version=snapshot))

        after = {p: p.read_bytes()
                 for d in register_dirs() if d.is_dir()
                 for p in d.glob("*.yaml")}
        self.assertEqual(after, before, "a run must not rewrite a human's register")

    def test_the_run_records_its_state_in_data(self):
        from vra.cli import assess

        with redirect_stdout(io.StringIO()):
            assess(RunConfig(offline=True, snapshot_version="v1"))

        blob = json.loads((REPO / "data" / "registry_state.json").read_text(encoding="utf-8"))
        self.assertEqual(blob["version"], RegistryState.VERSION)
        entry = blob["vendors"]["aegis-identity-cloud"]
        self.assertTrue(entry["last_assessed"])
        self.assertIn("subprocessors", entry["snapshot_hashes"])

    def test_a_new_register_carries_no_machine_owned_block(self):
        """`vra connect` writes a register a human owns, start to finish."""
        from vra.connect import build_stub

        stub = build_stub(
            provider="okta", slug="acme", vendor_name="Acme",
            base_url="https://acme.okta.com",
        )
        self.assertNotIn("state", stub,
                         "a fresh register must carry no machine-owned block")
        self.assertIn("probe", stub)


if __name__ == "__main__":
    unittest.main()
