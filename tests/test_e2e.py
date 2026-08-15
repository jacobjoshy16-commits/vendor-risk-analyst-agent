"""End-to-end: keychain survives a restart, the 3-step path runs, no secret leaks."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.creds import (  # noqa: E402
    FileKeyring,
    backend_info,
    delete_connector,
    get_secret,
    listed_connectors,
    reset_memory_keyring,
    resolve_secrets,
    set_secret,
)
from vra.connect import connect  # noqa: E402
from vra.config import RunConfig  # noqa: E402


SECRET = "ssws-e2e-super-secret-token-value-32"


class TestKeychainFallbackAndRestart(unittest.TestCase):
    """This sandbox (and many Linux boxes) have no Secret Service.

    Production must still store the token so a new shell can read it.
    """

    def setUp(self):
        reset_memory_keyring()
        self.tmp = Path(tempfile.mkdtemp())
        self.keyfile = self.tmp / "keyring.json"
        os.environ["VRA_KEYRING_FILE"] = str(self.keyfile)

    def tearDown(self):
        os.environ.pop("VRA_KEYRING_FILE", None)
        reset_memory_keyring()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_set_secret_works_when_os_keychain_is_missing(self):
        info = backend_info()
        self.assertTrue(info.startswith("file ("), info)
        set_secret("okta", "api_token", SECRET)
        self.assertEqual(get_secret("okta", "api_token"), SECRET)
        listed = listed_connectors()
        self.assertIn("okta", listed)
        self.assertNotIn(SECRET, json.dumps(listed))
        self.assertTrue(self.keyfile.exists())
        mode = stat.S_IMODE(self.keyfile.stat().st_mode)
        self.assertEqual(mode, 0o600, f"keyring file mode is {oct(mode)}, want 0600")
        # The file holds the value (that's the store) but nothing else should.
        on_disk = self.keyfile.read_text(encoding="utf-8")
        self.assertIn(SECRET, on_disk)

    def test_survives_a_new_python_process(self):
        """Shell restart = new process, empty memory. File/OS store must answer."""
        set_secret("okta", "api_token", SECRET)
        env = os.environ.copy()
        env["VRA_KEYRING_FILE"] = str(self.keyfile)
        env["PYTHONPATH"] = str(REPO / "src")
        script = (
            "from vra.creds import get_secret, reset_memory_keyring, listed_connectors; "
            "reset_memory_keyring(); "
            f"v = get_secret('okta', 'api_token'); "
            "idx = listed_connectors(); "
            "print('MATCH' if v == "
            + repr(SECRET)
            + " else 'MISS'); "
            "print('INDEX_CLEAN' if "
            + repr(SECRET)
            + " not in str(idx) else 'INDEX_LEAK')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(self.tmp),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("MATCH", proc.stdout)
        self.assertIn("INDEX_CLEAN", proc.stdout)

    def test_delete_forgets_across_restart(self):
        set_secret("okta", "api_token", SECRET)
        delete_connector("okta")
        self.assertIsNone(get_secret("okta", "api_token"))
        env = os.environ.copy()
        env["VRA_KEYRING_FILE"] = str(self.keyfile)
        env["PYTHONPATH"] = str(REPO / "src")
        proc = subprocess.run(
            [
                sys.executable, "-c",
                "from vra.creds import get_secret, reset_memory_keyring; "
                "reset_memory_keyring(); "
                "print(get_secret('okta', 'api_token'))",
            ],
            cwd=str(self.tmp), env=env, capture_output=True, text=True,
        )
        self.assertEqual((proc.stdout or "").strip(), "None")


class TestConnectDiscoverAssessReport(unittest.TestCase):
    def setUp(self):
        reset_memory_keyring()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "vendors").mkdir()
        (self.tmp / "data").mkdir()
        self.keyfile = self.tmp / "keyring.json"
        os.environ["VRA_KEYRING_FILE"] = str(self.keyfile)

    def tearDown(self):
        os.environ.pop("VRA_KEYRING_FILE", None)
        reset_memory_keyring()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_connect_stores_token_writes_stub_discovers(self):
        result = connect(
            "okta",
            base_url="https://dev-000000.okta.com",
            fixture="sandbox/probe/idp/okta_pages.json",
            offline=True,
            root=self.tmp,
            secrets={"api_token": SECRET},
        )
        self.assertTrue(result.stored)
        self.assertGreaterEqual(result.discovered, 8)
        yaml_text = (self.tmp / "vendors" / "okta.yaml").read_text(encoding="utf-8")
        self.assertNotIn(SECRET, yaml_text)
        self.assertNotIn("ssws-", yaml_text)
        nhis = json.loads((self.tmp / "data" / "nhis.json").read_text())
        dumped = json.dumps(nhis)
        self.assertNotIn(SECRET, dumped)
        self.assertEqual(get_secret("okta", "api_token"), SECRET)

    def test_assess_and_report_do_not_need_the_token_in_yaml(self):
        from vra.cli import assess
        from vra.report import summarize_latest

        result = assess(RunConfig(
            offline=True, snapshot_version="v1", dry_run=True,
            fail_on_critical=False, vendors=["meridian-revcycle"],
        ))
        self.assertIn(result.exit_code, (0, 1))
        self.assertGreaterEqual(result.vendor_count, 1)
        lines, _ = summarize_latest(out_dir=self.tmp / "out", data_dir=self.tmp / "data")
        blob = "\n".join(lines)
        self.assertNotIn(SECRET, blob)

    def test_discover_fixture_cli(self):
        from vra.discover import main as discover_main

        code = discover_main([
            "--fixture", "sandbox/probe/idp/okta_pages.json",
            "--dry-run",
        ])
        self.assertEqual(code, 0)

    def test_env_is_not_used_without_the_flag(self):
        os.environ["OKTA_API_TOKEN"] = SECRET
        try:
            secrets, err, used = resolve_secrets("okta", allow_env=False)
            self.assertTrue(err)
            self.assertFalse(used)
            self.assertEqual(secrets, {})
        finally:
            os.environ.pop("OKTA_API_TOKEN", None)


class TestFileKeyringPermissions(unittest.TestCase):
    def test_directory_is_private(self):
        tmp = Path(tempfile.mkdtemp()) / "nested" / "keyring.json"
        kr = FileKeyring(tmp)
        kr.set_password("vra:okta", "api_token", SECRET)
        self.assertEqual(stat.S_IMODE(tmp.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(tmp.parent.stat().st_mode), 0o700)
        kr.delete_password("vra:okta", "api_token")
        self.assertIsNone(kr.get_password("vra:okta", "api_token"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
