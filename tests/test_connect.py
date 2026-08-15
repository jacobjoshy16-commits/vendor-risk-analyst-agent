"""Interactive connect / report / enrich — the 3-step human path."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import RunConfig  # noqa: E402
from vra.creds import (  # noqa: E402
    get_secret,
    reset_memory_keyring,
    set_secret,
    use_memory_keyring,
)
from vra.connect import (  # noqa: E402
    build_stub,
    connect,
    enrich_vendor,
    is_connect_stub,
    normalize_base_url,
)
from vra.monitor import build_parser as monitor_parser  # noqa: E402
from vra.report import summarize_latest  # noqa: E402


OKTA_FIXTURE = "sandbox/probe/idp/okta_pages.json"


class TestConnectHelpers(unittest.TestCase):
    def test_normalize_adds_https_and_strips_slash(self):
        self.assertEqual(
            normalize_base_url("okta", "acme.okta.com/"),
            "https://acme.okta.com",
        )
        self.assertEqual(
            normalize_base_url("slack", None),
            "https://slack.com",
        )

    def test_stub_has_required_keys_and_no_secret_slot(self):
        stub = build_stub(
            provider="okta",
            slug="okta",
            vendor_name="Okta",
            base_url="https://acme.okta.com",
        )
        self.assertEqual(stub["slug"], "okta")
        self.assertEqual(stub["vendor"], "Okta")
        self.assertEqual(stub["probe"]["provider"], "okta")
        self.assertEqual(stub["probe"]["mode"], "live")
        self.assertEqual(stub["ai_surface"], [])
        self.assertEqual(stub["nhis"], [])
        self.assertTrue(is_connect_stub(stub))
        dumped = yaml.safe_dump(stub)
        self.assertNotIn("api_token", dumped)
        self.assertNotIn("token_env", dumped)


class TestConnectWizard(unittest.TestCase):
    def setUp(self):
        use_memory_keyring()
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "vendors").mkdir()
        (self.tmp / "data").mkdir()

    def tearDown(self):
        reset_memory_keyring()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_connect_writes_stub_and_discovers_from_fixture(self):
        result = connect(
            "okta",
            base_url="https://dev-000000.okta.com",
            fixture=OKTA_FIXTURE,
            offline=True,
            root=self.tmp,
            secrets={"api_token": "ssws-test-token-not-for-yaml"},
        )
        self.assertTrue(result.created)
        self.assertGreaterEqual(result.discovered, 8)
        path = self.tmp / "vendors" / "okta.yaml"
        self.assertTrue(path.exists())
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("ssws-test-token-not-for-yaml", text)
        data = yaml.safe_load(text)
        self.assertEqual(data["probe"]["provider"], "okta")
        self.assertEqual(data["onboarding"]["by"], "vra connect")
        self.assertEqual(get_secret("okta", "api_token"), "ssws-test-token-not-for-yaml")
        nhis = json.loads((self.tmp / "data" / "nhis.json").read_text())
        self.assertGreaterEqual(len(nhis["identities"]), 8)

    def test_connect_does_not_prompt_when_flags_complete(self):
        def boom(_prompt: str) -> str:
            raise AssertionError(f"prompted unexpectedly: {_prompt}")

        set_secret("okta", "api_token", "already-stored")
        result = connect(
            "okta",
            base_url="https://acme.okta.com",
            fixture=OKTA_FIXTURE,
            offline=True,
            skip_discover=True,
            root=self.tmp,
            prompt=True,
            input_fn=boom,
            getpass_fn=boom,
        )
        self.assertTrue(result.created)
        self.assertTrue(result.stored)

    def test_connect_prompts_for_missing_token(self):
        asked: list[str] = []

        def fake_getpass(prompt: str) -> str:
            asked.append(prompt)
            return "prompted-token"

        result = connect(
            "okta",
            base_url="https://acme.okta.com",
            fixture=OKTA_FIXTURE,
            offline=True,
            skip_discover=True,
            root=self.tmp,
            prompt=True,
            getpass_fn=fake_getpass,
            input_fn=lambda p: (_ for _ in ()).throw(AssertionError(p)),
        )
        self.assertTrue(asked)
        self.assertEqual(get_secret("okta", "api_token"), "prompted-token")
        self.assertTrue(result.stored)

    def test_connect_refuses_to_overwrite_hand_authored_register(self):
        dest = self.tmp / "vendors" / "okta.yaml"
        dest.write_text(
            "vendor: Hand Authored\nslug: okta\ntier: high\nai_surface: []\n",
            encoding="utf-8",
        )
        with self.assertRaises(ValueError) as ctx:
            connect(
                "okta",
                base_url="https://acme.okta.com",
                fixture=OKTA_FIXTURE,
                offline=True,
                skip_discover=True,
                root=self.tmp,
                secrets={"api_token": "x"},
            )
        self.assertIn("already exists", str(ctx.exception))
        self.assertIn("Hand Authored", dest.read_text(encoding="utf-8"))

    def test_connect_updates_its_own_stub(self):
        first = connect(
            "okta",
            base_url="https://old.okta.com",
            fixture=OKTA_FIXTURE,
            offline=True,
            skip_discover=True,
            root=self.tmp,
            secrets={"api_token": "tok"},
        )
        self.assertTrue(first.created)
        second = connect(
            "okta",
            base_url="https://new.okta.com",
            fixture=OKTA_FIXTURE,
            offline=True,
            skip_discover=True,
            root=self.tmp,
        )
        self.assertTrue(second.updated)
        self.assertFalse(second.created)
        data = yaml.safe_load((self.tmp / "vendors" / "okta.yaml").read_text())
        self.assertEqual(data["probe"]["base_url"], "https://new.okta.com")

    def test_connect_noninteractive_without_url_is_a_cli_error(self):
        from vra.connect import main as connect_main

        code = connect_main(["--provider", "okta", "--yes"])
        self.assertEqual(code, 2)

    def test_write_scope_warning_surfaces(self):
        import base64

        def b64(obj):
            raw = json.dumps(obj, separators=(",", ":")).encode("ascii")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        jwt = f"{b64({'alg': 'none'})}.{b64({'scope': 'okta.users.manage'})}.x"
        result = connect(
            "okta",
            base_url="https://acme.okta.com",
            fixture=OKTA_FIXTURE,
            offline=True,
            skip_discover=True,
            root=self.tmp,
            secrets={"api_token": jwt},
        )
        self.assertIsNotNone(result.scope_warning)
        self.assertIn("write", (result.scope_warning or "").lower())
        text = "\n".join(result.lines())
        self.assertIn("⚠", text)
        self.assertNotIn(jwt, text)


class TestMonitorDefaults(unittest.TestCase):
    def test_webui_on_by_default(self):
        args = monitor_parser().parse_args([])
        self.assertTrue(args.webui)
        self.assertEqual(args.interval, "900")

    def test_no_webui_flag(self):
        args = monitor_parser().parse_args(["--no-webui", "--offline"])
        self.assertFalse(args.webui)
        self.assertTrue(args.offline)

    def test_explicit_webui_still_accepted(self):
        args = monitor_parser().parse_args(["--webui", "--interval", "15m"])
        self.assertTrue(args.webui)
        self.assertEqual(args.interval, "15m")


class TestReportAndEnrich(unittest.TestCase):
    def test_report_empty_tells_you_to_connect(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            lines, path = summarize_latest(out_dir=tmp / "out", data_dir=tmp / "data")
            self.assertIsNone(path)
            blob = "\n".join(lines)
            self.assertIn("python3 vra.py connect", blob)
            self.assertIn("python3 vra.py monitor", blob)
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)

    def test_report_prints_stored_findings_only(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            out = tmp / "out"
            data = tmp / "data"
            out.mkdir()
            data.mkdir()
            (out / "latest.md").write_text("# pack\n", encoding="utf-8")
            (out / "latest.json").write_text(
                json.dumps(
                    {
                        "generated_at": "2026-08-15T12:00:00+00:00",
                        "findings": [
                            {
                                "id": "f1",
                                "kind": "finding",
                                "severity": "critical",
                                "control_id": "NHI-01",
                                "vendor_name": "Okta",
                                "feature": "Access Copilot",
                                "state": "open",
                            }
                        ],
                        "gaps": [
                            {
                                "id": "g1",
                                "kind": "gap",
                                "control_id": "NHI-02",
                                "vendor": "okta",
                                "state": "open",
                            }
                        ],
                        "nhis": [{"id": "a"}, {"id": "b"}],
                        "events": [
                            {
                                "kind": "entitlement_change",
                                "gained_write_scope": True,
                                "nhi_name": "Payroll Sync",
                                "added_scopes": ["okta.users.manage"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            lines, path = summarize_latest(out_dir=out, data_dir=data)
            self.assertEqual(path, out / "latest.md")
            blob = "\n".join(lines)
            self.assertIn("NHI-01", blob)
            self.assertIn("Access Copilot", blob)
            self.assertIn("NHIs       : 2", blob)
            self.assertIn("Payroll Sync", blob)
            self.assertNotIn("AIV-07", blob)  # not in the store — must not invent
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)

    def test_enrich_lists_unknowns_does_not_invent(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            (tmp / "vendors").mkdir()
            stub = build_stub(
                provider="okta",
                slug="okta",
                vendor_name="Okta",
                base_url="https://acme.okta.com",
            )
            (tmp / "vendors" / "okta.yaml").write_text(
                yaml.safe_dump(stub), encoding="utf-8"
            )
            lines = enrich_vendor("okta", root=tmp)
            blob = "\n".join(lines)
            self.assertIn("ai_surface", blob)
            self.assertIn("21-day", blob)
            self.assertNotIn("autonomy: acts", blob)
            self.assertNotIn("model_provider:", blob)
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)


class TestEntryDispatch(unittest.TestCase):
    def test_vra_py_knows_the_new_commands(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("vra_entry", REPO / "vra.py")
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for cmd in ("connect", "report", "enrich", "creds", "monitor"):
            self.assertIn(cmd, mod.SUBCOMMANDS)

    def test_connect_main_fixture_exit_zero(self):
        from vra.connect import main as connect_main
        from vra.creds import use_memory_keyring, reset_memory_keyring
        import shutil

        use_memory_keyring()
        tmp = Path(tempfile.mkdtemp())
        try:
            # Exercise the CLI parser; write into a temp tree via connect()
            # (main() writes to the repo — use --dry-run so it does not).
            code = connect_main([
                "--provider", "okta",
                "--base-url", "https://dev-000000.okta.com",
                "--fixture", OKTA_FIXTURE,
                "--offline",
                "--yes",
                "--dry-run",
            ])
            self.assertEqual(code, 0)
            self.assertFalse((REPO / "vendors" / "okta.yaml").exists())
        finally:
            reset_memory_keyring()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
