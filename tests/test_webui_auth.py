"""The local console is a privileged surface, so it must not be open.

Its POST routes spawn processes, read local paths (``trust_center_url`` and
``fixture`` both accept filesystem paths), and drive outbound fetches. Anyone
who can reach the port can do all three. These tests pin the three things that
stop that: a per-process token, a pinned Host header, and a same-origin check.
"""

from __future__ import annotations

import json
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import RunConfig  # noqa: E402
from vra.webui import LOOPBACK_HOSTS, console_url, start_server  # noqa: E402


def _get(url: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _post(url: str, body: dict, headers: dict[str, str] | None = None) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


class TestConsoleDefaultsToLoopback(unittest.TestCase):
    def test_default_bind_is_not_every_interface(self):
        self.assertEqual(RunConfig().webui_host, "127.0.0.1")


class TestConsoleRequiresAToken(unittest.TestCase):
    def setUp(self):
        self.server = start_server("127.0.0.1", 0, background=True)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.token = self.server.auth_token

    def test_a_token_is_generated(self):
        self.assertTrue(self.token)
        self.assertGreaterEqual(len(self.token), 32)

    def test_console_url_carries_the_token(self):
        self.assertIn(f"t={self.token}", console_url(self.server))

    def test_page_without_a_token_is_refused(self):
        code, _ = _get(f"{self.base}/")
        self.assertEqual(code, 401)

    def test_api_without_a_token_is_refused(self):
        code, _ = _get(f"{self.base}/api/summary")
        self.assertEqual(code, 401)

    def test_wrong_token_is_refused(self):
        code, _ = _get(f"{self.base}/api/summary", {"X-VRA-Token": "not-the-token"})
        self.assertEqual(code, 401)

    def test_post_without_a_token_cannot_spawn_the_monitor(self):
        code, _ = _post(f"{self.base}/api/monitor/start", {"offline": True})
        self.assertEqual(code, 401)

    def test_post_without_a_token_cannot_read_a_local_file(self):
        # onboard's trust_center_url accepts a filesystem path.
        code, _ = _post(
            f"{self.base}/api/onboard",
            {"name": "x", "offline": True, "trust_center_url": "/etc/hosts"},
        )
        self.assertEqual(code, 401)

    def test_header_token_is_accepted(self):
        code, body = _get(f"{self.base}/api/summary", {"X-VRA-Token": self.token})
        self.assertEqual(code, 200)
        self.assertIn("vendors", json.loads(body))

    def test_query_token_is_accepted(self):
        code, _ = _get(f"{self.base}/api/summary?t={self.token}")
        self.assertEqual(code, 200)

    def test_served_page_embeds_the_token(self):
        code, body = _get(f"{self.base}/?t={self.token}")
        self.assertEqual(code, 200)
        self.assertIn(self.token, body)
        self.assertNotIn("__VRA_TOKEN__", body)


class TestCrossSiteAndRebinding(unittest.TestCase):
    def setUp(self):
        self.server = start_server("127.0.0.1", 0, background=True)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.token = self.server.auth_token

    def test_cross_site_origin_is_refused_even_with_a_token(self):
        code, _ = _post(
            f"{self.base}/api/monitor/start",
            {"offline": True},
            {"X-VRA-Token": self.token, "Origin": "https://evil.example"},
        )
        self.assertEqual(code, 403)

    def test_same_origin_is_allowed(self):
        code, _ = _get(
            f"{self.base}/api/summary",
            {"X-VRA-Token": self.token, "Origin": f"http://127.0.0.1:{self.port}"},
        )
        self.assertEqual(code, 200)

    def test_rebound_hostname_is_refused(self):
        """A DNS name resolving to loopback must not reach the console."""
        code, _ = _get(
            f"{self.base}/api/summary",
            {"X-VRA-Token": self.token, "Host": f"attacker.example:{self.port}"},
        )
        self.assertEqual(code, 403)

    def test_loopback_hosts_are_allowed(self):
        for host in sorted(LOOPBACK_HOSTS):
            with self.subTest(host=host):
                code, _ = _get(
                    f"{self.base}/api/summary",
                    {"X-VRA-Token": self.token, "Host": f"{host}:{self.port}"},
                )
                self.assertEqual(code, 200)


if __name__ == "__main__":
    unittest.main()
