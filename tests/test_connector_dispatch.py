"""Connector dispatch: the registry must be built before anyone reads it.

Both regressions here produced the same field symptom — an Auth0 tenant walked
with the Okta API and answering 404 — from two independent defects:

  1. ``registry._ensure`` published ``_READY`` *before* registering, so a
     second poll thread could read a half-built registry.
  2. ``discover_estate`` treated "provider not in the registry" as "must be
     Okta", turning that half-built read into a call to the wrong vendor.
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import protocol, registry  # noqa: E402
from vra.idp import MemoryTransport, discover_estate  # noqa: E402


class TestRegistryInitIsAtomic(unittest.TestCase):
    def test_a_reader_never_sees_a_half_built_registry(self):
        """A thread reading mid-registration waits for the full set.

        ``okta`` registers before ``auth0`` in ``protocol.register_all``, so a
        reader that got in between them used to see Okta and not Auth0.
        """
        real_register_all = protocol.register_all
        registering = threading.Event()

        def slow_register_all() -> None:
            registering.set()
            time.sleep(0.2)  # the window a second thread used to read through
            real_register_all()

        saved = (
            dict(registry._MANIFESTS),
            dict(registry._LISTERS),
            dict(registry._PINGS),
            registry._READY,
        )
        seen: set[str] = set()
        try:
            protocol.register_all = slow_register_all  # type: ignore[assignment]
            with registry._LOCK:
                registry._MANIFESTS.clear()
                registry._LISTERS.clear()
                registry._PINGS.clear()
                registry._READY = False

            builder = threading.Thread(target=registry.known_ids, name="builder")
            builder.start()
            self.assertTrue(registering.wait(5), "registration never started")
            seen = registry.known_ids()  # reads while the builder is mid-flight
            builder.join(10)
        finally:
            protocol.register_all = real_register_all  # type: ignore[assignment]
            with registry._LOCK:
                registry._MANIFESTS.clear()
                registry._MANIFESTS.update(saved[0])
                registry._LISTERS.clear()
                registry._LISTERS.update(saved[1])
                registry._PINGS.clear()
                registry._PINGS.update(saved[2])
                registry._READY = saved[3]
            registry.known_ids()  # leave a complete registry for the rest

        self.assertIn("okta", seen)
        self.assertIn("auth0", seen, "reader saw Okta but not Auth0 — partial registry")

    def test_concurrent_first_readers_all_get_the_full_set(self):
        results: list[set[str]] = []
        errors: list[BaseException] = []
        start = threading.Barrier(6)

        def read() -> None:
            try:
                start.wait(5)
                results.append(registry.known_ids())
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=read) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 6)
        for ids in results:
            self.assertIn("auth0", ids)
            self.assertIn("okta", ids)


class TestUnknownProviderIsNotWalkedAsOkta(unittest.TestCase):
    def test_unresolved_provider_errors_instead_of_calling_okta(self):
        bus = MemoryTransport()
        estate = discover_estate(
            provider="auth0_typo",
            base_url="https://acme.us.auth0.com",
            transport=bus,
            token="tenant-token",
        )
        self.assertEqual(bus.calls, [], "an unknown provider must make no API calls")
        self.assertIsNotNone(estate.error)
        self.assertIn("auth0_typo", estate.error or "")
        self.assertEqual(estate.provider, "auth0_typo")

    def test_auth0_still_routes_to_the_auth0_walker(self):
        bus = MemoryTransport()
        estate = discover_estate(
            provider="auth0",
            base_url="https://acme.us.auth0.com",
            transport=bus,
            token="tenant-token",
        )
        self.assertEqual(estate.provider, "auth0")
        # It reached the Auth0 walker: the calls it made are Auth0 management
        # API paths, not /api/v1/apps.
        called = " ".join(url for _, url in bus.calls)
        self.assertNotIn("/api/v1/apps", called)


if __name__ == "__main__":
    unittest.main(verbosity=2)
