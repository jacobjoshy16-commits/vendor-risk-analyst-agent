"""The end-to-end scenario: a vendor pushes an update that is not from the vendor.

scripts/simulate_push.py stands up a vendor distribution server and drives the
whole chain over HTTP. This pins the two outcomes that matter, so the demo
cannot silently stop working.

The threat model is the realistic one. The attacker owns the artifact mirror, so
they control the binary AND the SHA-256 published beside it. They do not have
the signing key, which a real vendor publishes through a separate channel.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


class VendorPushSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proc = subprocess.run(
            [sys.executable, "scripts/simulate_push.py"],
            cwd=REPO, capture_output=True, text=True, timeout=300)
        cls.code, cls.out = proc.returncode, proc.stdout + proc.stderr

    def test_the_simulation_succeeds(self):
        self.assertEqual(self.code, 0, self.out[-2000:])

    def test_the_genuine_release_is_accepted(self):
        """NEGATIVE CONTROL. A gate that blocks everything is an outage."""
        self.assertIn("genuine release      exit 0  ACCEPTED", self.out)
        self.assertIn("PASS — safe to deploy", self.out)

    def test_the_substituted_release_is_blocked(self):
        self.assertIn("substituted release  exit 1  BLOCKED", self.out)
        self.assertIn("BLOCKED — do not deploy", self.out)

    def test_the_attacker_successfully_updated_the_published_hash(self):
        """If the substituted package failed the hash check too, the demo would
        prove nothing -- a plain hash check would have caught it."""
        self.assertIn("UPDATED to match the new binary", self.out)
        blocked = self.out.split("SUBSTITUTED RELEASE — cryptography", 1)[-1]
        self.assertIn("MATCH", blocked)
        self.assertIn("INVALID", blocked)

    def test_the_signature_is_what_caught_it(self):
        self.assertIn("published hash MATCHES but the signature does not verify",
                      self.out)

    def test_the_decision_cites_the_standard(self):
        self.assertIn("NERC CIP-010-4 R1 Part 1.6", self.out)

    def test_an_audit_record_is_written_back(self):
        self.assertIn("AUDIT RECORD WRITTEN BACK", self.out)
        for field in ("hash_match             True",
                      "signature_verified     False",
                      "integrity_verified     False"):
            self.assertIn(field, self.out)

    def test_an_alert_is_routed_to_a_named_owner(self):
        self.assertIn("alert → CIP Senior Manager / Security on-call", self.out)

    def test_the_model_and_the_rule_engine_agree_here(self):
        self.assertIn("analyst disposition    block", self.out)
        self.assertIn("rule_engine_verdict    block", self.out)


if __name__ == "__main__":
    unittest.main()
