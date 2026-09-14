"""Entra ID as a scored IdP, not just a listed one.

Entra keeps entitlements on the service principal in two shapes — appRole
assignments (a GUID that only resolves against the resource principal's
catalogue) and delegated oauth2PermissionGrants (a space-separated string).
Discovery used to fetch neither, so every Entra identity reported no scopes and
NHI-01 could never fire: the tenant read as clean rather than as unassessed.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.config import WRITE_SCOPE_MARKERS  # noqa: E402,F401
from vra.idp import discover_from_recorded  # noqa: E402
from vra.nhi import evaluate_nhis, load_nhi_controls  # noqa: E402
from vra.probe import _extract_nhis, _is_write_scope  # noqa: E402

FIXTURE = REPO / "sandbox" / "probe" / "idp" / "entra_pages.json"


def _estate():
    estate, err = discover_from_recorded(FIXTURE)
    assert err is None, err
    assert estate is not None
    return estate


def _nhis():
    return {n["name"]: n for n in _extract_nhis(_estate().to_probe_blob())}


class TestEntraEntitlements(unittest.TestCase):
    def test_application_permissions_are_resolved_to_names(self):
        """An appRoleId is a GUID; only the catalogue makes it a permission."""
        copilot = _nhis()["Access Copilot"]
        self.assertIn("User.ReadWrite.All", copilot["scopes"])
        self.assertIn("Group.ReadWrite.All", copilot["scopes"])

    def test_delegated_permissions_are_split_from_the_scope_string(self):
        copilot = _nhis()["Access Copilot"]
        for scope in ("openid", "profile", "User.Read", "Directory.Read.All"):
            self.assertIn(scope, copilot["scopes"])

    def test_write_scopes_are_separated_from_read(self):
        copilot = _nhis()["Access Copilot"]
        self.assertEqual(
            copilot["write_scopes"], ["Group.ReadWrite.All", "User.ReadWrite.All"]
        )
        self.assertNotIn("Directory.Read.All", copilot["write_scopes"])
        self.assertNotIn("openid", copilot["write_scopes"])

    def test_an_unresolvable_approle_is_kept_not_dropped(self):
        """A permission we cannot name is still a permission held."""
        copilot = _nhis()["Access Copilot"]
        unresolved = [s for s in copilot["scopes"] if s.startswith("appRole:")]
        self.assertEqual(len(unresolved), 1)
        self.assertTrue(_estate().warnings)
        self.assertTrue(any("could not be resolved" in w for w in _estate().warnings))

    def test_a_read_only_principal_has_no_write_scopes(self):
        reporting = _nhis()["Reporting Reader"]
        self.assertIn("Directory.Read.All", reporting["scopes"])
        self.assertEqual(reporting["write_scopes"], [])


class TestEntraObjectModel(unittest.TestCase):
    def test_a_registration_and_its_principal_are_one_identity(self):
        """appId ties the two Graph objects together; two rows would double-count."""
        names = [n["name"] for n in _extract_nhis(_estate().to_probe_blob())]
        self.assertEqual(names.count("Access Copilot"), 1)
        self.assertEqual(names.count("Billing Bot"), 1)

    def test_a_principal_with_no_registration_is_still_inventoried(self):
        """Managed identities and gallery apps exist only as service principals."""
        rovo = _nhis()["Rovo Writer"]
        self.assertEqual(rovo["kind"], "service_account")
        self.assertEqual(rovo["write_scopes"], ["Directory.ReadWrite.All"])

    def test_the_grant_is_attributed_to_the_registration_not_the_mirror(self):
        estate = _estate()
        targets = {g["app_id"] for g in estate.oauth_grants}
        self.assertIn("app-copilot-01", targets, "attributed to the registration")
        self.assertNotIn("sp-copilot-01", targets, "not to its mirror principal")

    def test_no_identity_appears_twice(self):
        rows = _extract_nhis(_estate().to_probe_blob())
        ids = [r["id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)), f"duplicate rows: {ids}")


class TestEntraWriteScopeDetection(unittest.TestCase):
    """Graph grants state-changing power under names with no obvious verb."""

    WRITES = (
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Group.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Sites.FullControl.All",
        "Mail.Send",
        "Directory.AccessAsUser.All",
        "okta.users.manage",
    )
    READS = (
        "Directory.Read.All",
        "User.Read",
        "Files.Read.All",
        "Reports.Read.All",
        "openid",
        "profile",
        "email",
    )

    def test_state_changing_permissions_are_writes(self):
        for scope in self.WRITES:
            with self.subTest(scope=scope):
                self.assertTrue(_is_write_scope(scope))

    def test_read_permissions_are_not(self):
        for scope in self.READS:
            with self.subTest(scope=scope):
                self.assertFalse(_is_write_scope(scope))


class TestEntraIdentitiesAreScored(unittest.TestCase):
    """The point of the whole exercise: NHI-* can now fire on Entra."""

    def _score(self, overlay=None):
        vendor = {"vendor": "Contoso Entra", "slug": "contoso", "tier": "high"}
        rows = _extract_nhis(_estate().to_probe_blob())
        copilot = next(r for r in rows if r["name"] == "Access Copilot")
        copilot.update(overlay or {})
        return evaluate_nhis(vendor, [copilot], load_nhi_controls())

    def test_an_agent_with_write_scopes_and_no_review_fires_nhi01(self):
        findings, _ = self._score({"kind": "agent_principal", "human_in_loop": False})
        controls = {f.control.id for f in findings}
        self.assertIn("NHI-01", controls)
        nhi01 = next(f for f in findings if f.control.id == "NHI-01")
        self.assertEqual(nhi01.control.severity, "critical")
        self.assertIn("AC-6", nhi01.control.citation)
        self.assertIn("CC6.3", nhi01.control.citation)

    def test_the_same_agent_under_review_does_not_fire(self):
        findings, _ = self._score({"kind": "agent_principal", "human_in_loop": True})
        self.assertNotIn("NHI-01", {f.control.id for f in findings})

    def test_unknown_review_status_is_a_gap_not_a_pass(self):
        findings, gaps = self._score({"kind": "agent_principal", "human_in_loop": "unknown"})
        self.assertNotIn("NHI-01", {f.control.id for f in findings})
        self.assertIn("NHI-01", {g.control.id for g in gaps})

    def test_before_this_change_nhi01_was_unreachable(self):
        """With no scopes, applies_when fails and the control never evaluates."""
        vendor = {"vendor": "Contoso Entra", "slug": "contoso", "tier": "high"}
        blind = {
            "id": "app-copilot-01", "name": "Access Copilot", "kind": "agent_principal",
            "principal": "Access Copilot", "human_in_loop": False,
            "scopes": [], "write_scopes": [], "status": "active",
        }
        findings, _ = evaluate_nhis(vendor, [blind], load_nhi_controls())
        self.assertNotIn(
            "NHI-01", {f.control.id for f in findings},
            "this is the old behaviour: an agent that can act reads as clean",
        )


if __name__ == "__main__":
    unittest.main()
