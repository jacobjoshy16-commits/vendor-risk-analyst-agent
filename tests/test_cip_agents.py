"""Following third-party agents through the IdP.

The claims under test:
  - a third party's identity holding a role on an ESP-facing system is found
    from what the IdP quotes (owning tenant, resource id), not from a name
  - a role nobody approved, and an agent nobody declared, each raise a finding
  - the monitor reports what changed between reads, and only concludes an
    agent is gone from a complete read
  - an unreachable IdP never resolves an open finding
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from io import StringIO
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra import cipagents  # noqa: E402
from vra.cip import assess_estate, load_cip_controls  # noqa: E402
from vra.cipstate import FindingStore  # noqa: E402
from vra.config import RunConfig  # noqa: E402
from vra.evaluate import to_record  # noqa: E402
from vra.grid import Estate  # noqa: E402

GRID = REPO / "sandbox" / "grid"
V1 = GRID / "idp" / "entra_v1.json"
V2 = GRID / "idp" / "entra_v2.json"
AS_OF = date(2026, 10, 4)

SENTINEL = "5e000000-0000-4000-8000-0000000000a9"
CASCADE = "ca000000-0000-4000-8000-0000000000a9"
IRONWOOD = "10000000-0000-4000-8000-0000000000a9"


def _agent_controls():
    return [c for c in load_cip_controls() if c.subject == cipagents.SUBJECT]


def _score(agents):
    estate = Estate(agents=agents)
    findings, gaps, _, coverage = assess_estate(estate, _agent_controls(), when=AS_OF)
    return findings, gaps, coverage


def _by_id(sighting):
    return {a["agent_id"]: a for a in sighting.agents}


class WhatTheIdPSays(unittest.TestCase):
    """The Entra walker keeps the two facts CIP scope rests on."""

    def test_owning_tenant_and_resource_are_quoted_from_graph(self):
        from vra.idp import discover_from_recorded
        from vra.probe import _extract_nhis

        estate, err = discover_from_recorded(V2)
        self.assertIsNone(err)
        nhis = {n["id"]: n for n in _extract_nhis(estate.to_probe_blob())}
        sentinel = nhis["sp-sentinel-relayops"]
        self.assertEqual(sentinel["app_owner_org"], "5e000000-0000-4000-8000-000000000005")
        self.assertIn(
            {"resource_id": "sp-relay-settings", "resource_name": "Relay Settings Service",
             "permission": "RelaySettings.Write.All"},
            sentinel["resource_grants"],
        )

    def test_both_pages_of_service_principals_are_walked(self):
        sighting = cipagents.sight(GRID, fixture=V2)
        # The agents are all on page two. Stopping at page one finds none.
        self.assertEqual(sighting.pages_fetched, 4)
        self.assertIn(IRONWOOD, _by_id(sighting))


class Scope(unittest.TestCase):
    def setUp(self):
        self.v1 = cipagents.sight(GRID, fixture=V1)
        self.v2 = cipagents.sight(GRID, fixture=V2)

    def test_declared_agents_are_followed(self):
        self.assertTrue(self.v1.complete)
        self.assertEqual(set(_by_id(self.v1)), {SENTINEL, CASCADE})

    def test_a_third_party_with_no_esp_role_is_out_of_scope_not_passing(self):
        names = {a["name"] for a in self.v2.agents}
        self.assertNotIn("Northgate Docs Portal", names)
        self.assertEqual(self.v2.out_of_scope, 1)

    def test_resource_principals_holding_nothing_are_not_counted(self):
        # Microsoft Graph's own principal is owned by another tenant too. A real
        # tenant has hundreds of those; counting them would make the number noise.
        self.assertEqual(self.v1.out_of_scope, 1)

    def test_an_undeclared_third_party_reaching_the_esp_is_followed(self):
        iron = _by_id(self.v2)[IRONWOOD]
        self.assertFalse(iron["registered"])
        self.assertTrue(iron["third_party"])
        self.assertEqual(iron["esp_systems"], ["Relay settings service"])
        self.assertEqual(iron["impact_rating"], "medium")

    def test_ai_is_a_label_from_the_register_never_inferred(self):
        self.assertTrue(_by_id(self.v2)[SENTINEL]["ai_agent"])
        self.assertIsNone(_by_id(self.v2)[IRONWOOD]["ai_agent"])

    def test_no_register_means_nothing_is_followed(self):
        empty = Path(tempfile.mkdtemp())
        sighting = cipagents.sight(empty)
        self.assertFalse(sighting.configured)
        self.assertEqual(sighting.agents, [])


class Controls(unittest.TestCase):
    def test_v1_is_clean(self):
        findings, gaps, coverage = _score(cipagents.sight(GRID, fixture=V1).agents)
        self.assertEqual(findings, [])
        self.assertEqual(gaps, [])
        # Negative control with a denominator: both agents were examined.
        self.assertEqual(coverage["CIP-35"].applicable, 2)
        self.assertEqual(coverage["CIP-36"].passed, 2)

    def test_v2_raises_exactly_the_two_planted_problems(self):
        findings, gaps, _ = _score(cipagents.sight(GRID, fixture=V2).agents)
        got = sorted((a.control.id, a.subject) for a in findings)
        self.assertEqual(got, [("CIP-35", IRONWOOD), ("CIP-36", SENTINEL)])
        self.assertEqual(gaps, [])
        cip36 = next(a for a in findings if a.control.id == "CIP-36")
        self.assertEqual(cip36.observed["unapproved_esp_permissions"],
                         ["RelaySettings.Write.All"])
        self.assertEqual(cip36.observed["agent"], "Sentinel RelayOps Agent")

    def test_no_approvals_on_file_is_a_gap_not_a_pass(self):
        agents = copy.deepcopy(cipagents.sight(GRID, fixture=V1).agents)
        for a in agents:
            a["approved_permissions"] = None
            a["unapproved_esp_permissions"] = None
        findings, gaps, _ = _score(agents)
        self.assertEqual(findings, [])
        self.assertEqual({g.control.id for g in gaps}, {"CIP-36"})

    def test_a_disabled_identity_is_not_access(self):
        agents = copy.deepcopy(cipagents.sight(GRID, fixture=V2).agents)
        for a in agents:
            a["status"] = "disabled"
        findings, _, _ = _score(agents)
        self.assertEqual(findings, [])

    def test_a_rename_does_not_fork_the_finding(self):
        agents = cipagents.sight(GRID, fixture=V2).agents
        before = {a.id for a in _score(agents)[0]}
        renamed = copy.deepcopy(agents)
        for a in renamed:
            a["name"] = a["agent"] = a["name"] + " v2"
        after = _score(renamed)[0]
        self.assertEqual(before, {a.id for a in after})
        self.assertTrue(all(a.observed["agent"].endswith(" v2") for a in after))


class Follow(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ledger = cipagents.open_ledger(self.tmp / "agents.json")

    def _follow(self, fixture):
        return cipagents.follow(cipagents.sight(GRID, fixture=fixture), self.ledger)

    def test_first_read_is_one_line_not_one_per_agent(self):
        events = self._follow(V1)
        self.assertEqual([e["kind"] for e in events], ["first_read"])
        self.assertEqual(events[0]["count"], 2)

    def test_changes_between_reads_are_reported(self):
        self._follow(V1)
        events = self._follow(V2)
        kinds = {(e["kind"], e["agent_id"]) for e in events}
        self.assertEqual(kinds, {("permissions", SENTINEL), ("new", IRONWOOD)})
        perm = next(e for e in events if e["kind"] == "permissions")
        self.assertEqual(perm["added"], ["RelaySettings.Write.All"])

    def test_an_agent_that_leaves_is_reported_gone_and_back(self):
        self._follow(V1)
        self._follow(V2)
        gone = self._follow(V1)
        self.assertIn(("gone", IRONWOOD), {(e["kind"], e["agent_id"]) for e in gone})
        back = self._follow(V2)
        self.assertIn(("back", IRONWOOD), {(e["kind"], e["agent_id"]) for e in back})

    def test_an_unreachable_idp_marks_stale_and_concludes_nothing(self):
        self._follow(V2)
        events = self._follow(self.tmp / "missing.json")
        self.assertEqual(events, [])
        rows = [r for r in self.ledger.all() if r["vendor"] == cipagents.LEDGER_SLUG]
        self.assertTrue(rows and all(r.get("stale") for r in rows))
        self.assertFalse(any(r.get("gone") for r in rows))

    def test_a_truncated_read_never_concludes_gone(self):
        self._follow(V2)
        partial = cipagents.sight(GRID, fixture=V1)
        partial.truncated = True
        events = cipagents.follow(partial, self.ledger)
        self.assertNotIn("gone", {e["kind"] for e in events})
        self.assertEqual(cipagents.unassessed(partial, _agent_controls()),
                         {"CIP-35", "CIP-36"})

    def test_history_survives_a_restart(self):
        self._follow(V1)
        first_seen = self.ledger.identities[f"idp|{SENTINEL}"]["first_seen"]
        reopened = cipagents.open_ledger(self.tmp / "agents.json")
        self.assertEqual(reopened.identities[f"idp|{SENTINEL}"]["first_seen"], first_seen)


class CarryForward(unittest.TestCase):
    """The finding store must not read an unreachable IdP as a fix."""

    def setUp(self):
        self.store = FindingStore(Path(tempfile.mkdtemp()) / "f.json")
        findings, _, _ = _score(cipagents.sight(GRID, fixture=V2).agents)
        self.records = [to_record(a) for a in findings]
        self.store.reconcile(self.records, AS_OF)

    def test_unassessed_controls_are_carried(self):
        delta = self.store.reconcile([], AS_OF, unassessed={"CIP-35", "CIP-36"})
        self.assertEqual(delta.resolved, [])
        self.assertEqual(len(delta.still_open), 2)

    def test_assessed_and_absent_still_resolves(self):
        delta = self.store.reconcile([], AS_OF)
        self.assertEqual(len(delta.resolved), 2)


class EvidencePack(unittest.TestCase):
    """Zero subjects because nobody looked is not zero subjects because none exist."""

    def _pack(self, unassessed):
        from vra.evidence import build_pack, render_html, render_markdown

        controls = _agent_controls()
        estate = Estate(agents=[])
        findings, gaps, verified, coverage = assess_estate(estate, controls, when=AS_OF)
        pack = build_pack(estate, controls, findings, gaps, verified, coverage,
                          when=AS_OF, unassessed=unassessed)
        return render_markdown(pack), render_html(pack)

    def test_an_unread_idp_is_reported_not_assessed(self):
        md, html = self._pack({"CIP-35": "IdP not read (401)", "CIP-36": "IdP not read (401)"})
        self.assertIn("CIP-35", md)
        self.assertIn("NOT ASSESSED — IdP not read (401)", md)
        self.assertNotIn("not applicable", md.split("CIP-35", 1)[1].split("\n", 1)[0])
        self.assertIn("NOT ASSESSED", html)

    def test_a_read_idp_with_no_agents_is_not_applicable(self):
        md, _ = self._pack({})
        self.assertNotIn("NOT ASSESSED", md)
        self.assertIn("not applicable", md)


class MonitorCycle(unittest.TestCase):
    """The real `cip monitor` cycle, four times over a changing IdP."""

    def setUp(self):
        from vra.cipcli import build_parser
        from vra.gridbuild import build

        self.tmp = Path(tempfile.mkdtemp())
        self.grid = self.tmp / "grid"
        build(self.grid, today=AS_OF)
        shutil.copy(GRID / cipagents.AGENTS_FILE, self.grid / cipagents.AGENTS_FILE)
        shutil.copytree(GRID / "idp", self.grid / "idp")
        self.args = build_parser().parse_args(
            ["monitor", "--grid-dir", str(self.grid), "--substations", "40", "--no-color"])
        self.store = FindingStore(self.tmp / "findings.json")
        self.ledger = cipagents.open_ledger(self.tmp / "agents.json")
        patcher = mock.patch("vra.cipalert.CIP_ALERT_LOG", self.tmp / "alerts.jsonl")
        patcher.start()
        self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ, {"VRA_CIP_WEBHOOK": ""})
        env.start()
        self.addCleanup(env.stop)

    def _cycle(self, fixture, *, baseline=False):
        from vra.cipcli import _cycle

        self.args.idp_fixture = fixture
        out = StringIO()
        with redirect_stdout(out):
            count, summary = _cycle(self.args, False, AS_OF, self.store,
                                    baseline=baseline, ledger=self.ledger)
        return count, summary, out.getvalue()

    def _alerts(self):
        path = self.tmp / "alerts.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def test_follows_the_idp_across_cycles(self):
        _, _, text = self._cycle(V1, baseline=True)
        self.assertIn("following 2 third-party agents", text)
        self.assertEqual(self._alerts(), [])

        _, summary, text = self._cycle(V2)
        self.assertIn("+RelaySettings.Write.All", text)
        self.assertIn("Ironwood Field Copilot", text)
        new = [a for a in self._alerts() if a["control_id"] in ("CIP-35", "CIP-36")]
        self.assertEqual(sorted(a["control_id"] for a in new), ["CIP-35", "CIP-36"])

        _, summary, text = self._cycle(self.tmp / "nowhere.json")
        self.assertIn("IdP not read", text)
        self.assertEqual(summary["resolved"], 0, "an unreachable IdP is not an all-clear")

        _, summary, text = self._cycle(V1)
        self.assertEqual(summary["resolved"], 2)
        self.assertIn("no longer in the IdP: Ironwood Field Copilot", text)


class LiveRead(unittest.TestCase):
    """mode: live goes through the real credential resolver and Graph walker.

    Only the socket is replaced: the transport replays the recorded pages.
    """

    def test_live_mode_reads_through_the_same_walker(self):
        from vra.idp import load_recorded_transport

        grid = Path(tempfile.mkdtemp())
        register = cipagents.load_register(GRID)
        register["idp"] = {**register["idp"], "mode": "live",
                           "token_env": "VRA_TEST_GRAPH_TOKEN"}
        (grid / cipagents.AGENTS_FILE).write_text(json.dumps(register))
        transport, _, _ = load_recorded_transport(V2)
        cfg = RunConfig(allow_env_creds=True)
        with mock.patch.dict(os.environ, {"VRA_TEST_GRAPH_TOKEN": "test-token-not-real"}), \
                mock.patch("vra.creds.get_secret", return_value=None):
            sighting = cipagents.sight(grid, cfg=cfg, transport=transport)
        self.assertIsNone(sighting.error)
        self.assertEqual(sighting.mode, "live")
        self.assertIn(IRONWOOD, _by_id(sighting))
        # Read-only: following an agent never writes to the directory.
        methods = [method for method, _url in transport.calls]
        self.assertTrue(methods and all(m == "GET" for m in methods))

    def test_offline_skips_a_live_read_and_says_so(self):
        grid = Path(tempfile.mkdtemp())
        register = cipagents.load_register(GRID)
        register["idp"] = {**register["idp"], "mode": "live"}
        (grid / cipagents.AGENTS_FILE).write_text(json.dumps(register))
        sighting = cipagents.sight(grid, cfg=RunConfig(offline=True))
        self.assertFalse(sighting.observed)
        self.assertIn("offline", sighting.error)


    def test_an_expired_token_is_reported_not_read(self):
        """A Graph token pasted into the keychain expires within about an hour.

        Past that, every cycle must say the IdP was not read -- never return an
        empty directory, which would read as every agent having left.
        """
        from vra.idp import MemoryTransport

        grid = Path(tempfile.mkdtemp())
        register = cipagents.load_register(GRID)
        register["idp"] = {**register["idp"], "mode": "live",
                           "token_env": "VRA_TEST_GRAPH_TOKEN"}
        (grid / cipagents.AGENTS_FILE).write_text(json.dumps(register))
        transport = MemoryTransport()
        transport.add("GET", "https://graph.microsoft.com/v1.0/applications?$top=99",
                      {"error": {"code": "InvalidAuthenticationToken"}}, status=401)
        cfg = RunConfig(allow_env_creds=True)
        with mock.patch.dict(os.environ, {"VRA_TEST_GRAPH_TOKEN": "expired"}), \
                mock.patch("vra.creds.get_secret", return_value=None):
            sighting = cipagents.sight(grid, cfg=cfg, transport=transport)
        self.assertFalse(sighting.observed)
        self.assertIn("401", sighting.error)
        self.assertFalse(sighting.complete)


class Command(unittest.TestCase):
    """`vra.py cip vendor-agents` exits non-zero when an agent finding is open."""

    def _run(self, *extra):
        from vra.cipcli import main

        out = StringIO()
        with redirect_stdout(out), \
                mock.patch.object(cipagents, "CIP_AGENTS_FILE",
                                  Path(tempfile.mkdtemp()) / "agents.json"):
            code = main(["vendor-agents", "--grid-dir", str(GRID), "--no-color",
                         "--date", AS_OF.isoformat(), *extra])
        return code, out.getvalue()

    def test_clean_idp_exits_zero(self):
        code, text = self._run("--idp-fixture", str(V1))
        self.assertEqual(code, 0)
        self.assertIn("Sentinel RelayOps Agent", text)

    def test_planted_changes_exit_one_and_are_named(self):
        code, text = self._run("--idp-fixture", str(V2))
        self.assertEqual(code, 1)
        self.assertIn("UNAPPROVED RelaySettings.Write.All", text)
        self.assertIn("NOT DECLARED", text)

    def test_unreadable_idp_is_a_run_error_not_clean(self):
        code, text = self._run("--idp-fixture", "/nonexistent/entra.json")
        self.assertEqual(code, 2)
        self.assertIn("IdP not read", text)


class ModelIsNotOnThisPath(unittest.TestCase):
    def test_following_agents_never_imports_the_model_client(self):
        source = (REPO / "src" / "vra" / "cipagents.py").read_text()
        self.assertNotIn("from .llm", source)
        self.assertNotIn("import llm", source)


if __name__ == "__main__":
    unittest.main()
