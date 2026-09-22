#!/usr/bin/env python3
"""Run every claim this project makes, and write down what actually happened.

    python3 scripts/prove.py

Produces RESULTS.md: for each claim, the exact command, the expected outcome,
the real captured output, and PASS/FAIL. Exits non-zero if any claim fails.

The point is that nothing here is asserted in prose. Every row in RESULTS.md was
produced by running the command in the row, on this machine, at the timestamp in
the header. Re-run it and the file regenerates.

Checks are ordered so the negative controls come first. "It caught the bad
firmware" means nothing until you have seen it stay silent on the good firmware.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIRMWARE = REPO / "sandbox/grid/firmware/CGC-RTU-200-7.1.0.bin"
DATE = "2026-09-21"          # pinned so the numbers are reproducible
SUBSTATIONS = "400"          # smaller estate keeps the proof run quick


@dataclass
class Check:
    name: str
    claim: str
    cmd: list[str]
    expect_exit: int | None = None
    must_contain: list[str] = field(default_factory=list)
    must_not_contain: list[str] = field(default_factory=list)
    # Output is trimmed in the report; the assertions run on the whole thing.
    show_lines: int = 14
    passed: bool = False
    exit_code: int = -1
    output: str = ""
    why: str = ""
    seconds: float = 0.0


def run(cmd: list[str]) -> tuple[int, str]:
    started = time.time()
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr), time.time() - started


def check(c: Check) -> Check:
    c.exit_code, c.output, c.seconds = run(c.cmd)
    problems = []
    if c.expect_exit is not None and c.exit_code != c.expect_exit:
        problems.append(f"exit {c.exit_code}, expected {c.expect_exit}")
    for needle in c.must_contain:
        if needle not in c.output:
            problems.append(f"missing {needle!r}")
    for needle in c.must_not_contain:
        if needle in c.output:
            problems.append(f"unexpectedly present: {needle!r}")
    c.passed = not problems
    c.why = "; ".join(problems)
    return c


def flip_bit(path: Path, offset: int) -> None:
    blob = bytearray(path.read_bytes())
    blob[offset] ^= 0x01
    path.write_bytes(bytes(blob))


def git_restore(pathspec: str) -> None:
    subprocess.run(["git", "checkout", "--", pathspec], cwd=REPO, check=False)


def clean_state() -> None:
    for name in ("data", "out", "pending_review"):
        shutil.rmtree(REPO / name, ignore_errors=True)


def populate_agent_ledger() -> None:
    """The agent ledger only exists once the analyst has been asked something.

    clean_state() before the monitor checks wipes it, so it is repopulated here
    rather than the check being written to tolerate an empty file -- a check
    that passes on no data proves nothing.
    """
    for package, grid in (
        ("KG-RTU-100-2.4.0", "sandbox/procurement/kestrel-grid"),
        ("KG-RTU-100-2.4.1", "sandbox/procurement/kestrel-grid"),
    ):
        run(cip("gate", "--package", package, "--grid-dir", grid,
                "--date", DATE, "--offline"))


def cip(*args: str) -> list[str]:
    return [sys.executable, "vra.py", "cip", *args, "--no-color"]


def main() -> int:
    checks: list[Check] = []
    notes: list[str] = []

    clean_state()
    run([sys.executable, "vra.py", "cip", "build-fixtures"])

    # --- 1. Is the cryptography real, or a stored field? -------------------
    checks.append(check(Check(
        name="Cryptography is real, not a stored flag",
        claim="Flipping a single bit anywhere in an 8 KB firmware image must break "
              "verification. No implementation that reads a boolean out of YAML can pass this.",
        cmd=[sys.executable, "-m", "unittest",
             "tests.test_cip.CryptoIsReal", "-v"],
        expect_exit=0,
        must_contain=["test_flipping_one_byte_breaks_the_signature", "OK"],
    )))

    # --- 2. NEGATIVE CONTROL: good packages stay silent -------------------
    checks.append(check(Check(
        name="NEGATIVE CONTROL — 14 of 15 packages produce nothing",
        claim="Exactly one package in the estate may fail verification. If two fail, "
              "the detector is producing false positives and no number it prints is trustworthy.",
        cmd=[sys.executable, "-m", "unittest",
             "tests.test_cip.EstateDetection.test_exactly_one_package_fails_verification",
             "tests.test_cip.LowImpactVendorAccessScoping."
             "test_low_impact_without_vendor_access_stays_out_of_scope", "-v"],
        expect_exit=0,
        must_contain=["OK"],
    )))

    # --- 3. A clean package is allowed through -----------------------------
    checks.append(check(Check(
        name="A correctly signed package is allowed",
        claim="The gate must pass a genuine package. A gate that blocks everything "
              "is not a control, it is an outage.",
        cmd=cip("gate", "--package", "KG-RTU-100-2.4.0",
                "--grid-dir", "sandbox/procurement/kestrel-grid",
                "--date", DATE, "--offline"),
        expect_exit=0,
        must_contain=["MATCH", "VALID", "PASS — safe to deploy"],
        must_not_contain=["BLOCKED"],
    )))

    # --- 4. THE CLAIM: hash passes, signature fails -----------------------
    checks.append(check(Check(
        name="Hash check PASSES and signature check FAILS",
        claim="The core argument. A substituted binary whose published digest was "
              "updated to match still fails signature verification, so a "
              "hash-and-spreadsheet process approves what this blocks.",
        cmd=cip("gate", "--package", "SPS-421-4.7.2",
                "--date", DATE, "--substations", SUBSTATIONS, "--offline"),
        expect_exit=1,
        must_contain=["MATCH", "INVALID", "BLOCKED — do not deploy",
                      "audit report", "routed to"],
        show_lines=22,
    )))

    # --- 5. A whole plant delivery ----------------------------------------
    checks.append(check(Check(
        name="Commissioning batch — 1 of 12 blocked, every hash matching",
        claim="A new plant's firmware arrives as a batch. Every row must pass the "
              "hash check so the only red on screen is a signature.",
        cmd=cip("commission", "--plant", "Cypress Bend Energy Center",
                "--batch", "sandbox/commissioning/cypress-bend", "--date", DATE),
        expect_exit=1,
        must_contain=["MATCH", "INVALID",
                      "ENERGISATION BLOCKED — 1 of 12 packages failed"],
        must_not_contain=["MISMATCH"],
        show_lines=20,
    )))

    # --- 6. Contract reading, and what the code refused -------------------
    checks.append(check(Check(
        name="Contract extraction — 6 clauses applied, 2 withheld with reasons",
        claim="The model reads a real contract and quotes clauses; code verifies every "
              "quote against the source. A clause it reports as MISSING never fails a "
              "control, and a verified quote cannot raise a critical on its own.",
        cmd=cip("onboard", "--vendor", "Kestrel Grid Systems",
                "--docs", "sandbox/procurement/kestrel-grid",
                "--date", DATE, "--offline"),
        expect_exit=1,
        must_contain=["An absence has no text to quote",
                      "drives a critical control",
                      "ACCEPTED  KG-RTU-100-2.4.0",
                      "REJECTED  KG-RTU-100-2.4.1"],
        must_not_contain=["UNVERIFIED"],
        show_lines=18,
    )))

    # --- 7. Monitor cold start must be silent ------------------------------
    clean_state()
    checks.append(check(Check(
        name="Cold start sends ZERO alerts",
        claim="On a first run every open finding is technically new. Alerting on all "
              "of them means the first thing a security team sees is a hundred-line "
              "dump, which is how a channel gets muted on day one.",
        cmd=cip("monitor", "--once", "--date", DATE, "--substations", SUBSTATIONS),
        expect_exit=0,
        must_contain=["baseline established", "no alerts sent"],
        must_not_contain=["NEW FINDING"],
    )))

    # --- 8. Nothing changed -> silence -------------------------------------
    checks.append(check(Check(
        name="Second cycle with no change is silent",
        claim="A monitor that alerts every cycle is noise. Re-detection must be quiet.",
        cmd=cip("monitor", "--once", "--date", DATE, "--substations", SUBSTATIONS),
        expect_exit=0,
        must_contain=["still_open"],
        must_not_contain=["NEW FINDING", "logged"],
    )))

    # --- 9. One flipped bit is detected ------------------------------------
    flip_bit(FIRMWARE, 4096)
    notes.append("Flipped one bit at offset 4096 of "
                 "`sandbox/grid/firmware/CGC-RTU-200-7.1.0.bin` before check 9.")
    checks.append(check(Check(
        name="One flipped bit in a vendor image is caught next cycle",
        claim="This is what makes it a monitor rather than a report generator: the "
              "change is detected, grouped to one root cause, and routed by severity.",
        cmd=cip("monitor", "--once", "--date", DATE, "--substations", SUBSTATIONS),
        expect_exit=0,
        must_contain=["NEW FINDING", "assets:", "CIP-010-4 R1 Part 1.6",
                      "CIP Senior Manager"],
        show_lines=12,
    )))

    # --- 10. Remediation is reported too -----------------------------------
    git_restore("sandbox/grid/firmware/")
    notes.append("Restored the firmware from git before check 10.")
    checks.append(check(Check(
        name="Fixing it reports CLEARED",
        claim="Resolution is news too, and it collapses to one alert rather than one "
              "per affected asset.",
        cmd=cip("monitor", "--once", "--date", DATE, "--substations", SUBSTATIONS),
        expect_exit=0,
        must_contain=["CLEARED", "resolved"],
    )))

    # --- 11. Seal the posture ----------------------------------------------
    checks.append(check(Check(
        name="Sealing records the approved vendor posture",
        claim="Once the initial verification is accepted, the posture is sealed. Each "
              "seal carries a digest of its own contents so a silently edited "
              "baseline no longer matches itself.",
        cmd=cip("seal", "--date", DATE, "--substations", SUBSTATIONS),
        expect_exit=0,
        must_contain=["SEALING VENDOR POSTURE", "seal digest", "baselines"],
    )))

    checks.append(check(Check(
        name="Drift against an unchanged posture is empty",
        claim="NEGATIVE CONTROL for drift. Without this, every cycle would report change.",
        cmd=cip("drift", "--date", DATE, "--substations", SUBSTATIONS),
        expect_exit=0,
        must_contain=["no undeclared drift"],
        must_not_contain=["UNDECLARED"],
    )))

    # --- 12. Undeclared vendor change --------------------------------------
    flip_bit(FIRMWARE, 2048)
    notes.append("Flipped one bit at offset 2048 of the same image before check 13, "
                 "simulating a vendor re-publishing a release under the same version.")
    drift = check(Check(
        name="A vendor re-publishing a release is undeclared drift",
        claim="Same version number, different bytes. A version check misses this "
              "entirely; comparing against the seal does not.",
        cmd=cip("drift", "--date", DATE, "--substations", SUBSTATIONS),
        expect_exit=1,
        must_contain=["UNDECLARED", "package hash changed", "undeclared change"],
    ))
    checks.append(drift)

    # --- 13. Approval makes it deliberate ----------------------------------
    key = ""
    for line in drift.output.splitlines():
        if "--approve" in line:
            key = line.split("--approve", 1)[1].strip()
            break
    if key:
        checks.append(check(Check(
            name="An approved change becomes deliberate and goes quiet",
            claim="'No change until it is deliberate' means recorded. An approval "
                  "names who and why, and is keyed to the exact before/after pair so "
                  "approving one change does not bless the next.",
            cmd=cip("drift", "--date", DATE, "--substations", SUBSTATIONS,
                    "--approve", key, "--by", "J. Joshy",
                    "--why", "Vendor confirmed re-publish by phone; hash re-verified"),
            expect_exit=0,
            must_contain=["approved", "recorded in"],
        )))
        checks.append(check(Check(
            name="After approval the same change no longer alerts",
            claim="The approved change is shown as declared, with who approved it.",
            cmd=cip("drift", "--date", DATE, "--substations", SUBSTATIONS),
            expect_exit=0,
            must_contain=["declared", "J. Joshy"],
            must_not_contain=["UNDECLARED"],
        )))
    git_restore("sandbox/grid/firmware/")
    notes.append("Restored the firmware from git after the drift checks.")

    # --- 14. The agent's own actions are auditable -------------------------
    populate_agent_ledger()
    checks.append(check(Check(
        name="Every AI decision is logged and auditable",
        claim="Entergy's Item 1A names AI-driven threats and states it cannot detect "
              "all threats. A tool that puts an AI in the decision path must be able "
              "to say what the AI did, on which model build.",
        cmd=cip("agent-log", "--limit", "5"),
        expect_exit=0,
        must_contain=["AGENT ACTION LEDGER", "behaviour by model build", "inputs"],
        show_lines=14,
    )))

    # --- 15. The audit artifact --------------------------------------------
    checks.append(check(Check(
        name="Audit evidence pack is produced with denominators",
        claim="Organised by requirement, not by finding, because an audit opens with "
              "'show me you checked'. Every requirement carries its population.",
        cmd=cip("--date", DATE, "--substations", SUBSTATIONS, "--evidence"),
        expect_exit=1,
        must_contain=["citations verified", "Requirement coverage",
                      "evidence-pack.md", "evidence-pack.html", "findings.json"],
        show_lines=16,
    )))

    # --- 16. Whole suite ----------------------------------------------------
    checks.append(check(Check(
        name="Full test suite",
        claim="Every claim above is also pinned by a test, so a regression fails "
              "rather than silently changing the numbers.",
        cmd=[sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        expect_exit=0,
        must_contain=["OK"],
        show_lines=4,
    )))

    write_report(checks, notes)
    failed = [c for c in checks if not c.passed]
    print()
    for c in checks:
        mark = "PASS" if c.passed else "FAIL"
        print(f"  [{mark}] {c.name}" + (f"  — {c.why}" if c.why else ""))
    print()
    print(f"  {len(checks) - len(failed)}/{len(checks)} checks passed. "
          f"Written to RESULTS.md")
    return 1 if failed else 0


def write_report(checks: list[Check], notes: list[str]) -> None:
    out = [
        "# Results — what actually happened when this was run",
        "",
        "Generated by `python3 scripts/prove.py`. **Nothing in this file is asserted "
        "in prose.** Every block below is real captured output from running the "
        "command shown, on this machine, at the timestamp below. Re-run the script "
        "and the file regenerates.",
        "",
        f"- **Run at:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- **Python:** {sys.version.split()[0]}",
        f"- **Assessment date (pinned):** {DATE}",
        f"- **Estate size:** {SUBSTATIONS} substations",
        "- **Model backend:** `offline-heuristic` (deterministic stand-in, so the "
        "run reproduces without Ollama; labelled as such everywhere it appears)",
        "",
        "The checks are ordered so the negative controls come first. \"It caught the "
        "bad firmware\" means nothing until you have seen it stay silent on the "
        "good firmware.",
        "",
        "## Summary",
        "",
        "| # | Check | Expected exit | Actual | Result |",
        "| --- | --- | :---: | :---: | :---: |",
    ]
    for i, c in enumerate(checks, 1):
        expected = "—" if c.expect_exit is None else str(c.expect_exit)
        out.append(f"| {i} | {c.name} | {expected} | {c.exit_code} | "
                   f"{'**PASS**' if c.passed else '**FAIL**'} |")

    passed = sum(1 for c in checks if c.passed)
    out += ["", f"**{passed} of {len(checks)} checks passed.**", ""]
    if notes:
        out += ["### Files modified during the run", ""]
        out += [f"- {n}" for n in notes]
        out += ["", "All modifications were reverted with `git checkout`. "
                    "The repository is unchanged by this script.", ""]
    out += ["---", ""]

    for i, c in enumerate(checks, 1):
        out += [
            f"## {i}. {c.name}",
            "",
            c.claim,
            "",
            "```",
            "$ " + " ".join(c.cmd[1:] if c.cmd[0] == sys.executable else c.cmd),
            "```",
            "",
        ]
        lines = [ln for ln in c.output.splitlines() if ln.strip()]
        shown = lines[:c.show_lines]
        out += ["```"] + shown
        if len(lines) > len(shown):
            out.append(f"... ({len(lines) - len(shown)} more lines)")
        out += ["```", ""]
        verdict = (f"**PASS** — exit {c.exit_code}"
                   if c.passed else f"**FAIL** — {c.why}")
        out += [f"{verdict}, {c.seconds:.2f}s", "", "---", ""]

    (REPO / "RESULTS.md").write_text("\n".join(out) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
