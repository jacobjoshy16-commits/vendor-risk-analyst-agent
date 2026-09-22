#!/usr/bin/env python3
"""The whole lifecycle, one stage at a time, with the command shown each step.

    python3 scripts/walkthrough.py            # run straight through
    python3 scripts/walkthrough.py --pause    # stop between stages (for a demo)
    python3 scripts/walkthrough.py --live     # use Ollama instead of the stand-in

Six stages, in the order they actually happen:

    1  ONBOARD     read the vendor's contracts, extract the CIP-013 obligations
    2  CRYPTO      SHA-256 then Ed25519 over the bytes they shipped
    3  CONTROLS    which NERC requirements applied, and how they scored
    4  MODEL       the local model reasons over all of it and decides
    5  MEMORY      seal the state, let time pass, detect what moved
    6  OUTPUT      audit evidence, the finding record, the routed alert

Every command printed is a real one you can run on its own. This script only
sequences them and points at what to look at.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATE = "2026-09-21"
SUBS = "300"
VENDOR_DOCS = "sandbox/procurement/kestrel-grid"
TAMPERED = "KG-RTU-100-2.4.1"
CLEAN = "KG-RTU-100-2.4.0"

TTY = sys.stdout.isatty()
B, D, R, G, Y, C, OFF = ("\033[1m", "\033[2m", "\033[31m", "\033[32m",
                         "\033[33m", "\033[36m", "\033[0m")


def col(text, code):
    return f"{code}{text}{OFF}" if TTY else text


def stage(n, title, why):
    print()
    print(col("═" * 74, D))
    print(col(f"  STAGE {n}  ·  {title}", B))
    print(col(f"  {why}", D))
    print(col("═" * 74, D))


def shell(cmd, keep=None, limit=None):
    """Print the command, run it, show the lines worth looking at."""
    printable = " ".join(x for x in cmd if x != sys.executable)
    print()
    print(col(f"  $ {printable}", C))
    print()
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    lines = [l for l in out.splitlines() if l.strip()]
    if keep:
        lines = [l for l in lines if any(k in l for k in keep)]
    if limit:
        lines = lines[:limit]
    for line in lines:
        print("    " + line.rstrip())
    return proc.returncode, out


def notice(*points):
    print()
    for p in points:
        print(col(f"  → {p}", Y))


def pause(enabled):
    if enabled:
        try:
            input(col("\n  [enter] to continue ", D))
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)


def main() -> int:
    paused = "--pause" in sys.argv
    live = "--live" in sys.argv
    offline = [] if live else ["--offline"]
    cip = [sys.executable, "vra.py", "cip"]

    # Clean slate so the memory stage has a real before/after.
    for name in ("data", "out"):
        shutil.rmtree(REPO / name, ignore_errors=True)
    subprocess.run(cip + ["build-fixtures"], cwd=REPO, capture_output=True)

    print()
    print(col("  VENDOR RISK LIFECYCLE — END TO END", B))
    print(col("  Kestrel Grid Systems, a supplier being onboarded.", D))
    print(col("  Synthetic vendor, synthetic firmware, no real OT network.", D))
    print(col(f"  Model backend: {'Ollama (live)' if live else 'offline stand-in'}", D))

    # ---------------------------------------------------------------- 1
    stage(1, "ONBOARD THE VENDOR",
          "Read their actual contract documents and find the CIP-013 obligations.")
    print()
    print("  What the vendor gave us:")
    for f in sorted(Path(REPO / VENDOR_DOCS).glob("*.txt")):
        print(f"    {f.name}  ({len(f.read_text().split())} words)")

    shell(cip + ["onboard", "--vendor", "Kestrel Grid Systems", "--docs", VENDOR_DOCS,
                 "--date", DATE, "--no-color"] + offline,
          keep=["CIP-013 R1", "obligation", "#  CIP"], limit=11)
    notice("The model FOUND each clause and quoted it word for word.",
           "Code then checked that quote is really in the document, is about that "
           "obligation, and was not reused for another one.",
           "'held' means the code refused to apply it — see the next block.")
    pause(paused)

    shell(cip + ["onboard", "--vendor", "Kestrel Grid Systems", "--docs", VENDOR_DOCS,
                 "--date", DATE, "--no-color"] + offline,
          keep=["refused", "R1.2.3", "R1.2.5", "absence", "critical control"], limit=8)
    notice("R1.2.3 is genuinely missing from the contract. A model cannot quote "
           "something that is not there, so it becomes a question for the vendor — "
           "never a failed control.",
           "R1.2.5 was quoted correctly, but it drives a CRITICAL, so it waits for a "
           "human rather than being decided by a model.")
    pause(paused)

    # ---------------------------------------------------------------- 2
    stage(2, "CRYPTOGRAPHY",
          "The vendor ships two firmware releases. Check the bytes they actually sent.")
    shell(cip + ["gate", "--package", CLEAN, "--grid-dir", VENDOR_DOCS,
                 "--date", DATE, "--no-color"] + offline,
          keep=["computed SHA-256", "published SHA-256", "Ed25519", "PASS —"])
    notice("Genuine release: hash matches AND signature verifies. Exit 0.")
    pause(paused)

    code, _ = shell(cip + ["gate", "--package", TAMPERED, "--grid-dir", VENDOR_DOCS,
                           "--date", DATE, "--no-color"] + offline,
                    keep=["computed SHA-256", "published SHA-256", "Ed25519",
                          "published hash MATCHES", "BLOCKED"])
    notice("Substituted release: the hash MATCHES and the signature does NOT.",
           "A hash proves the bytes match a published string. It does not prove the "
           "string came from the vendor — whoever swapped the binary swapped the hash "
           "beside it.",
           f"Exit code {code}. In a patch pipeline this firmware never gets flashed.")
    pause(paused)

    # ---------------------------------------------------------------- 3
    stage(3, "NERC CONTROLS",
          "Which requirements applied, to how many assets, and how they scored.")
    shell(cip + ["--date", DATE, "--substations", SUBS, "--no-color"],
          keep=["substations at high/medium", "low impact assets allow",
                "CIP-01 ", "CIP-02 ", "CIP-12 ", "CIP-31 ", "citations verified"],
          limit=10)
    notice("Every row has a denominator: population, applicable, passed, failed.",
           "CIP-002 impact ratings decide what even applies. Low-impact assets with no "
           "vendor access are NOT APPLICABLE — never 'passing'.",
           "22 of 34 citations are verified against the standard text; the rest are "
           "flagged and the tool says so.")
    pause(paused)

    # ---------------------------------------------------------------- 4
    stage(4, "THE LOCAL MODEL",
          "It receives everything the code found, and reaches its own decision.")
    shell(cip + ["gate", "--package", TAMPERED, "--grid-dir", VENDOR_DOCS,
                 "--date", DATE, "--decision", "model", "--no-color"] + offline,
          keep=["ANALYST", "disposition", "→ ", "? ", "DECISION"], limit=10)
    notice("--decision model removes the rule engine entirely. That verdict is the "
           "model's.",
           "It was given the crypto result, the failed controls, how many devices run "
           "this build, and what this vendor has done before.",
           "It can also BLOCK something the rules would have passed — that is the "
           "direction that matters.")
    pause(paused)

    # ---------------------------------------------------------------- 5
    stage(5, "MEMORY — what changed since last time",
          "Seal the approved state, let a cycle pass, then move something.")

    shell(cip + ["seal", "--date", DATE, "--substations", SUBS, "--no-color"],
          keep=["sealed", "seal digest"], limit=4)
    shell(cip + ["monitor", "--once", "--date", DATE, "--substations", SUBS,
                 "--no-color"], keep=["baseline established", "no alerts"], limit=3)
    notice("First run records what is already open and sends NOTHING. A monitor that "
           "pages you 115 times on day one gets muted on day two.")
    pause(paused)

    target = REPO / "sandbox/grid/firmware/CGC-RTU-200-7.1.0.bin"
    blob = bytearray(target.read_bytes())
    blob[4096] ^= 0x01
    target.write_bytes(bytes(blob))
    print()
    print(col("  [simulating a vendor quietly re-publishing a release]", Y))
    print(col("  flipped one bit in CGC-RTU-200-7.1.0.bin", D))

    shell(cip + ["monitor", "--once", "--date", DATE, "--substations", SUBS,
                 "--no-color"], keep=["NEW FINDING", "assets:", "CIP Senior"], limit=6)
    shell(cip + ["drift", "--date", DATE, "--substations", SUBS, "--no-color"],
          keep=["UNDECLARED", "undeclared change"], limit=4)
    notice("One bit, caught on the next cycle, grouped to ONE alert naming all the "
           "affected assets rather than one alert each.",
           "Drift is separate: the vendor's sealed posture moved and nobody declared "
           "it. Same version number, different bytes.")
    pause(paused)

    subprocess.run(["git", "checkout", "--", "sandbox/grid/firmware/"],
                   cwd=REPO, capture_output=True)
    shell(cip + ["monitor", "--once", "--date", DATE, "--substations", SUBS,
                 "--no-color"], keep=["CLEARED", "resolved"], limit=3)
    notice("Fixed, and the resolution is reported too. Due dates count from when a "
           "problem FIRST appeared, so re-detecting it does not reset the clock.")
    pause(paused)

    # ---------------------------------------------------------------- 6
    stage(6, "OUTPUT",
          "The audit evidence, the agent's record, and who got told.")
    shell(cip + ["--date", DATE, "--substations", SUBS, "--evidence", "--no-color"],
          keep=["markdown", "html", "json", "findings"], limit=5)

    shell(cip + ["agent-log", "--limit", "3", "--no-color"],
          keep=["behaviour by model", "BLOCK", "ALLOW", "inputs"], limit=8)
    notice("Every model call is logged with the model build, so you can see whether "
           "the agent's behaviour changed over time.")

    alerts = REPO / "data" / "cip_alerts.jsonl"
    if alerts.is_file():
        rows = [json.loads(l) for l in alerts.read_text().strip().splitlines() if l.strip()]
        # Show the most recent alert that actually stopped something, not the
        # clean-up notice that happens to be last in the file.
        blocking = [r for r in rows if r.get("kind") != "resolved"]
        last = (blocking or rows)[-1]
        print()
        print(col("  The alert a security team receives:", B))
        print(f"    severity   {last.get('severity')}")
        print(f"    routed to  {last.get('route_to')}")
        print(f"    citation   {last.get('citation')}")
        print(f"    {last.get('message', '')[:120]}")

    print()
    print(col("═" * 74, D))
    print(col("  THE WHOLE CHAIN", B))
    print("""
    contracts read      →  obligations extracted, quotes verified in code
    firmware verified   →  SHA-256 matched, signature did not
    controls scored     →  CIP-010 R1.6 failed, with a denominator
    model reasoned      →  block, with its reasoning recorded
    memory compared     →  one bit caught next cycle; drift undeclared
    output written      →  audit pack, finding record, routed alert
""")
    print(col("  Run any stage on its own — every command above is a real one.", D))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
