#!/usr/bin/env python3
"""Exercise the LIVE model path, and write down what the model actually said.

    python3 scripts/prove_live.py            # against your running Ollama
    python3 scripts/prove_live.py --fake     # against a stub, runs anywhere

Why this exists separately from prove.py
----------------------------------------
prove.py runs everything through the offline heuristic, which is deterministic
and therefore provable. That is the right way to test the pipeline, and the
wrong way to test the model. The heuristic finds quotes BY keyword, so its
quotes are topically relevant by construction -- which hid a real bug for weeks.

`--fake` stands up a local HTTP server that speaks Ollama's API and behaves like
a small model having a bad day: prose instead of JSON, code fences, invalid enum
values, and the same genuine sentence offered as evidence for every obligation.
Everything downstream of the socket is the real code -- requests.post, the JSON
parse, the schema check, the retry, the adjudication.

That last behaviour found the bug this harness exists to prevent: a model can
satisfy quote verification by quoting ANY sufficiently long real sentence. The
quote verifies, and the register gains a clause the contract does not contain.
See `quote_is_relevant` and the reuse check in procure.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATE = "2026-09-21"
FAKE_PORT = 11435
FAKE_MODEL = "qwen2.5:7b-instruct"

# A genuine sentence from the sandbox MSA. It is about incident notification
# and nothing else. The stub offers it for EVERY obligation, which is exactly
# the adversarial case: real text, wrong question.
REUSED_QUOTE = (
    "Supplier shall notify Customer's designated security contact of any Security "
    "Incident affecting the products or services provided under this Agreement")

MALFORMED = [
    "Certainly! Here is my assessment of the firmware package.",
    '```json\n{"disposition": "block"}\n```',
    '{"disposition": "probably", "risk": "quite bad", "reasoning": "hmm"}',
]


class _Stub(BaseHTTPRequestHandler):
    calls = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/tags"):
            self._json({"models": [{"name": FAKE_MODEL}]})
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        _Stub.calls += 1
        prompt = req.get("prompt", "")

        # Every other call gets garbage first, so the schema-rejection and
        # retry-with-reason path is what produces the usable answer.
        if _Stub.calls % 2 == 1:
            self._json({"response": MALFORMED[_Stub.calls % len(MALFORMED)]})
            return

        if "OBLIGATION SOUGHT" in prompt:
            body = {"present": True, "quote": REUSED_QUOTE, "confidence": 0.85,
                    "rationale": "found in the master services agreement"}
        else:
            bad = "signature valid ... NO" in prompt or "INVALID" in prompt
            body = {
                "disposition": "block" if bad else "allow",
                "risk": "critical" if bad else "low",
                "reasoning": ("The published hash matches but the signature does not verify "
                              "against the vendor's active key, so source identity under "
                              "CIP-010 R1.6.1 is not established."
                              if bad else
                              "Signature verifies against the vendor's active key."),
                "pattern": "", "recommended_actions": ["Quarantine and re-obtain."],
                "questions_for_vendor": ["Was this release re-signed after build?"],
                "confidence": 0.87,
            }
        self._json({"response": json.dumps(body)})

    def _json(self, obj):
        raw = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def start_stub() -> HTTPServer:
    srv = HTTPServer(("127.0.0.1", FAKE_PORT), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def ollama_reachable(host: str, model: str) -> tuple[bool, str]:
    try:
        import requests

        resp = requests.get(f"{host.rstrip('/')}/api/tags", timeout=5)
        resp.raise_for_status()
        names = {m.get("name", "") for m in resp.json().get("models", [])}
        if not names:
            return False, f"{host} is up but has no models pulled"
        match = any(n == model or n.split(":")[0] == model.split(":")[0] for n in names)
        if not match:
            return False, (f"{host} is up but {model!r} is not pulled. "
                           f"Available: {', '.join(sorted(names)) or 'none'}")
        return True, f"{host} · {model}"
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot reach {host}: {exc}"


def run(cmd: list[str], env: dict) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                          env={**os.environ, **env})
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    fake = "--fake" in sys.argv
    model = os.environ.get("VRA_MODEL", FAKE_MODEL)
    stub = None

    if fake:
        stub = start_stub()
        host = f"http://127.0.0.1:{FAKE_PORT}"
        model = FAKE_MODEL
        time.sleep(0.4)
        label = f"STUB on {host} (adversarial: malformed first replies, one quote reused)"
    else:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        ok, detail = ollama_reachable(host, model)
        if not ok:
            print(f"\n  Ollama not usable: {detail}\n")
            print("  Start it and pull a model:")
            print("      ollama serve &")
            print(f"      ollama pull {model}")
            print("  Or run the stub, which needs nothing:")
            print("      python3 scripts/prove_live.py --fake\n")
            return 2
        label = detail

    env = {"OLLAMA_HOST": host, "VRA_MODEL": model, "VRA_LLM_CACHE": "0"}
    sections = []

    def step(title, note, cmd, expect_exit=None):
        code, out = run(cmd, env)
        ok = expect_exit is None or code == expect_exit
        sections.append((title, note, cmd, code, expect_exit, out, ok))
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {title}  (exit {code})")
        return out

    print(f"\n  Live model path — {label}\n")

    cip = [sys.executable, "vra.py", "cip"]

    step("Gate a substituted package, model in the loop",
         "The model receives the crypto result, the failed controls, the blast radius "
         "and the vendor's history, and reaches its own disposition. Backend must read "
         "`ollama`, not `offline-heuristic`.",
         cip + ["gate", "--package", "SPS-421-4.7.2", "--date", DATE,
                "--substations", "200", "--no-color"], expect_exit=1)

    step("Gate a clean package",
         "NEGATIVE CONTROL for the live path. The model must not invent doubt about a "
         "package that verifies.",
         cip + ["gate", "--package", "KG-RTU-100-2.4.0", "--grid-dir",
                "sandbox/procurement/kestrel-grid", "--date", DATE, "--no-color"],
         expect_exit=0)

    step("Model decides alone",
         "--decision model removes the rule engine from the decision entirely, so what "
         "you see is the model's call.",
         cip + ["gate", "--package", "SPS-421-4.7.2", "--date", DATE, "--substations",
                "200", "--decision", "model", "--no-color"], expect_exit=1)

    onboard = step("Read a contract with the live model",
                   "The model locates CIP-013 clauses and quotes them; code verifies each "
                   "quote exists in the source, is about the obligation it was offered "
                   "for, and was not reused across obligations.",
                   cip + ["onboard", "--vendor", "Kestrel Grid Systems", "--docs",
                          "sandbox/procurement/kestrel-grid", "--date", DATE, "--no-color"])

    step("What the agent did, on the record",
         "Every invocation is logged with the model build, so the ledger must now show "
         "the live backend rather than the heuristic.",
         cip + ["agent-log", "--limit", "6", "--no-color"], expect_exit=0)

    if fake and "more than one obligation" not in onboard:
        print("\n  WARNING: the stub reused one quote for every obligation and the tool "
              "did not withhold them. The relevance/reuse check has regressed.\n")

    write_report(sections, label, model, host, fake)
    failed = [s for s in sections if not s[6]]
    print(f"\n  {len(sections) - len(failed)}/{len(sections)} steps passed. "
          f"Written to LIVE-RESULTS.md\n")
    if stub:
        stub.shutdown()
    return 1 if failed else 0


def write_report(sections, label, model, host, fake):
    out = [
        "# Live model results — what the model actually said",
        "",
        "Generated by `python3 scripts/prove_live.py"
        f"{' --fake' if fake else ''}`. Every block is real captured output.",
        "",
        f"- **Run at:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- **Backend:** {label}",
        f"- **Model:** `{model}`  ·  **Host:** `{host}`",
        f"- **Prompt cache:** disabled for this run, so every answer came from the model",
        "",
    ]
    if fake:
        out += [
            "> **This run used the stub, not a real model.** The stub speaks Ollama's HTTP "
            "API and behaves like a small model having a bad day: prose instead of JSON, "
            "code fences, invalid enum values, and one genuine sentence offered as "
            "evidence for every obligation. Everything downstream of the socket is the "
            "real code path.",
            "",
            "> That last behaviour is how the quote-relevance bug was found: a model can "
            "satisfy quote verification by quoting any sufficiently long real sentence, "
            "and the register then gains a clause the contract does not contain.",
            "",
        ]
    out += ["---", ""]

    for i, (title, note, cmd, code, expect, output, ok) in enumerate(sections, 1):
        out += [f"## {i}. {title}", "", note, "",
                "```", "$ " + " ".join(c for c in cmd if c != sys.executable), "```", ""]
        lines = [ln for ln in output.splitlines() if ln.strip()][:22]
        out += ["```"] + lines + ["```", ""]
        verdict = "**PASS**" if ok else f"**FAIL** — expected exit {expect}"
        out += [f"{verdict} (exit {code})", "", "---", ""]

    (REPO / "LIVE-RESULTS.md").write_text("\n".join(out) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
