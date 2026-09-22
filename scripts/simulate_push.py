#!/usr/bin/env python3
"""Simulate a vendor pushing a firmware update, and prove what happens to it.

    python3 scripts/simulate_push.py

Stands up a fake vendor distribution server on localhost — the kind of portal a
relay vendor publishes releases on — and drives the whole chain against it over
HTTP:

    vendor publishes  ->  tool fetches  ->  cryptography  ->  NERC controls
    ->  decision  ->  audit written back  ->  alert routed

It runs twice. First with a genuine release, which must be accepted. Then after
an attacker compromises the distribution mirror, which must be blocked.

The threat model is the realistic one
-------------------------------------
The attacker controls the artifact mirror. They can replace the binary AND the
SHA-256 published beside it, because both are served from the same host they
own. What they cannot do is forge the vendor's signature, because the signing
key never touches the mirror — a real vendor publishes it through a separate
channel and confirms the fingerprint out of band.

That asymmetry is the entire reason this tool exists, and this script is it
happening over a socket rather than described in a paragraph.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from vra.cipcrypto import derive_demo_keypair, encode_public_key, key_fingerprint  # noqa: E402
from vra.cipcrypto import sha256_bytes, sign_blob  # noqa: E402

PORT = 8799
VENDOR = "Sentinel Protective Systems"
SLUG = "sentinel-protective"
KEY_ID = f"{SLUG}-2026"
PACKAGE = "SPS-680-2.3.0"
MODEL = "SPS-680"
DATE = "2026-09-21"

BOLD, DIM, RED, GREEN, YELLOW, OFF = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"


def c(text: str, colour: str) -> str:
    return f"{colour}{text}{OFF}" if sys.stdout.isatty() else text


def banner(n: int, title: str) -> None:
    print()
    print(c(f"  ── {n}. {title} " + "─" * max(0, 58 - len(title)), BOLD))


# ---------------------------------------------------------------------------
# The vendor's distribution server
# ---------------------------------------------------------------------------
class Mirror:
    """What the vendor serves. `compromise()` is the attacker taking it over."""

    def __init__(self):
        private, public = derive_demo_keypair(f"{SLUG}-signing-2026")
        self.public_key = encode_public_key(public)
        self.fingerprint = key_fingerprint(self.public_key)
        # The genuine build, signed by the vendor before it ever reached a mirror.
        self.genuine = (b"\x7fFWIMG" + f"{VENDOR}\x00{MODEL}\x003.0\x00".encode()
                        + bytes(range(256)) * 32)
        self.signature = sign_blob(private, self.genuine)
        self.binary = self.genuine
        self.published_sha256 = sha256_bytes(self.genuine)
        self.compromised = False

    def compromise(self) -> None:
        """The attacker owns the mirror. They swap the binary and the digest
        beside it. The signature is stale and they cannot make a new one."""
        tampered = bytearray(self.genuine)
        tampered[900:1000] = b"\x90" * 100          # substituted payload
        self.binary = bytes(tampered)
        self.published_sha256 = sha256_bytes(self.binary)   # digest updated to match
        self.compromised = True                              # signature NOT reissued


MIRROR = Mirror()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/releases.json":
            self._json({
                "vendor": VENDOR,
                "releases": [{
                    "package_id": PACKAGE, "model": MODEL, "version": "3.0",
                    "sha256": MIRROR.published_sha256,       # attacker-controllable
                    "signature": MIRROR.signature,            # attacker cannot forge
                    "signing_key_id": KEY_ID,
                    "url": f"/firmware/{PACKAGE}.bin",
                }],
            })
        elif self.path == "/pubkey.json":
            # Separate channel. A real vendor publishes the key somewhere other
            # than the artifact mirror and confirms the fingerprint by phone.
            self._json({"key_id": KEY_ID, "vendor": VENDOR,
                        "public_key": MIRROR.public_key,
                        "fingerprint": MIRROR.fingerprint})
        elif self.path.startswith("/firmware/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(MIRROR.binary)))
            self.end_headers()
            self.wfile.write(MIRROR.binary)
        else:
            self.send_error(404)

    def _json(self, obj):
        raw = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


# ---------------------------------------------------------------------------
# The utility side
# ---------------------------------------------------------------------------
def fetch_release(staging: Path) -> dict:
    """Pull the release the way a patch pipeline would: over HTTP, into staging.

    Nothing here trusts the mirror. The digest and the signature it serves are
    recorded as CLAIMS, to be checked against the bytes and the key.
    """
    import requests

    base = f"http://127.0.0.1:{PORT}"
    manifest = requests.get(f"{base}/releases.json", timeout=10).json()
    release = manifest["releases"][0]
    keydata = requests.get(f"{base}/pubkey.json", timeout=10).json()
    blob = requests.get(f"{base}{release['url']}", timeout=30).content

    firmware = staging / "firmware"
    firmware.mkdir(parents=True, exist_ok=True)
    (firmware / f"{release['package_id']}.bin").write_bytes(blob)

    import yaml

    (staging / "signing-key.yaml").write_text(yaml.safe_dump([{
        "key_id": keydata["key_id"], "vendor": keydata["vendor"],
        "public_key": keydata["public_key"], "status": "active",
        "fingerprint_confirmed_out_of_band": True,
        "note": "Fetched from the vendor's key channel, fingerprint confirmed by phone.",
    }], sort_keys=False), encoding="utf-8")

    (staging / "releases.yaml").write_text(yaml.safe_dump([{
        "package_id": release["package_id"], "vendor": VENDOR, "vendor_slug": SLUG,
        "target_model": release["model"], "version": release["version"],
        "artifact": f"firmware/{release['package_id']}.bin",
        "published_sha256": release["sha256"],
        "signature": release["signature"],
        "signing_key_id": release["signing_key_id"],
    }], sort_keys=False), encoding="utf-8")

    return {"bytes": len(blob), "published_sha256": release["sha256"],
            "fingerprint": keydata["fingerprint"]}


def gate(staging: Path, out: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "vra.py", "cip", "gate", "--package", PACKAGE,
         "--grid-dir", str(staging), "--out", str(out),
         "--date", DATE, "--offline", "--no-color"],
        cwd=REPO, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def show(output: str, keep: tuple[str, ...]) -> None:
    for line in output.splitlines():
        if any(k in line for k in keep):
            print("     " + line.strip())


def run_cycle(label: str, n: int) -> tuple[int, Path]:
    staging = Path(tempfile.mkdtemp()) / "staging"
    out = Path(tempfile.mkdtemp()) / "audit"

    banner(n, f"{label} — utility fetches the release")
    info = fetch_release(staging)
    print(f"     GET /releases.json   → package {PACKAGE}")
    print(f"     GET /pubkey.json     → key {KEY_ID}  fingerprint {info['fingerprint']}")
    print(f"     GET /firmware/…      → {info['bytes']} bytes")
    print(c(f"     mirror claims SHA-256 {info['published_sha256'][:32]}…", DIM))

    banner(n + 1, f"{label} — cryptography, controls, decision")
    code, output = gate(staging, out)
    show(output, ("computed SHA-256", "published SHA-256", "Ed25519 verify",
                  "published hash MATCHES", "disposition", "PASS —", "BLOCKED —",
                  "audit report", "routed to", "alert log"))
    print(f"     {c('exit code ' + str(code), RED if code else GREEN)}")
    return code, out


def main() -> int:
    srv = HTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)

    print()
    print(c("  VENDOR FIRMWARE PUSH — SIMULATED END TO END", BOLD))
    print(c(f"  vendor distribution server on http://127.0.0.1:{PORT}", DIM))
    print(c("  synthetic vendor, synthetic firmware, no real OT network", DIM))

    # ---------------- Round 1: the genuine release ----------------
    code_clean, _ = run_cycle("GENUINE RELEASE", 1)

    # ---------------- The attacker takes the mirror ----------------
    banner(3, "ATTACKER COMPROMISES THE DISTRIBUTION MIRROR")
    before = MIRROR.published_sha256
    MIRROR.compromise()
    print("     binary on the mirror  : REPLACED")
    print(f"     published SHA-256     : {c('UPDATED to match the new binary', YELLOW)}")
    print(f"       {before[:32]}…")
    print(f"       {MIRROR.published_sha256[:32]}…")
    print(f"     vendor signature      : {c('unchanged — cannot be forged', GREEN)}")
    print(c("     The vendor has not been breached. Their mirror has.", DIM))

    # ---------------- Round 2: the substituted release ----------------
    code_bad, out_dir = run_cycle("SUBSTITUTED RELEASE", 4)

    # ---------------- The audit write-back ----------------
    banner(6, "AUDIT RECORD WRITTEN BACK")
    reports = sorted(out_dir.glob("blocked-*.json"))
    if reports:
        record = json.loads(reports[0].read_text())
        print(f"     {reports[0].name}")
        for key in ("disposition", "decided_by", "rule_engine_verdict", "citation"):
            print(f"       {key:22} {record.get(key)}")
        v = record.get("verification", {})
        for key in ("hash_match", "signature_verified", "signing_key_status",
                    "source_identity_verified", "integrity_verified"):
            print(f"       {key:22} {v.get(key)}")
        print(f"       {'analyst disposition':22} "
              f"{record.get('analyst_judgment', {}).get('disposition')}")
    alerts = REPO / "data" / "cip_alerts.jsonl"
    if alerts.is_file():
        last = json.loads(alerts.read_text().strip().splitlines()[-1])
        print()
        print(f"     alert → {last.get('route_to')}")
        print(f"       {last.get('message', '')[:100]}")

    # ---------------- Verdict ----------------
    print()
    print(c("  ── RESULT " + "─" * 58, BOLD))
    ok = code_clean == 0 and code_bad == 1
    print(f"     genuine release      exit {code_clean}  "
          f"{c('ACCEPTED', GREEN) if code_clean == 0 else c('WRONGLY BLOCKED', RED)}")
    print(f"     substituted release  exit {code_bad}  "
          f"{c('BLOCKED', GREEN) if code_bad == 1 else c('WRONGLY ALLOWED', RED)}")
    print()
    if ok:
        print(c("     The mirror controlled the binary and the published hash.", DIM))
        print(c("     It could not control the signature, and that is what caught it.", DIM))
    print()
    srv.shutdown()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
