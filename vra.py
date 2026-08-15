#!/usr/bin/env python3
"""Entry point.

Everyday path:
  python3 vra.py connect
  python3 vra.py monitor
  python3 vra.py report

Flag-based / scripted commands stay available:
  python3 vra.py --offline --snapshot v1
  python3 vra.py creds set okta
  python3 vra.py discover --provider okta --base-url https://org.okta.com
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vra.cli import main as cli_main  # noqa: E402

SUBCOMMANDS = (
    "run",
    "onboard",
    "bootstrap",
    "webui",
    "monitor",
    "discover",
    "nhis",
    "creds",
    "connect",
    "report",
    "enrich",
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in SUBCOMMANDS:
        cmd, rest = args[0], args[1:]
        if cmd == "onboard":
            from vra.onboard import main as onboard_main

            return onboard_main(rest)
        if cmd == "bootstrap":
            from vra.onboard import main as onboard_main

            extra = [] if "--bootstrap" in rest else ["--bootstrap"]
            return onboard_main(rest + extra)
        if cmd == "webui":
            from vra.webui import main as webui_main

            return webui_main(rest)
        if cmd == "monitor":
            from vra.monitor import main as monitor_main

            return monitor_main(rest)
        if cmd == "discover":
            from vra.discover import main as discover_main

            return discover_main(rest)
        if cmd == "creds":
            from vra.creds import main as creds_main

            return creds_main(rest)
        if cmd == "connect":
            from vra.connect import main as connect_main

            return connect_main(rest)
        if cmd == "report":
            from vra.report import report_main

            return report_main(rest)
        if cmd == "enrich":
            from vra.connect import enrich_main

            return enrich_main(rest)
        if cmd == "nhis":
            from vra.monitor import print_inventory

            vendor = None
            if rest and rest[0] in ("--vendor", "-v") and len(rest) > 1:
                vendor = rest[1]
            elif rest and not rest[0].startswith("-"):
                vendor = rest[0]
            return print_inventory(vendor)
        return cli_main(rest)
    # Legacy flag-style invocation: python3 vra.py --offline --snapshot v1
    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
