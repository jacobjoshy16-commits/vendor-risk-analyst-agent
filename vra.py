#!/usr/bin/env python3
"""Entry point.

Legacy usage (unchanged):      python3 vra.py --offline --snapshot v1
Subcommands:
  python3 vra.py run ...        same as legacy, explicit
  python3 vra.py onboard ...    onboard a vendor from a trust center URL
  python3 vra.py bootstrap ...  onboard + propose an initial register from full artifacts
  python3 vra.py webui ...      local onboarding console (browser UI)
  python3 vra.py monitor ...    autonomous daemon — watch vendors + NHIs while the PC is on
  python3 vra.py nhis ...       print the portfolio NHI inventory
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vra.cli import main as cli_main  # noqa: E402

SUBCOMMANDS = ("run", "onboard", "bootstrap", "webui", "monitor", "nhis")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in SUBCOMMANDS:
        cmd, rest = args[0], args[1:]
        if cmd == "onboard":
            from vra.onboard import main as onboard_main

            return onboard_main(rest)
        if cmd == "webui":
            from vra.webui import main as webui_main

            return webui_main(rest)
        if cmd == "monitor":
            from vra.monitor import main as monitor_main

            return monitor_main(rest)
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
