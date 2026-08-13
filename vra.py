#!/usr/bin/env python3
"""Entry point.

Legacy usage (unchanged):      python3 vra.py --offline --snapshot v1
Subcommands:
  python3 vra.py run ...        same as legacy, explicit
  python3 vra.py onboard ...    onboard a vendor from a trust center URL
  python3 vra.py webui ...      local onboarding console (browser UI)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vra.cli import main as cli_main  # noqa: E402

SUBCOMMANDS = ("run", "onboard", "webui")


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
        return cli_main(rest)
    # Legacy flag-style invocation: python3 vra.py --offline --snapshot v1
    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
