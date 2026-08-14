"""Autonomous monitor — keep watching every vendor while the machine is on.

This is the unattended loop the README roadmap called ``scheduled unattended
runs``. One process:

    watch → assess → persist → sleep → repeat

It does not invent a second pipeline. Each cycle is a normal ``assess()``
against the current register, so findings, NHI inventory, and reports stay
the source of truth. The daemon's job is to *keep doing that* for as long
as the workstation is up.

    python3 vra.py monitor --offline --webui
    python3 vra.py monitor --interval 15m
    python3 vra.py monitor --once
    python3 vra.py monitor status
    python3 vra.py monitor stop
    python3 vra.py monitor install

A file lock prevents two daemons. A stop file (or SIGINT/SIGTERM) ends the
loop between cycles. Status is published to ``data/monitor.json`` so the
local console can show a live heartbeat without talking to the process.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import (
    DATA_DIR,
    DEFAULT_MONITOR_INTERVAL,
    MONITOR_LOCK_FILE,
    MONITOR_LOG_FILE,
    MONITOR_STATUS_FILE,
    MONITOR_STOP_FILE,
    REPO_ROOT,
    RunConfig,
)

HISTORY_KEEP = 20


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None = None) -> str:
    return (dt or _utc_now()).isoformat()


def parse_interval(value: str | int) -> int:
    """Accept ``900``, ``90s``, ``15m``, ``1h``."""
    if isinstance(value, int):
        if value < 1:
            raise ValueError("interval must be >= 1 second")
        return value
    raw = str(value).strip().lower()
    if not raw:
        raise ValueError("interval is empty")
    multiplier = 1
    if raw[-1] in "smh":
        multiplier = {"s": 1, "m": 60, "h": 3600}[raw[-1]]
        raw = raw[:-1]
    try:
        n = int(raw)
    except ValueError as exc:
        raise ValueError(f"invalid interval {value!r}") from exc
    if n < 1:
        raise ValueError("interval must be >= 1 second")
    return n * multiplier


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


# ---------------------------------------------------------------------------
# Lock / stop / status
# ---------------------------------------------------------------------------
class MonitorLock:
    """PID file. Stale locks (dead PID) are stolen; live ones are respected."""

    def __init__(self, path: Path = MONITOR_LOCK_FILE):
        self.path = path
        self.held = False

    def living_pid(self) -> int | None:
        if not self.path.exists():
            return None
        try:
            pid = int(self.path.read_text(encoding="utf-8").strip() or "0")
        except ValueError:
            return None
        return pid if pid_alive(pid) else None

    def acquire(self) -> bool:
        living = self.living_pid()
        if living is not None and living != os.getpid():
            return False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(str(os.getpid()), encoding="utf-8")
        self.held = True
        return True

    def release(self) -> None:
        if not self.held:
            return
        try:
            if self.path.exists() and self.path.read_text(encoding="utf-8").strip() == str(os.getpid()):
                self.path.unlink()
        except OSError:
            pass
        self.held = False


def request_stop(path: Path = MONITOR_STOP_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_iso(), encoding="utf-8")


def clear_stop(path: Path = MONITOR_STOP_FILE) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def stop_requested(path: Path = MONITOR_STOP_FILE) -> bool:
    return path.exists()


class MonitorStatus:
    """``data/monitor.json`` — the console's view of the daemon."""

    def __init__(self, path: Path = MONITOR_STATUS_FILE):
        self.path = path
        self.data: dict[str, Any] = {
            "status": "stopped",
            "pid": None,
            "started_at": None,
            "last_heartbeat": None,
            "interval_seconds": DEFAULT_MONITOR_INTERVAL,
            "offline": True,
            "webui": False,
            "cycles_completed": 0,
            "next_cycle_at": None,
            "last_cycle": None,
            "history": [],
            "error": None,
        }

    def load(self) -> dict[str, Any]:
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return self.data

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.data, indent=2, default=str)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(self.path)

    def heartbeat(self) -> None:
        self.data["last_heartbeat"] = _iso()
        if self.data.get("status") == "running":
            # A process that can still write is alive; don't flap the status.
            self.data["pid"] = os.getpid()
        self.write()

    def mark_running(self, *, interval: int, offline: bool, webui: bool) -> None:
        self.data.update(
            {
                "status": "running",
                "pid": os.getpid(),
                "started_at": self.data.get("started_at") or _iso(),
                "last_heartbeat": _iso(),
                "interval_seconds": interval,
                "offline": offline,
                "webui": webui,
                "error": None,
            }
        )
        self.write()

    def mark_stopped(self, reason: str | None = None) -> None:
        self.data["status"] = "stopped"
        self.data["pid"] = None
        self.data["next_cycle_at"] = None
        self.data["last_heartbeat"] = _iso()
        if reason:
            self.data["error"] = reason
        self.write()

    def record_cycle(self, payload: dict[str, Any]) -> None:
        self.data["last_cycle"] = payload
        self.data["cycles_completed"] = int(self.data.get("cycles_completed") or 0) + 1
        self.data["last_heartbeat"] = _iso()
        history = list(self.data.get("history") or [])
        history.append(payload)
        self.data["history"] = history[-HISTORY_KEEP:]
        self.data["error"] = payload.get("error")
        self.write()


def read_status(path: Path = MONITOR_STATUS_FILE) -> dict[str, Any]:
    status = MonitorStatus(path)
    blob = status.load()
    # If the file says running but the PID is dead, say so.
    pid = blob.get("pid")
    if blob.get("status") == "running" and (not pid or not pid_alive(int(pid))):
        blob["status"] = "stale"
        blob["error"] = f"monitor pid {pid} is not running"
    return blob


# ---------------------------------------------------------------------------
# Cycle
# ---------------------------------------------------------------------------
def _result_payload(result, started: datetime, finished: datetime) -> dict[str, Any]:
    body = asdict(result) if is_dataclass(result) else dict(result)
    body.update(
        {
            "started_at": _iso(started),
            "finished_at": _iso(finished),
            "duration_seconds": round((finished - started).total_seconds(), 3),
        }
    )
    return body


def run_cycle(cfg: RunConfig, status: MonitorStatus | None = None) -> dict[str, Any]:
    """One assess() pass. Never raises — errors go into the payload."""
    from .cli import assess

    started = _utc_now()
    try:
        result = assess(cfg)
        payload = _result_payload(result, started, _utc_now())
    except Exception as exc:  # the daemon must survive a bad cycle
        payload = {
            "exit_code": 2,
            "error": f"{type(exc).__name__}: {exc}",
            "started_at": _iso(started),
            "finished_at": _iso(),
            "duration_seconds": round((_utc_now() - started).total_seconds(), 3),
        }
    if status is not None:
        status.record_cycle(payload)
    _append_log(payload)
    return payload


def _append_log(payload: dict[str, Any], path: Path = MONITOR_LOG_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (
        f"{payload.get('finished_at', _iso())}  "
        f"vendors={payload.get('vendor_count', '?')}  "
        f"nhis={payload.get('nhi_count', '?')}  "
        f"changed={payload.get('changed_sources', '?')}  "
        f"critical={payload.get('critical', '?')}  "
        f"new={payload.get('new_findings', '?')}  "
        f"exit={payload.get('exit_code', '?')}"
    )
    if payload.get("error"):
        line += f"  error={payload['error']}"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def interruptible_sleep(seconds: int, stop: threading.Event, *, tick: float = 0.5) -> bool:
    """Sleep ``seconds``. Return False if a stop was requested."""
    deadline = time.monotonic() + max(0, seconds)
    while time.monotonic() < deadline:
        if stop.is_set() or stop_requested():
            return False
        time.sleep(min(tick, max(0.0, deadline - time.monotonic())))
    return not (stop.is_set() or stop_requested())


# ---------------------------------------------------------------------------
# Daemon loop
# ---------------------------------------------------------------------------
def run_forever(
    cfg: RunConfig,
    *,
    interval: int,
    with_webui: bool = False,
    status_path: Path = MONITOR_STATUS_FILE,
    lock_path: Path = MONITOR_LOCK_FILE,
    stop: threading.Event | None = None,
) -> int:
    lock = MonitorLock(lock_path)
    if not lock.acquire():
        living = lock.living_pid()
        print(f"vra monitor: already running (pid {living})", file=sys.stderr)
        return 2

    stop = stop or threading.Event()
    status = MonitorStatus(status_path)
    status.load()
    # A new daemon starts its own cycle count from whatever was persisted
    # so the console can show lifetime cycles across restarts.
    status.mark_running(interval=interval, offline=cfg.offline, webui=with_webui)
    clear_stop()

    def _ask_stop(*_args: Any) -> None:
        stop.set()
        request_stop()

    previous_int = signal.getsignal(signal.SIGINT)
    previous_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _ask_stop)
    signal.signal(signal.SIGTERM, _ask_stop)

    webui_server = None
    if with_webui:
        try:
            from .webui import start_server

            webui_server = start_server(cfg.webui_host, cfg.webui_port, background=True)
            print(f"vra monitor: console on http://{cfg.webui_host}:{cfg.webui_port}")
        except OSError as exc:
            print(f"vra monitor: webui did not start ({exc}); continuing headless", file=sys.stderr)

    heartbeat_stop = threading.Event()

    def _beat() -> None:
        while not heartbeat_stop.is_set():
            try:
                status.heartbeat()
            except Exception:
                pass
            heartbeat_stop.wait(10)

    beater = threading.Thread(target=_beat, name="vra-heartbeat", daemon=True)
    beater.start()

    print(
        f"vra monitor: watching {interval}s interval, "
        f"{'offline' if cfg.offline else 'online'}, pid {os.getpid()}  (Ctrl-C to stop)",
        flush=True,
    )
    code = 0
    try:
        while not stop.is_set() and not stop_requested():
            status.data["status"] = "running"
            status.data["next_cycle_at"] = None
            status.heartbeat()
            payload = run_cycle(cfg, status)
            crit = payload.get("critical") or 0
            changed = payload.get("changed_sources") or 0
            print(
                f"vra monitor: cycle {status.data.get('cycles_completed')}  "
                f"vendors={payload.get('vendor_count', 0)}  "
                f"nhis={payload.get('nhi_count', 0)}  "
                f"changed={changed}  critical={crit}  "
                f"exit={payload.get('exit_code')}"
            )
            if cfg.monitor_once:
                code = 0 if payload.get("exit_code") in (0, 1) else int(payload.get("exit_code") or 2)
                break
            next_at = _utc_now() + timedelta(seconds=interval)
            status.data["next_cycle_at"] = _iso(next_at)
            status.write()
            if not interruptible_sleep(interval, stop):
                break
    except Exception as exc:  # last-resort; mark status so the UI isn't stuck
        status.mark_stopped(f"{type(exc).__name__}: {exc}")
        print(f"vra monitor: fatal: {exc}", file=sys.stderr)
        code = 2
    finally:
        heartbeat_stop.set()
        if webui_server is not None:
            try:
                webui_server.shutdown()
            except Exception:
                pass
        if status.data.get("status") != "stopped" or code != 2:
            status.mark_stopped()
        clear_stop()
        lock.release()
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)
        print("vra monitor: stopped")
    return code


# ---------------------------------------------------------------------------
# Detached start / stop (used by the web console)
# ---------------------------------------------------------------------------
def spawn_monitor(
    *,
    offline: bool = True,
    interval: int = DEFAULT_MONITOR_INTERVAL,
    snapshot: str = "v1",
    extra_args: list[str] | None = None,
) -> int:
    """Start a detached monitor process. Returns the new PID."""
    lock = MonitorLock()
    living = lock.living_pid()
    if living is not None:
        return living
    cmd = [
        sys.executable,
        str(REPO_ROOT / "vra.py"),
        "monitor",
        "--interval",
        str(interval),
        "--snapshot",
        snapshot,
    ]
    if offline:
        cmd.append("--offline")
    if extra_args:
        cmd.extend(extra_args)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log = MONITOR_LOG_FILE.open("a", encoding="utf-8")
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )
    return proc.pid


def stop_monitor() -> bool:
    """Ask the running daemon to exit. Returns True if a stop was signalled."""
    request_stop()
    lock = MonitorLock()
    pid = lock.living_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return False
    return True


# ---------------------------------------------------------------------------
# Autostart install
# ---------------------------------------------------------------------------
def install_autostart(
    *,
    interval: int = DEFAULT_MONITOR_INTERVAL,
    offline: bool = True,
    webui: bool = True,
) -> list[Path]:
    """Write a systemd user unit and an XDG autostart entry. Does not enable them."""
    python = sys.executable
    entry = str(REPO_ROOT / "vra.py")
    args = [python, entry, "monitor", "--interval", str(interval)]
    if offline:
        args.append("--offline")
    if webui:
        args.append("--webui")
    exec_line = " ".join(args)
    written: list[Path] = []

    systemd_dir = Path.home() / ".config/systemd/user"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    unit = systemd_dir / "vra-monitor.service"
    unit.write_text(
        "[Unit]\n"
        "Description=Vendor AI Risk Analyst — continuous NHI / vendor monitor\n"
        "After=default.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={REPO_ROOT}\n"
        f"ExecStart={exec_line}\n"
        "Restart=on-failure\n"
        "RestartSec=15\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n",
        encoding="utf-8",
    )
    written.append(unit)

    auto_dir = Path.home() / ".config/autostart"
    auto_dir.mkdir(parents=True, exist_ok=True)
    desktop = auto_dir / "vra-monitor.desktop"
    desktop.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Vendor AI Risk Analyst monitor\n"
        "Comment=Watch vendor AI surfaces and NHIs while this session is running\n"
        f"Exec={exec_line}\n"
        "X-GNOME-Autostart-enabled=true\n"
        "Terminal=false\n",
        encoding="utf-8",
    )
    written.append(desktop)

    launch_dir = Path.home() / "Library/LaunchAgents"
    # Only write launchd if we're on macOS or the directory already exists.
    if sys.platform == "darwin" or launch_dir.exists():
        launch_dir.mkdir(parents=True, exist_ok=True)
        plist = launch_dir / "ai.vra.monitor.plist"
        args_xml = "\n".join(f"    <string>{a}</string>" for a in args)
        plist.write_text(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\"><dict>\n"
            "  <key>Label</key><string>ai.vra.monitor</string>\n"
            "  <key>WorkingDirectory</key>"
            f"<string>{REPO_ROOT}</string>\n"
            "  <key>ProgramArguments</key><array>\n"
            f"{args_xml}\n"
            "  </array>\n"
            "  <key>RunAtLoad</key><true/>\n"
            "  <key>KeepAlive</key><true/>\n"
            "</dict></plist>\n",
            encoding="utf-8",
        )
        written.append(plist)
    return written


# ---------------------------------------------------------------------------
# NHI listing (``vra.py nhis``)
# ---------------------------------------------------------------------------
def print_inventory(vendor: str | None = None) -> int:
    from .nhi import NHIInventory

    inv = NHIInventory()
    rows = inv.for_vendor(vendor) if vendor else inv.all()
    if not rows:
        print("No NHIs inventoried yet. Run `python3 vra.py discover` against the IdP, or `monitor --once`.")
        return 0
    print(f"{'Vendor':<24} {'Identity':<28} {'Kind':<18} {'Write scopes':<28} {'Owner':<22} Source")
    print("-" * 140)
    for r in rows:
        writes = ", ".join(r.get("write_scopes") or []) or "none"
        print(
            f"{(r.get('vendor') or ''):<24} "
            f"{(r.get('name') or r.get('principal') or ''):<28} "
            f"{(r.get('kind') or ''):<18} "
            f"{writes[:28]:<28} "
            f"{(r.get('owner') or 'unknown'):<22} "
            f"{r.get('source') or ''}"
        )
    print(f"\n{len(rows)} identit{'y' if len(rows) == 1 else 'ies'}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra monitor",
        description="Run the analyst continuously while this machine is on.",
    )
    p.add_argument(
        "action",
        nargs="?",
        default="run",
        choices=("run", "status", "stop", "install"),
        help="run (default), status, stop, or install login-autostart units",
    )
    p.add_argument("--interval", default=str(DEFAULT_MONITOR_INTERVAL),
                   help="cycle interval: seconds, or 90s / 15m / 1h. Default: 900 (15m)")
    p.add_argument("--snapshot", default="v1", dest="snapshot_version",
                   help="sandbox snapshot set ({version} in watch paths). Default: v1")
    p.add_argument("--vendor", action="append", default=[], dest="vendors",
                   help="limit to a vendor slug (repeatable)")
    p.add_argument("--offline", action="store_true",
                   help="no network; deterministic heuristic backend")
    p.add_argument("--once", action="store_true",
                   help="run a single cycle and exit (for cron, or tests)")
    p.add_argument("--webui", action="store_true",
                   help="also serve the local console so you can watch the daemon")
    p.add_argument("--host", default=None, help="webui bind address")
    p.add_argument("--port", type=int, default=None, help="webui bind port")
    p.add_argument("--no-probe", action="store_true", help="skip in-tenant probes")
    p.add_argument("--model", default=None, help="Ollama model tag")
    return p


def _print_status() -> int:
    blob = read_status()
    print(f"  status     : {blob.get('status')}")
    print(f"  pid        : {blob.get('pid') or '—'}")
    print(f"  started    : {blob.get('started_at') or '—'}")
    print(f"  heartbeat  : {blob.get('last_heartbeat') or '—'}")
    print(f"  interval   : {blob.get('interval_seconds')}s")
    print(f"  cycles     : {blob.get('cycles_completed')}")
    print(f"  next cycle : {blob.get('next_cycle_at') or '—'}")
    last = blob.get("last_cycle") or {}
    if last:
        print(
            f"  last cycle : vendors={last.get('vendor_count')}  "
            f"nhis={last.get('nhi_count')}  "
            f"changed={last.get('changed_sources')}  "
            f"critical={last.get('critical')}  "
            f"exit={last.get('exit_code')}"
        )
    if blob.get("error"):
        print(f"  error      : {blob['error']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "status":
        return _print_status()
    if args.action == "stop":
        if stop_monitor():
            print("vra monitor: stop signalled")
            return 0
        print("vra monitor: not running")
        return 0
    try:
        interval = parse_interval(args.interval)
    except ValueError as exc:
        print(f"vra monitor: {exc}", file=sys.stderr)
        return 2
    if args.action == "install":
        paths = install_autostart(interval=interval, offline=args.offline, webui=args.webui)
        print("vra monitor: wrote autostart units (not enabled):")
        for p in paths:
            print(f"  {p}")
        print()
        print("  Linux (systemd user):  systemctl --user enable --now vra-monitor.service")
        print("  Linux (session):       the .desktop file starts the monitor at graphical login")
        print("  macOS:                 launchctl load ~/Library/LaunchAgents/ai.vra.monitor.plist")
        print("  otherwise:             leave `python3 vra.py monitor --webui` running")
        return 0

    cfg = RunConfig(
        snapshot_version=args.snapshot_version,
        offline=args.offline,
        vendors=args.vendors,
        no_probe=args.no_probe,
        fail_on_critical=False,  # a critical is a finding, not a crashed daemon
        monitor_once=args.once,
        interval_seconds=interval,
    )
    if args.model:
        cfg.model = args.model
    if args.host:
        cfg.webui_host = args.host
    if args.port:
        cfg.webui_port = args.port
    return run_forever(cfg, interval=interval, with_webui=args.webui)
