"""Paths, run configuration, and the severity policy tables.

Everything here is deterministic policy, deliberately kept out of the model's
reach. Due dates in particular come from a table in code (Phase 6.3) so that a
finding's deadline cannot drift because a model felt generous.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

VENDORS_DIR = REPO_ROOT / "vendors"
CONTROLS_FILE = REPO_ROOT / "controls.yaml"
NHI_CONTROLS_FILE = REPO_ROOT / "nhi_controls.yaml"
DATA_DIR = REPO_ROOT / "data"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
PENDING_REVIEW_DIR = REPO_ROOT / "pending_review"
LLM_AUDIT_LOG = DATA_DIR / "llm_audit.jsonl"
FINDINGS_FILE = DATA_DIR / "findings.json"
NHI_FILE = DATA_DIR / "nhis.json"
MONITOR_STATUS_FILE = DATA_DIR / "monitor.json"
MONITOR_LOCK_FILE = DATA_DIR / "monitor.lock"
MONITOR_STOP_FILE = DATA_DIR / "monitor.stop"
MONITOR_LOG_FILE = DATA_DIR / "monitor.log"
DEFAULT_OUT_DIR = REPO_ROOT / "out"
DEFAULT_MONITOR_INTERVAL = int(os.environ.get("VRA_MONITOR_INTERVAL", "900"))
DEFAULT_WORKERS = max(1, min(int(os.environ.get("VRA_WORKERS", "4")), 8))

SEVERITIES = ("critical", "high", "medium", "low")

# Phase 6.3 — due date derived from severity by a table in code.
DUE_DAYS_BY_SEVERITY = {
    "critical": 7,
    "high": 30,
    "medium": 60,
    "low": 90,
}

# Suggested owner role by control family. Deterministic, not model-chosen.
OWNER_BY_SEVERITY = {
    "critical": "CISO / Vendor Risk Lead",
    "high": "Vendor Risk Analyst",
    "medium": "Vendor Risk Analyst",
    "low": "Vendor Management",
}

# Information gaps are outreach, not remediation. They get a response-by date
# rather than a remediation deadline.
GAP_RESPONSE_DAYS = 21

FINDING_STATES = ("open", "awaiting_vendor", "accepted_risk", "closed")

# Values that mean "we do not know", as opposed to a failing answer.
UNKNOWN_TOKENS = {"unknown", "undisclosed", "tbd", "not_provided", None, ""}


@dataclass
class RunConfig:
    """Options for a single analyst run."""

    snapshot_version: str = "v1"
    offline: bool = False
    dry_run: bool = False
    out_dir: Path = field(default_factory=lambda: DEFAULT_OUT_DIR)
    vendors: list[str] = field(default_factory=list)  # empty = all
    model: str = field(default_factory=lambda: os.environ.get("VRA_MODEL", "qwen2.5:7b-instruct"))
    ollama_host: str = field(
        default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    )
    no_probe: bool = False
    fail_on_critical: bool = True
    interval_seconds: int = field(
        default_factory=lambda: int(os.environ.get("VRA_MONITOR_INTERVAL", "900"))
    )
    monitor_once: bool = False
    allow_env_creds: bool = False
    webui_host: str = field(default_factory=lambda: os.environ.get("VRA_WEBUI_HOST", "0.0.0.0"))
    webui_port: int = field(
        default_factory=lambda: int(os.environ.get("VRA_WEBUI_PORT", "8765"))
    )
    workers: int = field(
        default_factory=lambda: max(1, min(int(os.environ.get("VRA_WORKERS", "4")), 8))
    )

    @property
    def llm_enabled(self) -> bool:
        """Offline mode swaps the Ollama backend for a deterministic stub."""
        return not self.offline
