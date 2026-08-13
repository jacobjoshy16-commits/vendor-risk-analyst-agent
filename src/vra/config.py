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
DATA_DIR = REPO_ROOT / "data"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
PENDING_REVIEW_DIR = REPO_ROOT / "pending_review"
LLM_AUDIT_LOG = DATA_DIR / "llm_audit.jsonl"
FINDINGS_FILE = DATA_DIR / "findings.json"
DEFAULT_OUT_DIR = REPO_ROOT / "out"

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
    model: str = field(default_factory=lambda: os.environ.get("VRA_MODEL", "llama3.1:8b"))
    ollama_host: str = field(
        default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    )
    no_probe: bool = False
    fail_on_critical: bool = True

    @property
    def llm_enabled(self) -> bool:
        """Offline mode swaps the Ollama backend for a deterministic stub."""
        return not self.offline
