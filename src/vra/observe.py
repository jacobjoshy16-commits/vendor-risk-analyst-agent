"""Deterministic observation layer — structured fact extracted without a model.

This module exists to resolve a real tension in the design.

The register is human-authored, and the model may only *propose* changes to it
(Phase 3.4). But some vendor changes are structured enough to parse in code:
a subprocessor table is a table, and a tenant API response is JSON. Facts from
those sources are *observed*, not inferred, so they can drive a deterministic
finding immediately — without waiting for a human to ratify the register, and
without a model ever deciding anything.

So there are three tiers of state, and findings record which tier they came from:

  register  — a human wrote it down. Authoritative.
  observed  — parsed deterministically from a vendor artifact or tenant API.
              Overlays the register for evaluation, and is flagged in the report
              as not yet ratified.
  proposed  — a model read prose and suggested it. NEVER evaluated. Goes to
              pending_review/ for a human.

An observed overlay produces a finding because the tool can point at the exact
table row or JSON field it came from. A proposal cannot, and never does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Purpose text that marks a subprocessor as part of the AI surface.
AI_PURPOSE_TERMS = (
    "model", "inference", "llm", "generative", "generation", "ai ", " ai",
    "summariz", "embedding", "vector", "retrieval", "copilot", "assist",
    "transcription", "speech", "nlp",
)

# Known model/AI providers — a name match alone is enough even if the purpose
# column is vague, because these companies do exactly one thing for a vendor.
KNOWN_MODEL_PROVIDERS = (
    "openai", "anthropic", "perplexity", "cohere", "mistral", "hugging face",
    "stability ai", "aleph alpha", "ai21", "together ai", "replicate",
    "azure openai", "amazon bedrock", "google vertex", "vertex ai", "xai",
    "deepseek", "inflection", "runway", "elevenlabs", "assemblyai", "deepgram",
)

# BAA column values that do NOT constitute executed coverage.
NON_COVERAGE_MARKERS = ("no", "pending", "in progress", "n/a", "not applicable", "tbd", "—", "-")


@dataclass
class ObservedSubprocessor:
    name: str
    purpose: str
    region: str
    baa_marker: str
    source: str
    raw_line: str

    @property
    def is_ai_related(self) -> bool:
        blob = f"{self.name} {self.purpose}".lower()
        if any(p in self.name.lower() for p in KNOWN_MODEL_PROVIDERS):
            return True
        return any(t in blob for t in AI_PURPOSE_TERMS)

    @property
    def baa_covered(self) -> bool:
        marker = self.baa_marker.strip().lower()
        if not marker:
            return False
        if any(marker.startswith(m) for m in NON_COVERAGE_MARKERS):
            return False
        return marker.startswith("yes") or "executed" in marker or "covered" in marker


@dataclass
class ObservedState:
    vendor: str
    subprocessors: list[ObservedSubprocessor] = field(default_factory=list)
    # feature name -> {field: {"value":…, "provenance":…, "evidence":…}}
    overrides: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)

    def override_for(self, feature_name: str, key: str):
        return (self.overrides.get(feature_name) or {}).get(key)

    def add_override(self, feature: str, key: str, value, provenance: str, evidence: str) -> None:
        self.overrides.setdefault(feature, {})[key] = {
            "value": value,
            "provenance": provenance,
            "evidence": evidence,
        }

    @property
    def uncovered_ai_subprocessors(self) -> list[ObservedSubprocessor]:
        return [s for s in self.subprocessors if s.is_ai_related and not s.baa_covered]


def parse_subprocessor_table(text: str, source: str) -> list[ObservedSubprocessor]:
    """Parse the normalized pipe-delimited table the HTML normalizer emits.

    Deliberately tolerant: vendors format these tables inconsistently, and a
    missed row here is a missed critical finding. Column roles are detected by
    header keywords, with positional fallback.
    """
    rows: list[list[str]] = []
    for line in text.splitlines():
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.split("|")]
        cells = [c for c in cells if c]
        if len(cells) >= 2:
            rows.append(cells)
    if not rows:
        return []

    # Locate the header row to map columns.
    header_idx, header = None, None
    for idx, row in enumerate(rows[:5]):
        joined = " ".join(row).lower()
        if any(k in joined for k in ("subprocessor", "entity", "sub-processor", "vendor", "company")):
            if any(k in joined for k in ("purpose", "service", "function", "processing", "activity")):
                header_idx, header = idx, [c.lower() for c in row]
                break

    def col(keys: tuple[str, ...], default: int | None) -> int | None:
        if header:
            for i, cell in enumerate(header):
                if any(k in cell for k in keys):
                    return i
        return default

    i_name = col(("subprocessor", "entity", "sub-processor", "company", "vendor", "name"), 0)
    i_purpose = col(("purpose", "service", "function", "processing", "activity", "description"), 1)
    i_region = col(("location", "region", "country", "where"), 2)
    i_baa = col(("baa", "hipaa", "phi", "coverage"), 3)

    out: list[ObservedSubprocessor] = []
    for idx, row in enumerate(rows):
        if header_idx is not None and idx <= header_idx:
            continue

        def get(i: int | None) -> str:
            return row[i] if i is not None and i < len(row) else ""

        name = get(i_name)
        if not name or name.lower() in ("subprocessor", "entity", "name"):
            continue
        out.append(
            ObservedSubprocessor(
                name=name,
                purpose=get(i_purpose),
                region=get(i_region),
                baa_marker=get(i_baa),
                source=source,
                raw_line=" | ".join(row),
            )
        )
    return out


def observe_vendor(vendor: dict, snapshots: list, probe_result) -> ObservedState:
    """Build the observed overlay from artifacts and the tenant probe."""
    state = ObservedState(vendor=vendor["slug"])

    # --- structured artifact extraction: subprocessor tables --------------
    for snap in snapshots:
        if getattr(snap, "error", None) or snap.source != "subprocessors":
            continue
        state.subprocessors = parse_subprocessor_table(snap.text, snap.source)

    # Cross-check parsed BAA markers against the contract's own covered list.
    covered = {c.strip().lower() for c in (vendor.get("contract") or {}).get("baa_covered_subprocessors", [])}
    for sp in state.subprocessors:
        if sp.baa_covered:
            continue
        low = sp.name.lower()
        # A vendor page saying "Pending" outranks our stale contract list, but if
        # the page is silent and our contract covers them, treat as covered.
        if not sp.baa_marker and any(low in c or c in low for c in covered):
            sp.baa_marker = "yes (per contract record)"

    # --- tenant probe: hard facts about what is switched on ---------------
    if probe_result is not None and getattr(probe_result, "ran", False):
        surface = vendor.get("ai_surface") or []
        primary = surface[0].get("feature") if surface else None
        for recon in probe_result.reconciliation:
            target = recon.get("feature")
            names = {f.get("feature") for f in surface}
            if target not in names:
                target = primary
            if not target or recon.get("surface_field") is None:
                continue
            if recon["type"] == "retention_unset":
                continue  # absence of a value is a gap, not an observed override
            state.add_override(
                feature=target,
                key=recon["surface_field"],
                value=recon["proposed_value"],
                provenance=f"in_tenant_probe:{recon['type']}",
                evidence=recon["detail"],
            )

    return state


def effective_feature(feature: dict, observed: ObservedState) -> tuple[dict, dict[str, dict]]:
    """Register values overlaid with deterministically observed ones.

    Returns the effective feature dict and the provenance map for whichever
    fields were overridden, so the report can show that a finding rests on
    tenant observation rather than on the register.
    """
    name = feature.get("feature")
    overrides = observed.overrides.get(name) or {}
    if not overrides:
        return feature, {}
    merged = dict(feature)
    applied: dict[str, dict] = {}
    for key, meta in overrides.items():
        if merged.get(key) != meta["value"]:
            merged[key] = meta["value"]
            applied[key] = meta
    return merged, applied
