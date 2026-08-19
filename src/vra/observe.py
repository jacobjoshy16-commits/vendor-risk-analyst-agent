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
    "transcription", "speech", "nlp", "machine learning", "deep learning",
    "large language", "intelligence", "synthetic", "rag ",
)

# Known model/AI providers — a name match alone is enough even if the purpose
# column is vague, because these companies do exactly one thing for a vendor.
KNOWN_MODEL_PROVIDERS = (
    "openai", "anthropic", "perplexity", "cohere", "mistral", "hugging face",
    "stability ai", "aleph alpha", "ai21", "together ai", "replicate",
    "azure openai", "amazon bedrock", "google vertex", "vertex ai", "xai",
    "deepseek", "inflection", "runway", "elevenlabs", "assemblyai", "deepgram",
    "eleven labs", "fireworks",
)

# BAA column values that do NOT constitute executed coverage.
NON_COVERAGE_MARKERS = (
    "no", "pending", "in progress", "n/a", "not applicable", "tbd",
    "—", "-", "none", "not covered", "unexecuted", "false",
)

# Header keyword classification
NAME_HEADER_KEYWORDS = (
    "subprocessor", "sub-processor", "sub processor", "entity", "legal entity",
    "company", "vendor", "supplier", "third-party", "third party", "provider",
    "name", "organization", "partner", "contractor", "subcontractor",
)

PURPOSE_HEADER_KEYWORDS = (
    "purpose", "service", "services", "function", "processing", "activity",
    "activities", "scope", "description", "nature", "role", "use case",
    "applicable", "feature", "category", "subject matter",
)

REGION_HEADER_KEYWORDS = (
    "location", "region", "country", "where", "hosting", "data location",
    "jurisdiction", "headquarters", "corporate", "geographic", "storage",
    "place",
)

BAA_HEADER_KEYWORDS = (
    "baa", "hipaa", "phi", "coverage", "covered", "agreement", "dpa",
    "safeguards", "status",
)

EXCLUDED_NAME_VALUES = {
    "subprocessor", "subprocessors", "sub-processor", "sub-processors",
    "sub processor", "sub processors", "entity", "entity name",
    "legal entity name", "legal entity", "third party", "third-party",
    "third party subprocessor", "third-party subprocessor", "third-party subprocessors",
    "vendor", "company", "name", "organization", "partner", "supplier",
    "provider", "service provider",
}


@dataclass
class ParseStatus:
    """How the subprocessor artifact was (or was not) turned into rows.

    This is the answer to "can AIV-03 actually be evaluated?" — a status other
    than ``parsed`` must surface as an information gap, never as a silent pass.

    * ``parsed``       — rows extracted; AIV-03 evaluates against them.
    * ``blocked``      — the list is behind a click-through NDA / branded
                         portal / login wall. No parse attempted or no rows.
    * ``parse_failed`` — the page is about subprocessors (or looks like a
                         table) but no rows could be extracted. Never a silent
                         pass; always an AIV-03 gap.
    * ``empty``        — the artifact was readable but contained no
                         subprocessor language and no table.
    * ``error``        — the artifact could not be ingested (PDF without pypdf,
                         fetch failure, corrupt file).
    * ``missing``      — no subprocessor watch source is configured at all.
    """

    status: str                       # parsed | blocked | parse_failed | empty | error | missing
    platform: str | None = None       # safebase | whistic | vanta | generic | pdf | None
    reason: str = ""
    evidence: str = ""
    rows: int = 0

    @property
    def assessable(self) -> bool:
        return self.status == "parsed"


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
    subprocessor_parse: ParseStatus | None = None
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


def _rows_from_text(text: str) -> tuple[list[list[str]], bool]:
    """Split normalized text into candidate rows.

    Returns ``(rows, any_pipe_rows)``. Prefers pipe-delimited table rows (the
    form the HTML normalizer emits, and the form PDF text extraction tends to
    produce); falls back to whitespace-aligned lines when no pipe row exists.
    """
    rows: list[list[str]] = []
    any_pipe = False
    for line in text.splitlines():
        if "|" in line:
            cells = [c.strip() for c in line.split("|")]
            cells = [c for c in cells if c]
            if len(cells) >= 2:
                rows.append(cells)
                any_pipe = True
                continue
        cells = re.split(r"\s{2,}", line.strip())
        cells = [c for c in (c.strip() for c in cells) if c]
        if len(cells) >= 2:
            rows.append(cells)
    return rows, any_pipe


def _rows_from_tables(tables: list[list[list[str]]]) -> list[list[str]]:
    """Flatten extracted HTML tables into candidate rows, dropping empties."""
    rows: list[list[str]] = []
    for table in tables:
        for row in table:
            cells = [c for c in (c.strip() for c in row) if c]
            if len(cells) >= 2:
                rows.append(cells)
            elif len(cells) == 1:
                rows.append(cells)  # keep section headers so we can skip them
    return rows


# Real trust-center tables (Atlassian) put the field name inside the cell.
_LABELED_CELL = (
    ("purpose", ("nature and purpose of processing", "purpose of processing",
                 "nature of processing", "type of service", "services provided")),
    ("region", ("location of processing", "country of location", "processing location")),
    ("baa", ("baa coverage", "hipaa coverage", "phi coverage")),
)

_SECTION_NAME = re.compile(
    r"(providers?|affiliates?|entities|group companies|infrastructure|platform|"
    r"customer and support|business operations|authorized subprocessors|"
    r"third-party subprocessors|list of third-party)$",
    re.I,
)
_HEADER_NAME_WORDS = (
    "subprocessor", "sub-processor", "entity", "company", "vendor", "name",
    "third party", "third-party",
)
_HEADER_PURPOSE_WORDS = (
    "purpose", "service", "function", "processing", "activity", "description",
)
_SKIP_NAMES = {
    "subprocessor", "subprocessors", "sub-processor", "entity", "name", "vendor",
    "company", "third party", "third-party", "applicable cloud products",
}


def _split_labeled_cell(cell: str) -> tuple[str | None, str]:
    """Return (label_role, remainder) when a cell starts with a known label."""
    low = re.sub(r"\s+", " ", cell).strip().lower()
    for role, labels in _LABELED_CELL:
        for lab in labels:
            if low.startswith(lab):
                return role, cell[len(lab):].lstrip(" \n\t:-–—")
            if lab in low[: len(lab) + 8]:
                parts = re.split(re.escape(lab), cell, maxsplit=1, flags=re.I)
                if len(parts) == 2:
                    return role, parts[1].lstrip(" \n\t:-–—")
    return None, cell


def _labeled_fields(row: list[str]) -> dict[str, str] | None:
    """Atlassian-style rows: first unlabeled cell is the name, others are tagged."""
    fields: dict[str, str] = {}
    unlabeled: list[str] = []
    hits = 0
    for cell in row:
        role, rest = _split_labeled_cell(cell)
        if role:
            fields[role] = rest
            hits += 1
        else:
            unlabeled.append(cell)
    if hits < 1:
        return None
    if unlabeled:
        fields.setdefault("name", unlabeled[0])
    return fields if fields.get("name") else None


def _is_section_or_header_name(name: str) -> bool:
    low = name.strip().lower()
    if low in _SKIP_NAMES:
        return True
    if _SECTION_NAME.search(low):
        return True
    return False


def _from_fields(fields: dict[str, str], source: str, raw: list[str]) -> ObservedSubprocessor | None:
    name = (fields.get("name") or "").strip()
    if not name or _is_section_or_header_name(name):
        return None
    return ObservedSubprocessor(
        name=name,
        purpose=fields.get("purpose", ""),
        region=fields.get("region", ""),
        baa_marker=fields.get("baa", ""),
        source=source,
        raw_line=" | ".join(raw),
    )


def _parse_rows(
    rows: list[list[str]], source: str, *, require_header: bool = False
) -> list[ObservedSubprocessor]:
    """Header-guided column mapping, plus Atlassian labeled-cell fallback.

    A missed row here is a missed critical finding.
    """
    header_idx, header = None, None
    for idx, row in enumerate(rows[:8]):
        joined = " ".join(row).lower()
        if any(k in joined for k in _HEADER_NAME_WORDS) and any(k in joined for k in _HEADER_PURPOSE_WORDS):
            header_idx, header = idx, [c.lower() for c in row]
            break

    def col(keys: tuple[str, ...], default: int | None) -> int | None:
        if header:
            for i, cell in enumerate(header):
                if any(k in cell for k in keys):
                    return i
        return default

    i_name = col(("subprocessor", "sub-processor", "entity", "company", "vendor", "name"), 0)
    i_purpose = col(("purpose", "service", "function", "processing", "activity", "description"), 1)
    i_region = col(("location", "region", "country", "where"), 2)
    i_baa = col(("baa", "hipaa", "phi", "coverage"), None)

    out: list[ObservedSubprocessor] = []

    if require_header and header_idx is None:
        for row in rows:
            fields = _labeled_fields(row)
            if not fields:
                continue
            item = _from_fields(fields, source, row)
            if item:
                out.append(item)
        return out

    for idx, row in enumerate(rows):
        if idx < start_idx:
            continue
        if len(row) < 2:
            continue
        if len(row) == 1 and _is_section_or_header_name(row[0]):
            continue

        labeled = _labeled_fields(row)
        if labeled:
            item = _from_fields(labeled, source, row)
            if item:
                out.append(item)
            continue

        def get(i: int | None) -> str:
            if i is not None and 0 <= i < len(row):
                return re.sub(r"\s+", " ", row[i]).strip()
            return ""

        name = get(i_name)
        if not name or _is_section_or_header_name(name):
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


def _parse_rows(
    rows: list[list[str]], source: str, *, require_header: bool = False
) -> list[ObservedSubprocessor]:
    """Backward-compatible alias for table row parsing."""
    return _parse_table_rows(rows, source, require_header=require_header)


def parse_html_tables(
    tables: list[list[list[str]]], source: str
) -> list[ObservedSubprocessor]:
    """Extract subprocessor rows across all HTML tables in a document."""
    all_rows: list[ObservedSubprocessor] = []
    seen: set[tuple[str, str]] = set()

    for table in tables:
        if not table or len(table) < 2:
            continue
        parsed = _parse_table_rows(table, source, require_header=True)
        if not parsed and len(tables) == 1:
            parsed = _parse_table_rows(table, source, require_header=False)
        for sp in parsed:
            key = (sp.name.lower().strip(), sp.purpose.lower().strip())
            if key not in seen:
                seen.add(key)
                all_rows.append(sp)
    return all_rows


def parse_subprocessor_table(text: str, source: str) -> list[ObservedSubprocessor]:
    """Parse subprocessor rows from normalized text (pipe-delimited or aligned)."""
    rows, _ = _rows_from_text(text)
    return _parse_table_rows(rows, source, require_header=False)


def parse_subprocessors(
    text: str,
    *,
    source: str,
    tables: list[list[list[str]]] | None = None,
    platform: str | None = None,
    portal_blocked: bool = False,
    portal_evidence: str = "",
    raw_kind: str = "text",
) -> tuple[list[ObservedSubprocessor], ParseStatus]:
    """Parse a real-world subprocessor artifact into rows plus a parse status.

    Order of attack:

    1. Structured HTML tables (extracted at ingestion) when present.
    2. Pipe-delimited / aligned text (normalized HTML, PDF extraction).
    3. Explicit verdicts for everything unparseable — a branded portal, a
       JS shell, a PDF without rows — so AIV-03 is marked not-assessable
       instead of silently passing.
    """
    if tables:
        rows = _rows_from_tables(tables)
        parsed = _parse_rows(rows, source)
    else:
        rows, any_pipe = _rows_from_text(text)
        parsed = _parse_rows(rows, source, require_header=not any_pipe)

    def status(kind: str, reason: str, rows: int = 0) -> ParseStatus:
        return ParseStatus(kind, platform=platform, reason=reason,
                           evidence=portal_evidence or reason, rows=rows)

    if platform in ("safebase", "whistic", "vanta") or portal_blocked:
        if parsed:
            return parsed, status(
                "parsed",
                f"rows parsed from a {platform or 'gated'} trust-portal page; "
                "verify the list is the post-NDA, current disclosure before relying on it.",
                rows=len(parsed),
            )
        return [], status(
            "blocked",
            f"subprocessor disclosure is hosted on the {platform or 'gated'} trust "
            "portal behind a click-through NDA / access request; the list cannot be "
            "parsed without guest access.",
        )

    if not parsed:
        has_language = bool(re.search(r"sub-?processor", text, re.IGNORECASE))
        kind_note = "PDF" if raw_kind == "pdf" else "page"
        if has_language or (tables and any(len(t) > 1 for t in tables)):
            return [], status(
                "parse_failed",
                f"the {kind_note} discusses subprocessors or contains table markup "
                "but no entity rows could be extracted; AIV-03 cannot be evaluated. "
                "This is a parse failure, not a clean list.",
            )
        return [], status(
            "parse_failed",
            "subprocessor disclosure page was reachable but could not be parsed into "
            "valid subprocessor rows; unrecognized table structure or unsupported markup. "
            "Manual review required.",
        )

    return [], status(
        "empty",
        "no subprocessor table found in the artifact; AIV-03 cannot be evaluated "
        "from this source. Confirm the watch URL points at the subprocessor list.",
    )


def observe_vendor(vendor: dict, snapshots: list, probe_result) -> ObservedState:
    """Build the observed overlay from artifacts and the tenant probe."""
    state = ObservedState(vendor=vendor["slug"])

    for snap in snapshots:
        if snap.source != "subprocessors":
            continue
        if getattr(snap, "error", None):
            state.subprocessor_parse = ParseStatus(
                "error", platform=snap.platform,
                reason=f"subprocessor artifact could not be ingested: {snap.error}",
                evidence=snap.error,
            )
            continue
        state.subprocessors, state.subprocessor_parse = parse_subprocessors(
            snap.text,
            source=snap.source,
            tables=snap.tables,
            platform=snap.platform,
            portal_blocked=snap.portal_blocked,
            portal_evidence=snap.portal_evidence,
            raw_kind=snap.raw_kind,
        )
        break

    if state.subprocessor_parse is None:
        state.subprocessor_parse = ParseStatus(
            "missing",
            reason=(
                "no subprocessor watch source is configured for this vendor; AIV-03 has no "
                "observed data. Add a `watch: subprocessors:` entry (or run `vra onboard`). "
            ),
        )

    covered = {c.strip().lower() for c in (vendor.get("contract") or {}).get("baa_covered_subprocessors", [])}
    for sp in state.subprocessors:
        if sp.baa_covered:
            continue
        low = sp.name.lower()
        if not sp.baa_marker and any(low in c or c in low for c in covered):
            sp.baa_marker = "yes (per contract record)"

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
                continue
            state.add_override(
                feature=target,
                key=recon["surface_field"],
                value=recon["proposed_value"],
                provenance=f"in_tenant_probe:{recon['type']}",
                evidence=recon["detail"],
            )

    return state


def effective_feature(feature: dict, observed: ObservedState) -> tuple[dict, dict[str, dict]]:
    """Register values overlaid with deterministically observed ones."""
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
