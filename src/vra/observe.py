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
    "huggingface", "stability ai", "aleph alpha", "ai21", "together ai",
    "together.ai", "replicate", "azure openai", "amazon bedrock", "bedrock",
    "google vertex", "vertex ai", "google gemini", "gemini", "xai",
    "deepseek", "inflection", "runway", "elevenlabs", "eleven labs",
    "assemblyai", "deepgram", "turbopuffer", "pinecone", "weaviate",
    "qdrant", "chroma",
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
    * ``parse_failed`` — subprocessor disclosure was reached but could not be
                         parsed into valid rows (unrecognized table layout,
                         malformed markup, or extraction error).
    * ``empty``        — the artifact was readable but contained no parseable
                         subprocessor table or language.
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
    The flag tells the parser whether it may trust positional column mapping
    without a header row — prose lines split on multiple spaces are far more
    likely to be junk than pipe rows are.
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
    return rows


def _detect_table_header(rows: list[list[str]], max_scan: int = 8) -> tuple[int | None, list[str] | None]:
    """Find the header row index and column names in a table."""
    for idx, row in enumerate(rows[:max_scan]):
        if len(row) < 2:
            continue
        row_clean = [re.sub(r"\s+", " ", c).strip().lower() for c in row]
        joined = " ".join(row_clean)

        has_name = any(k in joined for k in NAME_HEADER_KEYWORDS)
        has_purpose = any(k in joined for k in PURPOSE_HEADER_KEYWORDS)
        has_region = any(k in joined for k in REGION_HEADER_KEYWORDS)
        has_baa = any(k in joined for k in BAA_HEADER_KEYWORDS)

        if has_name and (has_purpose or has_region or has_baa):
            return idx, row_clean
        if any("subprocessor" in c or "sub-processor" in c or "sub processor" in c for c in row_clean):
            return idx, row_clean
    return None, None


def _parse_table_rows(
    rows: list[list[str]], source: str, *, require_header: bool = False
) -> list[ObservedSubprocessor]:
    """Header-guided column mapping over table rows. Tolerant by design:
    a missed row here is a missed critical finding. With ``require_header``,
    rows are only accepted when a header row was found."""
    header_idx, header = _detect_table_header(rows)

    if require_header and header_idx is None:
        return []

    def col(keys: tuple[str, ...], default: int | None) -> int | None:
        if header:
            for i, cell in enumerate(header):
                if any(k in cell for k in keys):
                    return i
        return default

    i_name = col(NAME_HEADER_KEYWORDS, 0)
    i_purpose = col(PURPOSE_HEADER_KEYWORDS, 1)
    i_region = col(REGION_HEADER_KEYWORDS, 2)
    i_baa = col(BAA_HEADER_KEYWORDS, 3 if header and len(header) > 3 else None)

    out: list[ObservedSubprocessor] = []
    start_idx = (header_idx + 1) if header_idx is not None else 0
    for idx, row in enumerate(rows):
        if idx < start_idx:
            continue
        if len(row) < 2:
            continue

        def get(i: int | None) -> str:
            if i is not None and 0 <= i < len(row):
                return re.sub(r"\s+", " ", row[i]).strip()
            return ""

        name = get(i_name)
        if not name or name.lower() in EXCLUDED_NAME_VALUES:
            continue
        if any(name.lower() == k for k in ("subprocessor name", "entity name", "legal entity", "third party")):
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
    """Parse subprocessor rows from normalized text (pipe-delimited or aligned).

    Deliberately tolerant: vendors format these tables inconsistently, and a
    missed row here is a missed critical finding. Column roles are detected by
    header keywords, with positional fallback.
    """
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

    This is the AIV-03 entry point. Order of attack:

    1. Structured HTML tables (extracted at ingestion) when present.
    2. Pipe-delimited / aligned text (normalized HTML, PDF extraction).
    3. Explicit verdicts for everything unparseable — a branded portal, a wall,
       a PDF without pypdf, an unparseable table format (parse_failed), or a
       readable page with no table — so AIV-03 is marked not-assessable instead
       of silently passing.
    """
    def status(kind: str, reason: str, rows: int = 0) -> ParseStatus:
        return ParseStatus(kind, platform=platform, reason=reason,
                           evidence=portal_evidence or reason, rows=rows)

    try:
        if tables:
            parsed = parse_html_tables(tables, source)
        else:
            rows, any_pipe = _rows_from_text(text)
            parsed = _parse_table_rows(rows, source, require_header=not any_pipe)
    except Exception as exc:
        return [], status(
            "parse_failed",
            f"subprocessor extraction failed with an error: {exc}",
        )

    # 1) Portal / click-through gate: even if incidental tables parsed, the
    #    authoritative list is gated — say so. If nothing parsed, hard blocked.
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

    if parsed:
        return parsed, status("parsed", f"parsed {len(parsed)} subprocessor row(s).", rows=len(parsed))

    if raw_kind == "pdf":
        return [], status(
            "empty",
            "the PDF was read but no subprocessor table (pipe-delimited or aligned "
            "rows) could be identified; manual review of the extracted text required.",
        )

    # If the page had tables or subprocessor keywords, but failed to parse into valid rows:
    has_tables = bool(tables and any(len(t) >= 2 for t in tables))
    has_language = bool(re.search(r"sub-?processor|third[- ]party", text, re.IGNORECASE))
    if has_tables or has_language:
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

    # --- structured artifact extraction: subprocessor tables --------------
    # AIV-03 rests on this parse, so a failed or gated parse must be recorded
    # on the state and surfaced as a gap — never silently treated as "no rows".
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
        break  # one subprocessors source per vendor; first non-error wins

    if state.subprocessor_parse is None:
        # No subprocessor watch source at all: AIV-03 has no observed data and
        # must be flagged rather than silently skipped.
        state.subprocessor_parse = ParseStatus(
            "missing",
            reason=(
                "no subprocessor watch source is configured for this vendor; AIV-03 has no "
                "observed data. Add a `watch: subprocessors:` entry (or run `vra onboard`)."
            ),
        )

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
