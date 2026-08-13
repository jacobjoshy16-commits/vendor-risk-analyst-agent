"""Phase 3 — AI-relevance triage.

The model's first job, and the one it is genuinely good at: read a diff of
vendor prose and say whether the vendor's AI surface changed.

Hard boundaries enforced here in code, not asked of the model:
  * change_type is validated against a closed enum. Anything else is rejected
    and retried, then downgraded to "none".
  * The model PROPOSES a surface update. It never writes one. Proposals land in
    pending_review/ for a human to accept (Phase 3.4).
  * proposed_surface_update keys are filtered to known register fields, so a
    hallucinated field name cannot enter the register even if a human
    rubber-stamps the file.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PENDING_REVIEW_DIR, RunConfig
from .llm import call_json
from .watch import SourceDiff

CHANGE_TYPES = {
    "new_ai_feature",
    "new_agent",
    "autonomy_increase",
    "new_subprocessor",
    "model_provider_change",
    "retention_change",
    "training_policy_change",
    "none",
}

# Only these register fields may ever appear in a proposed surface update.
SURFACE_FIELDS = {
    "feature", "status", "autonomy", "data_reach", "model_provider",
    "training_on_customer_data", "human_in_loop", "retention_days",
    "output_logged", "change_notification", "error_rate_disclosed",
    "prompt_injection_tested", "data_residency", "bias_tested_clinical",
    "ai_incident_process", "customer_disableable",
}

SYSTEM = """You are a third-party risk analyst at a hospital system. You read vendor \
changelogs, trust center pages, subprocessor lists and DPA text, and you decide whether a \
change affects the vendor's AI surface: the AI features, agents, and model providers that \
touch our data.

Rules you must follow:
- Answer ONLY with a single JSON object. No prose outside it.
- Judge only what the diff text actually says. Do not speculate about what a vendor might mean.
- Cosmetic edits, wording changes, marketing copy, performance notes, UI changes, and \
unrelated product features are NOT AI-relevant. Return change_type "none" for them.
- Rewording an existing AI feature description without changing its behaviour is NOT AI-relevant.
- You do not assign risk, severity, or compliance findings. Another system does that.
- evidence_excerpt must be copied verbatim from the diff. Never paraphrase it."""

PROMPT_TEMPLATE = """TASK: AI_RELEVANCE_TRIAGE

vendor: {vendor}
source: {source}
This source is the vendor's {source_desc}.

The vendor's AI surface as currently recorded in our register:
{surface}

Below is a unified diff of the vendor's {source} between our previous snapshot and today.
Lines beginning with + were added. Lines beginning with - were removed.

--- BEGIN DIFF ---
{diff}
--- END DIFF ---

Decide whether this diff changes the vendor's AI surface.

change_type must be exactly one of:
  new_ai_feature, new_agent, autonomy_increase, new_subprocessor,
  model_provider_change, retention_change, training_policy_change, none

Return JSON exactly in this shape:
{{
  "ai_relevant": true,
  "change_type": "new_agent",
  "summary": "one or two sentences, factual",
  "affected_fields": ["autonomy"],
  "proposed_surface_update": {{"autonomy": "acts"}},
  "evidence_excerpt": "verbatim line from the diff",
  "confidence": 0.8
}}

If nothing in the diff affects the AI surface, return ai_relevant false, change_type "none",
empty affected_fields, empty proposed_surface_update, and an empty evidence_excerpt."""

SOURCE_DESC = {
    "changelog": "product changelog or release notes",
    "trust_center": "trust center / security and AI disclosures page",
    "subprocessors": "subprocessor list",
    "dpa": "data processing addendum or BAA text",
}


@dataclass
class TriageResult:
    vendor: str
    source: str
    ai_relevant: bool
    change_type: str
    summary: str
    affected_fields: list[str]
    proposed_surface_update: dict[str, Any]
    evidence_excerpt: str
    confidence: float
    backend: str
    llm_ok: bool
    churn: int = 0
    error: str | None = None
    rejected_fields: list[str] = field(default_factory=list)


def _schema_check(obj: dict) -> str | None:
    required = [
        "ai_relevant", "change_type", "summary", "affected_fields",
        "proposed_surface_update", "evidence_excerpt", "confidence",
    ]
    missing = [k for k in required if k not in obj]
    if missing:
        return f"missing keys: {missing}"
    if not isinstance(obj["ai_relevant"], bool):
        return "ai_relevant must be a boolean"
    if obj["change_type"] not in CHANGE_TYPES:
        return f"change_type must be one of {sorted(CHANGE_TYPES)}"
    if not isinstance(obj["affected_fields"], list):
        return "affected_fields must be a list"
    if not isinstance(obj["proposed_surface_update"], dict):
        return "proposed_surface_update must be an object"
    try:
        conf = float(obj["confidence"])
    except (TypeError, ValueError):
        return "confidence must be a number"
    if not 0.0 <= conf <= 1.0:
        return "confidence must be between 0 and 1"
    return None


def _surface_summary(vendor: dict) -> str:
    lines = []
    for feat in vendor.get("ai_surface") or []:
        lines.append(
            "- {feature}: status={status}, autonomy={autonomy}, provider={mp}, "
            "human_in_loop={hil}, data_reach={dr}".format(
                feature=feat.get("feature"),
                status=feat.get("status"),
                autonomy=feat.get("autonomy"),
                mp=feat.get("model_provider"),
                hil=feat.get("human_in_loop"),
                dr=", ".join(feat.get("data_reach") or []),
            )
        )
    return "\n".join(lines) or "- (no AI features recorded)"


def triage_diff(vendor: dict, diff: SourceDiff, cfg: RunConfig) -> TriageResult:
    """Run one diff through the model. Returns a validated, clamped result."""
    prompt = PROMPT_TEMPLATE.format(
        vendor=vendor["vendor"],
        source=diff.source,
        source_desc=SOURCE_DESC.get(diff.source, "public artifact"),
        surface=_surface_summary(vendor),
        diff=diff.unified_diff[:12000],
    )
    result = call_json(
        system=SYSTEM,
        prompt=prompt,
        cfg=cfg,
        schema_check=_schema_check,
        task="ai_relevance_triage",
        context={"vendor": vendor["slug"], "source": diff.source, "new_hash": diff.new_hash},
    )

    if not result.ok:
        # Fail closed on content, loud on process: no finding is invented, but
        # the run records that triage could not be completed for this source.
        return TriageResult(
            vendor=vendor["slug"], source=diff.source, ai_relevant=False,
            change_type="none", summary="Triage failed; source requires manual review.",
            affected_fields=[], proposed_surface_update={}, evidence_excerpt="",
            confidence=0.0, backend=result.backend, llm_ok=False,
            churn=diff.churn, error=result.error,
        )

    data = result.data
    proposed = {k: v for k, v in (data.get("proposed_surface_update") or {}).items() if k in SURFACE_FIELDS}
    rejected = [k for k in (data.get("proposed_surface_update") or {}) if k not in SURFACE_FIELDS]
    affected = [f for f in (data.get("affected_fields") or []) if isinstance(f, str)]

    ai_relevant = bool(data["ai_relevant"])
    change_type = data["change_type"]
    # Consistency clamp: "none" and "relevant" cannot both be true.
    if change_type == "none":
        ai_relevant = False
    if not ai_relevant:
        change_type, proposed, affected = "none", {}, []

    return TriageResult(
        vendor=vendor["slug"],
        source=diff.source,
        ai_relevant=ai_relevant,
        change_type=change_type,
        summary=str(data.get("summary", ""))[:1000],
        affected_fields=affected,
        proposed_surface_update=proposed,
        evidence_excerpt=str(data.get("evidence_excerpt", ""))[:1500],
        confidence=float(data["confidence"]),
        backend=result.backend,
        llm_ok=True,
        churn=diff.churn,
        rejected_fields=rejected,
    )


def write_pending_review(vendor: dict, results: list[TriageResult], cfg: RunConfig) -> Path | None:
    """Phase 3.4 — proposals land here for a human to accept. Never auto-applied."""
    actionable = [r for r in results if r.ai_relevant and r.proposed_surface_update]
    if not actionable or cfg.dry_run:
        return None
    PENDING_REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = PENDING_REVIEW_DIR / f"{vendor['slug']}-{stamp}.json"
    payload = {
        "vendor": vendor["vendor"],
        "slug": vendor["slug"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "instructions": (
            "MODEL PROPOSAL — NOT APPLIED. Review each proposed change against the evidence "
            "excerpt and the linked source. To accept, edit the matching feature block in "
            f"vendors/{vendor['slug']}.yaml by hand, then delete this file. The tool will never "
            "write to the register on its own."
        ),
        "proposals": [
            {
                "source": r.source,
                "change_type": r.change_type,
                "summary": r.summary,
                "confidence": r.confidence,
                "backend": r.backend,
                "affected_fields": r.affected_fields,
                "proposed_surface_update": r.proposed_surface_update,
                "rejected_unknown_fields": r.rejected_fields,
                "evidence_excerpt": r.evidence_excerpt,
            }
            for r in actionable
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
