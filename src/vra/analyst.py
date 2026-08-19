"""Phase 6 — analyst output.

The model's second job: turn a finding object into language a compliance officer
can use. Three artifacts per item:

  1. Finding narrative     — two or three sentences, constrained to facts in the
                             finding object. No new claims, no severity changes.
  2. Vendor outreach draft — email requesting specific evidence, citing the
                             control. Gaps become questions; failures become
                             demands.
  3. POA&M row             — remediation action, compensating control, owner
                             role, due date. Built in code from the severity
                             table, NOT by the model.

Guardrails applied after generation, not requested politely in the prompt:
severity words that contradict the deterministic severity are rejected and the
item falls back to a templated narrative.
"""

from __future__ import annotations

import re
from typing import Any

from .config import RunConfig
from .llm import call_json

NARRATIVE_SYSTEM = """You are a third-party risk analyst writing for a compliance officer who monitors vendor agentic identities against NIST SP 800-53 and SOC 2.

You will be given a single, already-decided vendor risk finding. Your only job is to state it \
in clear prose.

Absolute rules:
- Use ONLY facts present in the finding object you are given.
- Do NOT introduce new facts, vendors, products, numbers, dates, or regulations.
- Do NOT change, argue with, or comment on the severity. It is already decided.
- Do NOT recommend a severity, a risk score, or a decision.
- Two or three sentences. Plain professional English. No bullet points, no headers.
- Answer ONLY with a single JSON object: {"narrative": "..."}"""

NARRATIVE_PROMPT = """TASK: FINDING_NARRATIVE

vendor: {vendor}
feature: {feature}
control_id: {control_id}
control_question: {question}
citation: {citation}
severity: {severity}
kind: {kind}
observed: {observed}
reason: {reason}
{evidence_block}
Write the narrative now. Two or three sentences. JSON only: {{"narrative": "..."}}"""

OUTREACH_SYSTEM = """You are a vendor-risk analyst drafting an email to a vendor contact \
about a non-human identity or AI feature under continuous NIST SP 800-53 / SOC 2 monitoring.

Rules:
- Reference the specific control and the specific missing evidence.
- If kind is "gap", ask a precise question and request the evidence.
- If kind is "finding", state the deficiency and require a remediation plan and date.
- Professional, direct, no filler, no apology, no marketing tone.
- Do not invent contract terms, prices, names, or deadlines beyond the response window given.
- Answer ONLY with a single JSON object: {"subject": "...", "body": "..."}"""

OUTREACH_PROMPT = """TASK: VENDOR_OUTREACH

vendor: {vendor}
feature: {feature}
control_id: {control_id}
control_question: {question}
citation: {citation}
kind: {kind}
severity: {severity}
observed: {observed}
what_we_need: {need}
response_window_days: {window}

Write the email. JSON only: {{"subject": "...", "body": "..."}}"""

# Words that would mean the model editorialised about risk level.
SEVERITY_WORDS = re.compile(
    r"\b(critical|high[- ]risk|severe|catastrophic|low[- ]risk|negligible|minor|trivial|"
    r"medium[- ]risk|urgent|emergency)\b",
    re.IGNORECASE,
)


def _narrative_schema(obj: dict) -> str | None:
    if "narrative" not in obj:
        return "missing key: narrative"
    text = obj["narrative"]
    if not isinstance(text, str) or len(text.strip()) < 40:
        return "narrative must be a string of at least 40 characters"
    if len(text) > 1200:
        return "narrative too long; two or three sentences only"
    return None


def _outreach_schema(obj: dict) -> str | None:
    for key in ("subject", "body"):
        if key not in obj:
            return f"missing key: {key}"
        if not isinstance(obj[key], str) or not obj[key].strip():
            return f"{key} must be a non-empty string"
    if len(obj["subject"]) > 200:
        return "subject too long"
    return None


def _fallback_narrative(record: dict) -> str:
    if record["kind"] == "gap":
        fields = ", ".join(record["observed"].keys())
        return (
            f"{record['vendor_name']} has not provided enough information to assess control "
            f"{record['control_id']} for {record['feature']}: {record['control_question']} "
            f"The following is unknown in our register: {fields}. This is an information gap "
            f"pending vendor response, not a confirmed control failure."
        )
    observed = "; ".join(f"{k}={v}" for k, v in record["observed"].items())
    return (
        f"{record['vendor_name']} fails control {record['control_id']} for {record['feature']}: "
        f"{record['control_question']} Observed: {observed}. Cited against {record['citation']}."
    )


def _fallback_outreach(record: dict) -> dict[str, str]:
    is_gap = record["kind"] == "gap"
    fields = ", ".join(record["observed"].keys())
    if record.get("subject") == "subprocessor-list-access":
        return {
            "subject": f"Vendor NHI / agentic review — {record['vendor_name']} — subprocessor disclosure access",
            "body": (
                "Hello,\\n\\n"
                f"As part of continuous monitoring of {record['vendor_name']} agentic identities "
                "against NIST SP 800-53 and SOC 2, we must complete control AIV-03 (every model "
                "provider named as a subprocessor and covered by an executed BAA or DPA).\\n\\n"
                "We were unable to access your subprocessor disclosure from the public trust portal. "
                "Please either:\\n"
                "1. Grant us guest or NDA-gated access to the subprocessor page, or\\n"
                "2. Send the complete, current subprocessor list with BAA coverage status for each "
                "entity, including every model or AI service provider.\\n\\n"
                "This item affects our assessment of customer data processed by your service and by "
                "any non-human identity it runs in our tenants. Please respond within 21 days.\\n\\n"
                "Regards,\\nVendor Risk / NHI Monitoring"
            ),
        }
    verb = "provide the following information" if is_gap else "confirm your remediation plan"
    return {
        "subject": f"Vendor NHI / agentic review — {record['vendor_name']} — control {record['control_id']}",
        "body": (
            "Hello,\n\n"
            f"As part of continuous third-party NHI and agentic-AI monitoring (NIST SP 800-53 / SOC 2), "
            f"we are reviewing {record['feature']} against our control {record['control_id']}.\n\n"
            f"Control question: {record['control_question']}\n"
            f"Framework references: {record['citation']}\n\n"
            f"Please {verb} in respect of: {fields}.\n\n"
            "This item affects our assessment of customer data processed by your service and by "
            "any non-human identity it runs in our tenants. Please respond within 21 days.\n\n"
            "Regards,\nVendor Risk / NHI Monitoring"
        ),
    }


def _evidence_block(record: dict) -> str:
    ev = record.get("evidence") or []
    if not ev:
        return ""
    lines = ["evidence_excerpts:"]
    for item in ev[:3]:
        excerpt = (item.get("excerpt") or "").strip()
        if excerpt:
            lines.append(f"  - [{item.get('source', 'source')}] {excerpt[:400]}")
    return "\n".join(lines) + "\n" if len(lines) > 1 else ""


def draft_narrative(record: dict, cfg: RunConfig) -> tuple[str, bool]:
    """Returns (narrative, model_generated)."""
    prompt = NARRATIVE_PROMPT.format(
        vendor=record["vendor_name"],
        feature=record["feature"],
        control_id=record["control_id"],
        question=record["control_question"],
        citation=record["citation"],
        severity=record["severity"],
        kind=record["kind"],
        observed="; ".join(f"{k}={v}" for k, v in record["observed"].items()),
        reason=record["reason"],
        evidence_block=_evidence_block(record),
    )
    result = call_json(
        system=NARRATIVE_SYSTEM, prompt=prompt, cfg=cfg,
        schema_check=_narrative_schema, task="finding_narrative",
        context={"vendor": record["vendor"], "control_id": record["control_id"], "kind": record["kind"]},
    )
    if not result.ok:
        return _fallback_narrative(record), False

    text = result.data["narrative"].strip()
    # Guardrail: the model may restate the given severity, but may not introduce
    # a different one. Any severity word not matching the record's own severity
    # means it editorialised; fall back to the deterministic template.
    for word in SEVERITY_WORDS.findall(text):
        normalized = word.lower().replace("-risk", "").replace(" risk", "").strip()
        if normalized and normalized != record["severity"].lower():
            return _fallback_narrative(record), False
    return text, True


def draft_outreach(record: dict, cfg: RunConfig) -> tuple[dict[str, str], bool]:
    if record.get("subject") == "subprocessor-list-access":
        need = (
            "guest or NDA-gated access to the subprocessor disclosure (or a copy sent directly), "
            "plus confirmation of BAA coverage status for every model and AI service provider"
        )
    elif record["kind"] == "gap":
        need = (
            f"written evidence answering the control question, covering: {', '.join(record['observed'].keys())}"
        )
    else:
        need = f"a remediation plan and target date for: {record['remediation']}"
    prompt = OUTREACH_PROMPT.format(
        vendor=record["vendor_name"],
        feature=record["feature"],
        control_id=record["control_id"],
        question=record["control_question"],
        citation=record["citation"],
        kind=record["kind"],
        severity=record["severity"],
        observed="; ".join(f"{k}={v}" for k, v in record["observed"].items()),
        need=need,
        window=21,
    )
    result = call_json(
        system=OUTREACH_SYSTEM, prompt=prompt, cfg=cfg,
        schema_check=_outreach_schema, task="vendor_outreach",
        context={"vendor": record["vendor"], "control_id": record["control_id"], "kind": record["kind"]},
    )
    if not result.ok:
        return _fallback_outreach(record), False
    return {"subject": result.data["subject"].strip(), "body": result.data["body"].strip()}, True


def build_poam(record: dict) -> dict[str, Any]:
    """POA&M row. Entirely deterministic — no model input."""
    return {
        "poam_id": record["id"],
        "vendor": record["vendor_name"],
        "weakness": f"{record['control_id']}: {record['control_question']}",
        "feature": record["feature"],
        "severity": record["severity"],
        "remediation_action": record["remediation"]
        or "Obtain vendor evidence and re-assess against the control.",
        "compensating_control": record["compensating_control"] or "None identified.",
        "owner_role": record["owner"],
        "due_date": record["due_date"],
        "status": record.get("state", "open"),
        "citation": record["citation"],
    }


def enrich(record: dict, cfg: RunConfig) -> dict:
    """Attach narrative, outreach draft, and POA&M row to a finding record."""
    narrative, narr_model = draft_narrative(record, cfg)
    outreach, out_model = draft_outreach(record, cfg)
    record["narrative"] = narrative
    record["narrative_model_generated"] = narr_model
    record["outreach"] = outreach
    record["outreach_model_generated"] = out_model
    record["poam"] = build_poam(record)
    return record
