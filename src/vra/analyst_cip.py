"""The model as analyst: it reasons, and the code's output is one of its inputs.

How this differs from procure.py
--------------------------------
In procure.py the model extracts and the code adjudicates. That is the right
shape for reading a contract, where the question is "is this clause present"
and a wrong answer is a wrong fact.

This module is the other shape. Here the question is "what should we do about
this package", which is a judgement, and judgement is what a model is for. So
the code runs first and hands the model everything it established --- the
cryptographic result, which controls fired, what this vendor has done before,
how much of the estate depends on them --- and the model reasons over all of it
and reaches a disposition.

The code's verdict is not the answer. It is evidence, alongside the vendor's
history and the blast radius, and the model weighs it.

Why the deterministic layer still runs first
--------------------------------------------
Not as a guardrail. Because it is how the model gets good input. A model asked
"is this firmware safe" with only the bytes has nothing to reason with. A model
told "SHA-256 matches the published digest, the Ed25519 signature does not
verify against the vendor's active key, this vendor had two prior signature
failures this quarter, and this build is on 131 relays across 12 medium-impact
substations" has a great deal to reason with, and that is the difference
between a 4B model guessing and a 4B model being useful.

Disposition modes
-----------------
`--decision` selects who decides:

    code    the deterministic verdict decides (the original behaviour)
    model   the model's disposition decides
    both    both are computed and shown; disagreement is surfaced (default)

Disagreement is reported rather than hidden, because the two disagreeing is
information --- either the model saw context the rules do not encode, or it got
it wrong, and both are worth knowing.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import date
from typing import Any

from .cipcrypto import VerificationResult
from .config import RunConfig
from .llm import call_json

DISPOSITIONS = ("block", "allow", "escalate")
RISKS = ("critical", "high", "medium", "low")

DECIDE_CODE = "code"
DECIDE_MODEL = "model"
DECIDE_BOTH = "both"


# ---------------------------------------------------------------------------
# The brief
# ---------------------------------------------------------------------------
@dataclass
class ReasoningBrief:
    """Everything the code established, assembled for the model to reason over."""

    package_id: str
    vendor: str
    target_model: str = ""
    version: str = ""

    # What the cryptography found.
    computed_sha256: str | None = None
    published_sha256: str | None = None
    hash_match: bool | None = None
    signature_verified: bool | None = None
    signing_key_id: str | None = None
    signing_key_status: str = "unknown"
    signing_key_fingerprint: str | None = None
    key_fingerprint_confirmed_oob: bool | None = None
    verification_strength: str = "none"
    source_identity_verified: bool | None = None
    integrity_verified: bool | None = None
    verification_log: list[str] = field(default_factory=list)

    # What the control set concluded.
    failed_controls: list[dict] = field(default_factory=list)
    deterministic_verdict: str = "allow"

    # Blast radius, from the asset inventory.
    deployed_on_devices: int = 0
    substations: int = 0
    high_impact_devices: int = 0
    medium_impact_devices: int = 0

    # What this vendor has done before, from the finding store.
    vendor_prior_findings: int = 0
    vendor_prior_signature_failures: int = 0
    vendor_open_findings: int = 0

    # Procurement posture, from the contract.
    contract_software_integrity_clause: Any = "unknown"
    contract_key_rotation_notice_clause: Any = "unknown"

    def as_prompt(self) -> str:
        """Render as compact labelled facts.

        Deliberately not JSON. A 4B model reasons better over short labelled
        lines than over a nested object, and every token spent on braces is a
        token not spent on the facts.
        """
        def yn(value):
            return {True: "YES", False: "NO", None: "UNKNOWN"}.get(value, str(value))

        lines = [
            f"PACKAGE: {self.package_id} ({self.target_model} v{self.version})",
            f"VENDOR: {self.vendor}",
            "",
            "CRYPTOGRAPHIC VERIFICATION (performed by code, on the actual bytes):",
            f"  computed SHA-256 .......... {self.computed_sha256}",
            f"  vendor published SHA-256 .. {self.published_sha256}",
            f"  hash matches .............. {yn(self.hash_match)}",
            f"  Ed25519 signature valid ... {yn(self.signature_verified)}",
            f"  signing key ............... {self.signing_key_id} [{self.signing_key_status}]",
            f"  key fingerprint confirmed   {yn(self.key_fingerprint_confirmed_oob)}",
            f"  verification strength ..... {self.verification_strength}",
            f"  CIP-010 R1.6.1 source id .. {yn(self.source_identity_verified)}",
            f"  CIP-010 R1.6.2 integrity .. {yn(self.integrity_verified)}",
            "",
            "BLAST RADIUS (from the asset inventory):",
            f"  devices running this build  {self.deployed_on_devices}",
            f"  substations affected ...... {self.substations}",
            f"  on high impact systems .... {self.high_impact_devices}",
            f"  on medium impact systems .. {self.medium_impact_devices}",
            "",
            "VENDOR HISTORY (from the finding store):",
            f"  prior findings ............ {self.vendor_prior_findings}",
            f"  prior signature failures .. {self.vendor_prior_signature_failures}",
            f"  currently open findings ... {self.vendor_open_findings}",
            "",
            "PROCUREMENT POSTURE (from the contract):",
            f"  CIP-013 R1.2.5 integrity clause ... {self.contract_software_integrity_clause}",
            f"  key rotation notice clause ........ {self.contract_key_rotation_notice_clause}",
        ]
        if self.failed_controls:
            lines += ["", "CONTROLS THE RULE ENGINE FAILED:"]
            lines += [f"  {c['control_id']} ({c['severity']}) {c['citation']}"
                      for c in self.failed_controls]
        else:
            lines += ["", "CONTROLS THE RULE ENGINE FAILED: none"]
        lines += ["", f"RULE ENGINE VERDICT: {self.deterministic_verdict.upper()}"]
        lines += ["", "VERIFICATION LOG:"] + [f"  - {e}" for e in self.verification_log]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# The judgement
# ---------------------------------------------------------------------------
@dataclass
class Judgment:
    disposition: str = "escalate"
    risk: str = "high"
    reasoning: str = ""
    pattern: str = ""
    recommended_actions: list[str] = field(default_factory=list)
    questions_for_vendor: list[str] = field(default_factory=list)
    confidence: float = 0.0
    backend: str = ""
    model: str = ""
    ok: bool = False
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


SYSTEM = (
    "You are a NERC CIP supply chain analyst for an electric utility. You decide "
    "whether a vendor firmware package may be deployed to grid equipment. You are "
    "given the results of cryptographic verification performed in code, the "
    "controls a rule engine evaluated, how much equipment depends on this build, "
    "and what this vendor has done before. Weigh all of it and reach a judgement. "
    "Be concise and concrete. Never invent a fact that is not in the brief."
)

PROMPT = """{brief}

Decide the disposition for this package.

  block     do not deploy; the package cannot be trusted
  allow     deploy; verification is satisfied and nothing else argues against it
  escalate  a human must look before this moves either way

Guidance, not rules --- you are weighing, not matching:
- A failed signature where the vendor publishes a key is the strongest single
  signal against a package.
- A matching hash does NOT establish that the bytes came from the vendor: an
  attacker who can substitute a binary on a mirror can substitute the digest
  printed beside it.
- Blast radius and vendor history change how urgent something is, and can turn
  an ambiguous case into an escalation.
- A package that verifies cleanly is normally fine. Do not manufacture doubt.

Return ONLY this JSON:
{{"disposition": "block"|"allow"|"escalate",
  "risk": "critical"|"high"|"medium"|"low",
  "reasoning": "<2-3 sentences citing the specific facts you used>",
  "pattern": "<one sentence on vendor history, or empty>",
  "recommended_actions": ["<action>", ...],
  "questions_for_vendor": ["<question>", ...],
  "confidence": 0.0-1.0}}
"""


def _schema(obj: dict) -> str | None:
    if obj.get("disposition") not in DISPOSITIONS:
        return f"disposition must be one of {list(DISPOSITIONS)}"
    if obj.get("risk") not in RISKS:
        return f"risk must be one of {list(RISKS)}"
    if not str(obj.get("reasoning", "")).strip():
        return "reasoning must explain the decision using facts from the brief"
    for key in ("recommended_actions", "questions_for_vendor"):
        if key in obj and not isinstance(obj[key], list):
            return f"{key} must be a list of strings"
    if "confidence" in obj:
        try:
            value = float(obj["confidence"])
        except (TypeError, ValueError):
            return "confidence must be a number between 0 and 1"
        if not 0.0 <= value <= 1.0:
            return "confidence must be between 0 and 1"
    return None


def judge(brief: ReasoningBrief, cfg: RunConfig) -> Judgment:
    """Ask the model for a disposition, reasoning over the whole brief."""
    if not cfg.llm_enabled:
        return _offline_judgment(brief)

    answer = call_json(
        system=SYSTEM,
        prompt=PROMPT.format(brief=brief.as_prompt()),
        cfg=cfg,
        schema_check=_schema,
        task=f"firmware_disposition:{brief.package_id}",
        context={"package_id": brief.package_id, "vendor": brief.vendor},
    )
    if not answer.ok:
        # A model that cannot produce a usable judgement must not silently
        # become an "allow". No answer is an escalation.
        return Judgment(
            disposition="escalate",
            risk="high",
            reasoning=(
                "The model did not return a usable judgement, so this is escalated "
                "rather than decided. The deterministic verdict and the full "
                "verification log are unaffected and appear above."
            ),
            backend=answer.backend,
            model=answer.model,
            ok=False,
            error=answer.error,
        )

    data = answer.data
    return Judgment(
        disposition=str(data["disposition"]),
        risk=str(data["risk"]),
        reasoning=" ".join(str(data.get("reasoning", "")).split()),
        pattern=" ".join(str(data.get("pattern", "")).split()),
        recommended_actions=[str(a) for a in (data.get("recommended_actions") or [])][:6],
        questions_for_vendor=[str(q) for q in (data.get("questions_for_vendor") or [])][:6],
        confidence=float(data.get("confidence", 0.0) or 0.0),
        backend=answer.backend,
        model=answer.model,
        ok=True,
    )


def _offline_judgment(brief: ReasoningBrief) -> Judgment:
    """Deterministic stand-in so the pipeline runs with no model present.

    NOT a model, and labelled `offline-heuristic` wherever it appears. It exists
    so the tests, CI and a laptop with no Ollama can exercise the same path.
    """
    if brief.integrity_verified is True and brief.source_identity_verified is True:
        return Judgment(
            disposition="allow", risk="low",
            reasoning=("Signature verifies against the vendor's active key and the "
                       "published hash matches, so CIP-010 R1.6.1 and R1.6.2 are both "
                       "satisfied for this package."),
            confidence=0.8, backend="offline-heuristic", ok=True)

    if brief.hash_match and brief.signature_verified is False:
        risk = "critical" if brief.high_impact_devices or brief.deployed_on_devices > 50 else "high"
        return Judgment(
            disposition="block", risk=risk,
            reasoning=("The published hash matches but the Ed25519 signature does not "
                       "verify against the vendor's key. A matching hash does not "
                       "establish the bytes came from the vendor, so CIP-010 R1.6.1 is "
                       f"not satisfied. This build is on {brief.deployed_on_devices} devices."),
            pattern=(f"{brief.vendor} has {brief.vendor_prior_signature_failures} prior "
                     f"signature failure(s) on record."
                     if brief.vendor_prior_signature_failures else ""),
            recommended_actions=[
                "Quarantine the binary and do not deploy.",
                "Re-obtain from the vendor's authenticated distribution channel.",
                "Confirm the signing key fingerprint out of band before retrying.",
            ],
            questions_for_vendor=[
                "Was this release re-signed or re-published after the original build?",
                "Has the signing key rotated without notice under CIP-013 R1.2.5?",
            ],
            confidence=0.9, backend="offline-heuristic", ok=True)

    return Judgment(
        disposition="escalate", risk="high",
        reasoning=("Verification could not be completed conclusively, so this needs a "
                   "human before it moves in either direction."),
        confidence=0.5, backend="offline-heuristic", ok=True)


# ---------------------------------------------------------------------------
# Combining the two
# ---------------------------------------------------------------------------
@dataclass
class Decision:
    disposition: str
    decided_by: str
    deterministic: str
    model_disposition: str
    disagreement: bool
    judgment: Judgment

    @property
    def blocks(self) -> bool:
        return self.disposition in ("block", "escalate")


def decide(brief: ReasoningBrief, judgment: Judgment, mode: str = DECIDE_BOTH) -> Decision:
    """Resolve the deterministic verdict and the model's judgement into one call.

    In `both`, either side wanting to stop is enough to stop. That is not the
    code overruling the model --- it is the same rule in both directions, and it
    means the model can block a package the rules would have passed.
    """
    deterministic = brief.deterministic_verdict
    model_says = judgment.disposition

    if mode == DECIDE_CODE:
        final, by = deterministic, "rule engine"
    elif mode == DECIDE_MODEL:
        final, by = model_says, f"model ({judgment.backend})"
    else:
        stop = {"block": 2, "escalate": 1, "allow": 0}
        final = max((deterministic, model_says), key=lambda d: stop.get(d, 0))
        by = "rule engine + model (stricter of the two)"

    return Decision(
        disposition=final,
        decided_by=by,
        deterministic=deterministic,
        model_disposition=model_says,
        disagreement=deterministic != model_says,
        judgment=judgment,
    )


# ---------------------------------------------------------------------------
# Brief assembly
# ---------------------------------------------------------------------------
def build_brief(
    package: dict,
    result: VerificationResult,
    *,
    estate=None,
    failed_controls: list[dict] | None = None,
    store=None,
) -> ReasoningBrief:
    """Gather everything the code knows about one package into a brief."""
    vendor = str(package.get("vendor", ""))
    brief = ReasoningBrief(
        package_id=str(package.get("package_id", "")),
        vendor=vendor,
        target_model=str(package.get("target_model", "")),
        version=str(package.get("version", "")),
        computed_sha256=result.computed_sha256,
        published_sha256=result.published_sha256,
        hash_match=result.hash_match,
        signature_verified=result.signature_verified,
        signing_key_id=result.signing_key_id,
        signing_key_status=result.signing_key_status,
        signing_key_fingerprint=result.signing_key_fingerprint,
        verification_strength=result.verification_strength,
        source_identity_verified=result.source_identity_verified,
        integrity_verified=result.integrity_verified,
        verification_log=list(result.evidence),
        failed_controls=failed_controls or [],
    )
    brief.deterministic_verdict = (
        "allow"
        if result.integrity_verified is True and result.source_identity_verified is True
        else "block"
    )

    if estate is not None:
        deployments = [d for d in estate.deployments
                       if d.get("package_id") == brief.package_id]
        brief.deployed_on_devices = len(deployments)
        brief.substations = len({d.get("substation_id") for d in deployments})
        brief.high_impact_devices = sum(1 for d in deployments if d.get("impact_rating") == "high")
        brief.medium_impact_devices = sum(1 for d in deployments if d.get("impact_rating") == "medium")
        for record in estate.vendors:
            if str(record.get("vendor", "")).lower() == vendor.lower():
                contract = record.get("contract") or {}
                brief.contract_software_integrity_clause = contract.get(
                    "software_integrity_clause", "unknown")
                brief.contract_key_rotation_notice_clause = contract.get(
                    "key_rotation_notice_clause", "unknown")
        key = estate.registry.get(result.signing_key_id)
        if key is not None:
            brief.key_fingerprint_confirmed_oob = key.fingerprint_confirmed_out_of_band

    if store is not None:
        for tracked in store.all():
            if str(tracked.vendor).lower() != vendor.lower():
                continue
            brief.vendor_prior_findings += 1
            if tracked.state == "open":
                brief.vendor_open_findings += 1
            if tracked.control_id in ("CIP-01", "CIP-02", "CIP-03"):
                brief.vendor_prior_signature_failures += 1

    return brief
