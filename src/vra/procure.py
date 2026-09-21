"""Detect a vendor's procurement process from its actual contract documents.

The problem this solves
-----------------------
CIP-013 R1.2.1 through R1.2.6 ask whether your procurement process addresses six
obligations. Until now this tool answered that by reading a boolean somebody
typed into YAML, which moves the work rather than doing it -- a human still had
to read a 90-page master services agreement and decide. That is the manual
bottleneck the product exists to remove.

So the model reads the contract. But the model does not decide anything.

The split, precisely
--------------------
    The model does:      find the clause, return the field it bears on, and
                         quote it verbatim.
    The code does:       verify the quote is really in the document, decide
                         whether the claim may drive a finding, set severity,
                         set the due date, and adjudicate the control.

This is the existing three-tier model (observe.py) with one tier added:

    register   a human wrote it down.                    Drives findings.
    observed   parsed deterministically from a table
               or an API.                                Drives findings.
    extracted  a model read prose AND the quote it gave
               was found in the source document.         Drives findings, capped.  <- new
    proposed   a model said something it could not
               evidence.                                 Never evaluated.

An extracted claim whose quote does not appear in the document is not a
near-miss to be cleaned up. It is demoted to `proposed` and sent to
pending_review, because a model that paraphrases is a model that could equally
have invented the clause.

Two rules that are not negotiable
---------------------------------
1. **Presence can be evidenced. Absence cannot.**
   The model can quote MSA 9.1 to show an incident-notification clause exists.
   It cannot quote anything to show a clause is *missing* -- an absence has no
   text. So a model reporting "this clause is not present" never produces
   `False`, which would be a control failure. It produces `unknown`, which is an
   information gap with a response date and a drafted question to the vendor.
   Getting this backwards would let a model fail a vendor on a clause it simply
   did not find, in a document it may have only partly read.

2. **A verified extraction may not raise a critical on its own.**
   Quote verification proves the text exists. It does not prove the model read
   the scope right: a definition in an exhibit, an obligation that applies to a
   different product line, or a clause that was struck in an amendment all quote
   perfectly. So anything that would raise a critical is routed to
   pending_review for ratification and recorded as a gap in the meantime. Highs
   and below stand on their own. This is the one irreversible call that keeps a
   human.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .config import PENDING_REVIEW_DIR, RunConfig, reserve_path
from .llm import LLMResult, call_json

# The six CIP-013 R1.2 obligations plus the R1.1 planning process, expressed as
# the register fields they set. Adding a clause here is what teaches the
# extractor a new obligation; the control file decides what to do about it.
CLAUSE_TARGETS: list[dict[str, Any]] = [
    {
        "field": "contract.incident_notification_clause",
        "requirement": "CIP-013 R1.2.1",
        "asks": "an obligation on the vendor to NOTIFY the entity of vendor-identified "
                "security incidents affecting the products or services supplied",
        "window_field": "contract.incident_notification_hours",
        "window_unit": "hours",
    },
    {
        "field": "contract.incident_coordination_clause",
        "requirement": "CIP-013 R1.2.2",
        "asks": "an obligation to COORDINATE incident response with the entity — named "
                "contacts, joint response, or cooperation with the entity's process",
    },
    {
        "field": "contract.access_termination_notice_clause",
        "requirement": "CIP-013 R1.2.3",
        "asks": "an obligation on the vendor to NOTIFY the entity when a vendor "
                "representative should no longer be granted remote or onsite access — "
                "for example on departure or reassignment. An internal offboarding "
                "process is NOT this obligation unless it commits the vendor to notify.",
    },
    {
        "field": "contract.vulnerability_disclosure_clause",
        "requirement": "CIP-013 R1.2.4",
        "asks": "an obligation to DISCLOSE known vulnerabilities in the products or "
                "services supplied",
        "window_field": "contract.vulnerability_disclosure_days",
        "window_unit": "days",
    },
    {
        "field": "contract.software_integrity_clause",
        "requirement": "CIP-013 R1.2.5",
        "asks": "an obligation to provide a method to VERIFY SOFTWARE INTEGRITY AND "
                "AUTHENTICITY of software, firmware or patches — a signature, a "
                "published hash, or a code signing key",
    },
    {
        "field": "contract.remote_access_coordination_clause",
        "requirement": "CIP-013 R1.2.6",
        "asks": "coordinated controls for vendor-initiated Interactive Remote Access "
                "and system-to-system remote access",
    },
    {
        "field": "contract.vendor_transition_clause",
        "requirement": "CIP-013 R1.1(ii)",
        "asks": "an obligation covering TRANSITION away from this vendor — transition "
                "assistance, return or transfer of configuration baselines, or "
                "documentation needed to replace the supplied equipment",
    },
    {
        "field": "contract.key_rotation_notice_clause",
        "requirement": "CIP-013 R1.2.5",
        "asks": "an obligation to notify the entity before rotating, or upon "
                "compromise of, a code signing key",
    },
]

CLAUSE_BY_FIELD = {c["field"]: c for c in CLAUSE_TARGETS}

# Fields whose failure would raise a critical control. A verified extraction may
# not set these to False on its own; see rule 2 in the module docstring. Derived
# from cip_controls.yaml at call time rather than hardcoded here, but this is the
# fallback if the control set cannot be read.
DEFAULT_CRITICAL_FIELDS = {"contract.software_integrity_clause"}


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------
@dataclass
class SourceDocument:
    name: str
    path: str
    text: str

    @property
    def normalized(self) -> str:
        return normalize(self.text)


def normalize(text: str) -> str:
    """Collapse whitespace and case for quote comparison.

    Contract text wraps at inconsistent widths and a model reflows what it
    quotes. Comparing raw strings would reject correct quotes for whitespace
    reasons, which would push genuine extractions into pending_review and make
    the reviewer stop trusting the queue.
    """
    return " ".join(str(text or "").split()).lower()


def load_documents(path: Path) -> list[SourceDocument]:
    """Read every readable document under `path`.

    PDFs are read through pypdf when available. A PDF that yields no text is
    kept with empty text rather than skipped, so the caller can report it as
    unreadable instead of silently assessing a vendor on a partial document set.
    """
    if path.is_file():
        candidates = [path]
    else:
        candidates = sorted(
            p for p in path.rglob("*")
            if p.is_file() and p.suffix.lower() in (".txt", ".md", ".html", ".htm", ".pdf")
        )

    docs: list[SourceDocument] = []
    for candidate in candidates:
        if candidate.name == "README.md":
            continue  # repository notes, not vendor evidence
        docs.append(
            SourceDocument(
                name=candidate.name,
                path=str(candidate),
                text=_read_text(candidate),
            )
        )
    return docs


def _read_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        try:
            import logging

            from pypdf import PdfReader

            # A scanned or malformed PDF is an expected input here -- the caller
            # reports it as unreadable. pypdf writes its complaint to the root
            # logger, which would put "EOF marker not found" in the middle of a
            # clean run for a case the code already handles.
            logging.getLogger("pypdf").setLevel(logging.ERROR)
            return "\n".join((page.extract_text() or "") for page in PdfReader(str(path)).pages)
        except Exception:  # noqa: BLE001 — an unreadable PDF is data, not a crash
            return ""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if suffix in (".html", ".htm"):
        raw = re.sub(r"(?is)<(script|style).*?</\1>", " ", raw)
        raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    return raw


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------
@dataclass
class ExtractedClaim:
    """One model reading of one clause, and what the code decided about it."""

    field: str
    requirement: str
    present: bool | None          # what the model said
    quote: str
    source_document: str = ""
    confidence: float = 0.0
    rationale: str = ""

    # Set by code, never by the model.
    quote_verified: bool = False
    tier: str = "proposed"        # extracted | proposed
    applied_value: Any = None     # what actually reaches the register
    withheld_reason: str = ""
    backend: str = ""
    # Where this obligation fell in the prioritised reading order. Recorded so
    # the evidence shows what the model was asked to look at first; it has no
    # effect on adjudication.
    read_rank: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "requirement": self.requirement,
            "model_said_present": self.present,
            "quote": self.quote,
            "source_document": self.source_document,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "quote_verified": self.quote_verified,
            "tier": self.tier,
            "applied_value": self.applied_value,
            "withheld_reason": self.withheld_reason,
            "backend": self.backend,
            "read_rank": self.read_rank,
        }


@dataclass
class ProcurementExtraction:
    vendor: str
    vendor_slug: str
    documents: list[str] = field(default_factory=list)
    unreadable_documents: list[str] = field(default_factory=list)
    claims: list[ExtractedClaim] = field(default_factory=list)
    backend: str = ""
    footprint: "VendorFootprint | None" = None
    reading_order: list[str] = field(default_factory=list)

    @property
    def applied(self) -> list[ExtractedClaim]:
        return [c for c in self.claims if c.tier == "extracted"]

    @property
    def withheld(self) -> list[ExtractedClaim]:
        return [c for c in self.claims if c.tier == "proposed"]

    def summary(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "documents_read": len(self.documents),
            "unreadable": len(self.unreadable_documents),
            "clauses_examined": len(self.claims),
            "quotes_verified": sum(1 for c in self.claims if c.quote_verified),
            "applied_to_register": len(self.applied),
            "withheld_for_review": len(self.withheld),
            "backend": self.backend,
        }

    def register_contract_block(self) -> dict[str, Any]:
        """The `contract:` block this extraction produces.

        Only fields the code decided to apply appear here. Everything else is
        simply absent, which the evaluator already treats as unknown -- an
        information gap rather than a failure.
        """
        out: dict[str, Any] = {}
        for claim in self.applied:
            key = claim.field.split(".", 1)[1] if "." in claim.field else claim.field
            out[key] = claim.applied_value
        return out


# ---------------------------------------------------------------------------
# Verification — the code half
# ---------------------------------------------------------------------------
def verify_quote(quote: str, documents: list[SourceDocument]) -> tuple[bool, str]:
    """Is this quote really in one of these documents?

    Returns (verified, document name). The prompt asks for verbatim text; asking
    is not a control. A model that reflows or paraphrases puts its own prose into
    a finding's evidence block under the vendor's name, and a model that invents
    a clause manufactures compliance.

    A quote must be long enough to mean something -- a model returning "Supplier
    shall" would otherwise verify against almost any contract.
    """
    needle = normalize(quote)
    if len(needle) < 40:
        return False, ""
    for doc in documents:
        if needle in doc.normalized:
            return True, doc.name
    return False, ""


def critical_fields_from_controls(controls: list) -> set[str]:
    """Which register fields drive a critical control.

    Read from the control set rather than hardcoded, so re-rating a control in
    YAML also moves the extraction ceiling. If the severity of CIP-12 is lowered
    to high, extraction is allowed to decide it -- and the reverse.
    """
    fields: set[str] = set()
    for control in controls or []:
        if control.severity != "critical":
            continue
        for cond in list(control.fails_when) + list(control.gap_when):
            name = cond.get("field", "")
            if name.startswith("contract."):
                fields.add(name)
    return fields or set(DEFAULT_CRITICAL_FIELDS)


def adjudicate(
    claims: list[ExtractedClaim],
    documents: list[SourceDocument],
    *,
    critical_fields: set[str],
) -> None:
    """Decide, in code, what each model claim is allowed to do.

    Mutates the claims in place. This function is the entire safety boundary
    between "a model read a contract" and "a control failed", and it is
    deliberately short enough to read in one sitting.
    """
    for claim in claims:
        claim.quote_verified, claim.source_document = verify_quote(claim.quote, documents)

        # Rule 1: absence cannot be evidenced.
        if claim.present is not True:
            claim.tier = "proposed"
            claim.applied_value = None
            claim.withheld_reason = (
                "the model reported this clause as not present. An absence has no text to "
                "quote, so it is recorded as an unanswered question for the vendor rather "
                "than as a failed control."
            )
            continue

        if not claim.quote_verified:
            claim.tier = "proposed"
            claim.applied_value = None
            claim.withheld_reason = (
                "the quote the model gave was not found in any source document. A claim "
                "that cannot be located is treated as unevidenced, not as a near miss."
            )
            continue

        # Rule 2: a verified extraction may not settle a critical on its own.
        if claim.field in critical_fields:
            claim.tier = "proposed"
            claim.applied_value = None
            claim.withheld_reason = (
                f"{claim.field} drives a critical control. The quote was verified, but "
                f"verification proves the text exists — not that its scope was read "
                f"correctly. Routed for human ratification."
            )
            continue

        claim.tier = "extracted"
        claim.applied_value = True


# ---------------------------------------------------------------------------
# Extraction — the model half
# ---------------------------------------------------------------------------
SYSTEM = (
    "You are a contract analyst reading vendor procurement documents for an electric "
    "utility subject to NERC CIP-013. You locate clauses and quote them. You do not "
    "judge compliance, assign severity, or decide whether anything is acceptable."
)

PROMPT = """Read the vendor documents below and determine whether they contain an
obligation matching the description.

WHAT THIS VENDOR SUPPLIES (from the asset inventory — context only; it does not
change what counts as an obligation, and you must not treat a large footprint as
a reason to read a clause more generously):
{estate_context}

OBLIGATION SOUGHT ({requirement}):
{asks}

RULES:
- Quote VERBATIM from the documents. Do not reflow, summarise, or paraphrase.
- The quote must be at least one full sentence and copied exactly.
- If you cannot find the obligation, set present=false and leave quote empty.
- A statement describing the vendor's internal process is NOT an obligation to
  the customer unless it commits the vendor to do something for the customer.
- Do not infer an obligation from a definition or a heading.

Return ONLY this JSON:
{{"present": true|false, "quote": "<verbatim text or empty>",
  "confidence": 0.0-1.0, "rationale": "<one sentence>"}}

DOCUMENTS:
{documents}
"""


def extract_procurement(
    vendor: str,
    vendor_slug: str,
    documents: list[SourceDocument],
    cfg: RunConfig,
    *,
    controls: list | None = None,
    footprint: "VendorFootprint | None" = None,
) -> ProcurementExtraction:
    """Read the documents and produce adjudicated claims.

    `footprint` is machine-derived context about what this vendor supplies. It
    changes what the model is told and the order it reads in. It cannot change
    what happens to a claim afterwards.
    """
    readable = [d for d in documents if d.text.strip()]
    result = ProcurementExtraction(
        vendor=vendor,
        vendor_slug=vendor_slug,
        documents=[d.name for d in readable],
        unreadable_documents=[d.name for d in documents if not d.text.strip()],
    )
    if not readable:
        return result

    blob = "\n\n".join(f"--- {d.name} ---\n{d.text}" for d in readable)
    claims: list[ExtractedClaim] = []
    backend = ""
    estate_context = footprint.as_prompt_context() if footprint else ""
    result.footprint = footprint
    result.reading_order = [t["field"] for t in reading_order(footprint)]

    for rank, target in enumerate(reading_order(footprint), start=1):
        if cfg.llm_enabled:
            answer = call_json(
                system=SYSTEM,
                prompt=PROMPT.format(
                    requirement=target["requirement"],
                    asks=target["asks"],
                    estate_context=estate_context or "(no estate context available)",
                    documents=blob[:60000],
                ),
                cfg=cfg,
                schema_check=_clause_schema,
                task=f"procurement_clause:{target['field']}",
                context={"field": target["field"], "requirement": target["requirement"]},
            )
            data, backend = (answer.data or {}), answer.backend
            if not answer.ok:
                data = {}
        else:
            data, backend = _offline_extract(target, readable), "offline-heuristic"

        claims.append(
            ExtractedClaim(
                field=target["field"],
                requirement=target["requirement"],
                present=bool(data.get("present")) if "present" in data else None,
                quote=str(data.get("quote") or ""),
                confidence=_as_float(data.get("confidence")),
                rationale=str(data.get("rationale") or ""),
                backend=backend,
                read_rank=rank,
            )
        )

    result.claims = claims
    result.backend = backend
    adjudicate(claims, readable, critical_fields=critical_fields_from_controls(controls or []))
    return result


def _clause_schema(obj: dict) -> str | None:
    """Reject a malformed clause answer before it reaches adjudication.

    A small local model (Gemma 4B, for instance) will sometimes return prose, a
    code fence, or a partial object. call_json retries with the rejection reason
    attached, so a schema that names the problem precisely is what turns a bad
    first answer into a good second one.
    """
    if "present" not in obj:
        return "missing key: present"
    if not isinstance(obj["present"], bool):
        return "present must be a boolean (true or false), not a string"
    if obj["present"] and not str(obj.get("quote", "")).strip():
        return "present is true, so quote must contain the verbatim clause text"
    if "confidence" in obj:
        try:
            value = float(obj["confidence"])
        except (TypeError, ValueError):
            return "confidence must be a number between 0 and 1"
        if not 0.0 <= value <= 1.0:
            return "confidence must be between 0 and 1"
    return None


def _as_float(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# Offline extractor
# ---------------------------------------------------------------------------
# Keyword signatures per clause. This is NOT a model. It exists so the pipeline,
# the tests and CI run end to end without pulling a 7B model, and everything it
# produces is labelled `offline-heuristic` so nobody mistakes it for one.
#
# It is held to exactly the same rules as the model: it must return a real
# verbatim sentence from the document, and that sentence goes through the same
# verify_quote check. A heuristic that could bypass verification would make the
# whole safety boundary untested in CI, which is where it matters most.
OFFLINE_SIGNATURES: dict[str, tuple[tuple[str, ...], ...]] = {
    "contract.incident_notification_clause": (("notify", "incident"),),
    "contract.incident_coordination_clause": (("incident response", "cooperate"),
                                              ("incident response", "coordinat"),
                                              ("joint response",)),
    "contract.access_termination_notice_clause": (("notify", "no longer", "access"),
                                                  ("notify", "access should", "revoke")),
    "contract.vulnerability_disclosure_clause": (("disclose", "vulnerabilit"),),
    "contract.software_integrity_clause": (("signature", "sha-256"),
                                           ("code signing", "integrity")),
    "contract.remote_access_coordination_clause": (("remote access", "terminate"),
                                                   ("interactive remote access",)),
    "contract.vendor_transition_clause": (("transition assistance",),
                                          ("transition", "configuration baselines")),
    "contract.key_rotation_notice_clause": (("signing key", "rotation"),
                                            ("code signing key", "compromise")),
}


def _sentences(text: str) -> list[str]:
    # Contract numbering ("9.1", "Section 14.4") defeats a naive split on ".",
    # so sentence ends are only counted when followed by whitespace and a
    # capital or newline.
    parts = re.split(r"(?<=[.;])\s+(?=[A-Z\n])", text)
    return [" ".join(p.split()) for p in parts if len(p.split()) > 6]


def _offline_extract(target: dict, documents: list[SourceDocument]) -> dict[str, Any]:
    signatures = OFFLINE_SIGNATURES.get(target["field"], ())
    for doc in documents:
        for sentence in _sentences(doc.text):
            low = sentence.lower()
            for signature in signatures:
                if all(token in low for token in signature):
                    return {
                        "present": True,
                        "quote": sentence,
                        "confidence": 0.6,
                        "rationale": f"heuristic matched {'+'.join(signature)}",
                    }
    return {
        "present": False,
        "quote": "",
        "confidence": 0.5,
        "rationale": "heuristic found no matching sentence",
    }


# ---------------------------------------------------------------------------
# Review queue
# ---------------------------------------------------------------------------
def write_pending_review(
    extraction: ProcurementExtraction, *, when: date | None = None, root: Path | None = None
) -> Path | None:
    """Queue everything the code refused to apply, with the reason.

    A review queue that only says "please check" wastes the reviewer's time. Each
    entry carries what the model said, whether the quote was found, and which
    rule withheld it, so ratifying or rejecting is a decision rather than a
    re-investigation.
    """
    withheld = extraction.withheld
    if not withheld:
        return None
    when = when or date.today()
    directory = root or PENDING_REVIEW_DIR
    directory.mkdir(parents=True, exist_ok=True)
    path = reserve_path(directory / f"procurement-{extraction.vendor_slug}-{when.isoformat()}.json")
    path.write_text(
        json.dumps(
            {
                "vendor": extraction.vendor,
                "vendor_slug": extraction.vendor_slug,
                "generated_on": when.isoformat(),
                "backend": extraction.backend,
                "documents": extraction.documents,
                "note": (
                    "These claims were NOT applied to the register and did not drive any "
                    "finding. A human ratifies or rejects each one."
                ),
                "items": [c.as_dict() for c in withheld],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Prioritized reading — machine context, without moving the boundary
# ---------------------------------------------------------------------------
# The model used to read a contract knowing nothing about the vendor. That is
# wasteful: a supplier of four relays at one low-impact distribution substation
# and a supplier of nine hundred relays across the 500 kV backbone get the same
# attention on the same eight clauses, in the same arbitrary order.
#
# So the model is told what the estate knows before it reads: how many devices
# this vendor supplies, at what CIP-002 impact ratings, and whether the entity
# actually holds a signing key for them. It then reads the obligations that
# carry the most weight for THAT footprint first.
#
# What this deliberately does NOT do
# ----------------------------------
# The footprint changes what the model is told and the ORDER it reads in.
# It cannot change what happens to a claim afterwards. Every claim still goes
# through verify_quote and adjudicate() with identical rules, and the severity
# ceiling still comes from the control set. A vendor with a large footprint does
# not get its claims accepted more easily, and a small one does not get them
# refused -- that would make the footprint an input to a decision, which is
# exactly the boundary this design exists to hold.
#
# tests/test_cip_onboarding.py asserts this directly: the same documents under
# opposite footprints produce the same adjudicated result.

# Base weight per obligation, before the footprint adjusts it. Software
# integrity leads because it is the clause that makes CIP-010 R1.6 operable at
# all; a contract missing it means every release from this vendor is
# unverifiable no matter what else is agreed.
BASE_PRIORITY: dict[str, int] = {
    "contract.software_integrity_clause": 100,
    "contract.remote_access_coordination_clause": 80,
    "contract.access_termination_notice_clause": 70,
    "contract.vulnerability_disclosure_clause": 60,
    "contract.incident_notification_clause": 50,
    "contract.key_rotation_notice_clause": 40,
    "contract.incident_coordination_clause": 30,
    "contract.vendor_transition_clause": 20,
}


@dataclass
class VendorFootprint:
    """What the estate already knows about a vendor, computed from machine data.

    Every field here comes from the asset inventory or the key registry. None of
    it is asked of a human and none of it is asked of the model.
    """

    vendor: str
    devices: int = 0
    substations: int = 0
    high_impact_devices: int = 0
    medium_impact_devices: int = 0
    deployments: int = 0
    packages: int = 0
    publishes_signing_key: bool = False
    trusted_key_ids: list[str] = field(default_factory=list)

    @property
    def max_impact(self) -> str:
        if self.high_impact_devices:
            return "high"
        if self.medium_impact_devices:
            return "medium"
        return "low"

    @property
    def in_scope_devices(self) -> int:
        return self.high_impact_devices + self.medium_impact_devices

    def priority(self, field_name: str) -> int:
        """Rank one obligation for this vendor. Higher is read first."""
        score = BASE_PRIORITY.get(field_name, 10)

        # A vendor whose equipment sits on high-impact systems raises the stakes
        # on everything, because that is where CIP-013 obligations attach most
        # heavily and where a bad firmware flash has the largest consequence.
        if self.max_impact == "high":
            score += 25
        elif self.max_impact == "medium":
            score += 10

        # The entity holds no key for this vendor, so CIP-010 R1.6.1 is
        # currently unevaluable for every release it ships. Finding out whether
        # the contract even obliges them to provide one is the single most
        # useful thing to establish.
        if not self.publishes_signing_key and field_name in (
            "contract.software_integrity_clause",
            "contract.key_rotation_notice_clause",
        ):
            score += 60

        # A large deployed base makes disclosure and notification timing matter
        # more: the same unpatched vulnerability is on more devices.
        if self.deployments >= 100 and field_name in (
            "contract.vulnerability_disclosure_clause",
            "contract.incident_notification_clause",
        ):
            score += 15

        return score

    def as_prompt_context(self) -> str:
        """The block handed to the model before it reads.

        Stated as facts about the estate, with no instruction about what to
        conclude. The model is being told where it is, not what to find.
        """
        if not self.devices and not self.deployments:
            return (
                f"{self.vendor} has no equipment in service in this estate yet. "
                f"This is a pre-procurement review."
            )
        key = (
            f"The entity holds a trusted signing key for this vendor "
            f"({', '.join(self.trusted_key_ids)})."
            if self.publishes_signing_key
            else "The entity holds NO trusted signing key for this vendor."
        )
        return (
            f"{self.vendor} supplies {self.devices} cyber assets across "
            f"{self.substations} substations in this estate: "
            f"{self.high_impact_devices} on high impact BES Cyber Systems and "
            f"{self.medium_impact_devices} on medium impact. "
            f"{self.deployments} firmware deployments draw on {self.packages} "
            f"distinct releases from this vendor. {key}"
        )


def footprint_from_estate(vendor: str, estate) -> VendorFootprint:
    """Derive a footprint from the asset inventory and the key registry."""
    low = vendor.strip().lower()
    devices = [d for d in estate.devices if str(d.get("vendor", "")).strip().lower() == low]
    deployments = [
        d for d in estate.deployments if str(d.get("vendor", "")).strip().lower() == low
    ]
    active = [k for k in estate.registry.for_vendor(vendor) if k.status == "active"]
    return VendorFootprint(
        vendor=vendor,
        devices=len(devices),
        substations=len({d.get("substation_id") for d in devices}),
        high_impact_devices=sum(1 for d in devices if d.get("impact_rating") == "high"),
        medium_impact_devices=sum(1 for d in devices if d.get("impact_rating") == "medium"),
        deployments=len(deployments),
        packages=len({d.get("package_id") for d in deployments}),
        publishes_signing_key=bool(active),
        trusted_key_ids=[k.key_id for k in active],
    )


def reading_order(footprint: VendorFootprint | None) -> list[dict[str, Any]]:
    """The clause targets, highest-stakes first for this vendor.

    Every target is always returned. Prioritisation changes the order, never the
    coverage -- silently skipping an obligation because it scored low would be a
    gap the report could not see.
    """
    if footprint is None:
        return list(CLAUSE_TARGETS)
    return sorted(CLAUSE_TARGETS, key=lambda t: -footprint.priority(t["field"]))
