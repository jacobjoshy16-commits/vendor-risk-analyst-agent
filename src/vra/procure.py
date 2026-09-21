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
        }


@dataclass
class ProcurementExtraction:
    vendor: str
    vendor_slug: str
    documents: list[str] = field(default_factory=list)
    unreadable_documents: list[str] = field(default_factory=list)
    claims: list[ExtractedClaim] = field(default_factory=list)
    backend: str = ""

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
) -> ProcurementExtraction:
    """Read the documents and produce adjudicated claims."""
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

    for target in CLAUSE_TARGETS:
        if cfg.llm_enabled:
            answer = call_json(
                SYSTEM,
                PROMPT.format(
                    requirement=target["requirement"],
                    asks=target["asks"],
                    documents=blob[:60000],
                ),
                cfg,
                task=f"procurement_clause:{target['field']}",
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
            )
        )

    result.claims = claims
    result.backend = backend
    adjudicate(claims, readable, critical_fields=critical_fields_from_controls(controls or []))
    return result


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
