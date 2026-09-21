"""NERC CIP assessment over the substation estate.

Reuses the existing deterministic evaluator wholesale. `evaluate_condition`,
the severity policy, the due-date table and the finding record shape are the
same ones the AIV-* and NHI-* sets have always used, so a NERC finding is
produced by exactly the machinery that already had to survive the question
"why did this fail?". The answer stays "a condition in a YAML file plus a field
on a subject", and for the firmware controls that field is the result of a
cryptographic operation recorded in the evidence.

The model is not involved at any point in this file.

Four subjects
-------------
    firmware_deployment   one per device running a vendor firmware package
    procurement           one per vendor (CIP-013 R1/R2/R3 contract layer)
    vendor_access         one per vendor remote access session into an ESP
    vendor_personnel      one per vendor representative holding ESP access

Each control names its subject in cip_controls.yaml. Nothing here maps control
ids to collections; adding a control is a YAML edit.

Applicability
-------------
Every control is scoped by `applies_when`, and nearly all of them start with
`impact_rating in [high, medium]`. That is CIP-002 doing its job. Roughly 89%
of the estate is low impact, so a run that ignored applicability would produce
an order of magnitude more findings, almost all of them wrong.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable

from .cipcrypto import VerificationResult
from .config import CIP_CONTROLS_FILE
from .evaluate import Assessment, Control, evaluate_condition, load_controls, to_record
from .grid import Estate

SUBJECTS = ("firmware_deployment", "procurement", "vendor_access", "vendor_personnel")


def cip_citation(control: Control) -> str:
    """NERC citation as an auditor writes it: CIP-010-4 R1 Part 1.6.2.

    Control.citation already handles the standard/version/requirement/part
    shape. Kept as a named function because the CIP code and the evidence pack
    read better asking for a citation than reaching for a property.
    """
    return control.citation


def citations_verified(controls: list[Control]) -> tuple[int, int]:
    """(verified, total) framework citations across the control set."""
    total = verified = 0
    for control in controls:
        for fw in control.frameworks:
            total += 1
            if fw.get("citation_verified") is True:
                verified += 1
    return verified, total


def load_cip_controls(path: Path | None = None) -> list[Control]:
    controls = load_controls(path or CIP_CONTROLS_FILE)
    unknown = sorted({c.subject for c in controls} - set(SUBJECTS))
    if unknown:
        # A control with a subject nothing iterates would be silently skipped
        # forever, which reads as a passing control. Fail loudly instead.
        raise ValueError(f"cip_controls.yaml names unknown subject(s): {unknown}")
    return controls


# ---------------------------------------------------------------------------
# Subject construction
# ---------------------------------------------------------------------------
def firmware_subjects(
    estate: Estate, verified: dict[str, VerificationResult]
) -> Iterable[tuple[dict, dict, VerificationResult | None]]:
    """Yield (subject, container, verification) per firmware deployment.

    The cryptographic outcome is merged onto the deployment so the control file
    can score it with ordinary operators. `model_match` is computed here rather
    than in the verification cache because it is the one fact that depends on
    the device rather than on the package.
    """
    for dep in estate.deployments:
        result = verified.get(dep["package_id"])
        package = estate.packages.get(dep["package_id"], {})
        subject = dict(dep)
        if result is not None:
            subject.update(result.as_fields())
        target_model = package.get("target_model")
        subject["target_model"] = target_model
        subject["model_match"] = (
            None if not target_model else target_model == dep.get("device_model")
        )
        subject["package_version"] = package.get("version")
        yield subject, {}, result


def procurement_subjects(estate: Estate) -> Iterable[tuple[dict, dict, None]]:
    """Yield (subject, container) per vendor.

    The container is the vendor record itself so that `contract.*` field paths
    in the control file resolve through the evaluator's existing prefix
    handling -- the same mechanism the AIV-* set uses for `contract.baa_on_file`.

    `vendor_publishes_signing_key` is computed here rather than recorded,
    following the same rule as the firmware fields: it is a fact about the key
    registry, so asking a human to assert it would let the register drift away
    from what the tool can actually verify. It is what CIP-30 uses to tell a
    contract clause apart from a working control.
    """
    for vendor in estate.vendors:
        subject = dict(vendor)
        active = [
            k for k in estate.registry.for_vendor(str(vendor.get("vendor", "")))
            if k.status == "active"
        ]
        subject["vendor_publishes_signing_key"] = bool(active)
        subject["trusted_key_ids"] = [k.key_id for k in active]
        yield subject, vendor, None


def access_subjects(estate: Estate) -> Iterable[tuple[dict, dict, None]]:
    for session in estate.access_sessions:
        yield dict(session), {}, None


def personnel_subjects(estate: Estate) -> Iterable[tuple[dict, dict, None]]:
    for person in estate.personnel:
        yield dict(person), {}, None


SUBJECT_LABEL = {
    "firmware_deployment": ("deployment_id", "device_id"),
    "procurement": ("contract_id", "vendor_slug"),
    "vendor_access": ("session_id", "session_id"),
    "vendor_personnel": ("person_id", "person_id"),
}


def _label(subject_kind: str, subject: dict) -> tuple[str, str]:
    primary, secondary = SUBJECT_LABEL[subject_kind]
    return str(subject.get(primary, "(unidentified)")), str(subject.get(secondary, ""))


def _observed(conds: list[dict], subject: dict, container: dict) -> dict[str, Any]:
    from .evaluate import MISSING, resolve_field

    out: dict[str, Any] = {}
    for cond in conds:
        val = resolve_field(subject, container, cond["field"])
        out[cond["field"]] = "<not recorded>" if val is MISSING else val
    return out


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------
@dataclass
class Coverage:
    """Per-control tally of what was actually examined.

    An audit does not ask only what failed. It asks what population was in
    scope, how many of them were examined, and how many passed -- a report
    listing 131 exceptions with no denominator is not evidence of anything. So
    every control records the number of subjects it applied to, and passes are
    counted rather than inferred from the absence of a finding.
    """

    control_id: str
    subject: str
    severity: str
    citation: str
    in_population: int = 0   # subjects of this kind that exist at all
    applicable: int = 0      # subjects that passed applies_when
    failed: int = 0
    gapped: int = 0
    passed: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "subject": self.subject,
            "severity": self.severity,
            "citation": self.citation,
            "in_population": self.in_population,
            "applicable": self.applicable,
            "not_applicable": self.in_population - self.applicable,
            "failed": self.failed,
            "gapped": self.gapped,
            "passed": self.passed,
        }


def assess_estate(
    estate: Estate,
    controls: list[Control] | None = None,
    *,
    when: date | None = None,
) -> tuple[list[Assessment], list[Assessment], dict[str, VerificationResult], dict[str, Coverage]]:
    """Score the whole estate.

    Returns (findings, gaps, verification results, per-control coverage).
    """
    when = when or date.today()
    controls = controls or load_cip_controls()
    verified = estate.verify_all(when=when)

    by_subject: dict[str, list[Control]] = {}
    for control in controls:
        by_subject.setdefault(control.subject, []).append(control)

    streams = {
        "firmware_deployment": lambda: firmware_subjects(estate, verified),
        "procurement": lambda: procurement_subjects(estate),
        "vendor_access": lambda: access_subjects(estate),
        "vendor_personnel": lambda: personnel_subjects(estate),
    }

    findings: list[Assessment] = []
    gaps: list[Assessment] = []
    coverage: dict[str, Coverage] = {
        c.id: Coverage(
            control_id=c.id,
            subject=c.subject,
            severity=c.severity,
            citation=cip_citation(c),
        )
        for c in controls
    }

    for subject_kind, subject_controls in by_subject.items():
        for subject, container, result in streams[subject_kind]():
            feature, disambiguator = _label(subject_kind, subject)
            provenance = _provenance_for(result)
            for control in subject_controls:
                coverage[control.id].in_population += 1
                if control.applies_when:
                    applies = [
                        evaluate_condition(c, subject, container) for c in control.applies_when
                    ]
                    if not all(a is True for a in applies):
                        continue
                coverage[control.id].applicable += 1

                fail_results = [
                    evaluate_condition(c, subject, container) for c in control.fails_when
                ]
                fails = bool(fail_results) and all(r is True for r in fail_results)

                if fails:
                    coverage[control.id].failed += 1
                    findings.append(
                        Assessment(
                            kind="finding",
                            vendor=str(subject.get("vendor_slug", "")),
                            vendor_name=str(subject.get("vendor", "")),
                            feature=feature,
                            control=control,
                            observed=_observed(control.fails_when, subject, container),
                            reason="all failure conditions met",
                            subject=disambiguator,
                            provenance=provenance,
                        )
                    )
                    continue

                gap_results = [evaluate_condition(c, subject, container) for c in control.gap_when]
                # A fail condition that could not be evaluated because its field
                # is unknown is a gap, not a pass. Treating an unevaluable
                # critical as clean is how a control goes quiet for a year.
                unknown_blocks_eval = any(r is None for r in fail_results)
                if any(r is True for r in gap_results) or unknown_blocks_eval:
                    coverage[control.id].gapped += 1
                    conds = control.gap_when or control.fails_when
                    gaps.append(
                        Assessment(
                            kind="gap",
                            vendor=str(subject.get("vendor_slug", "")),
                            vendor_name=str(subject.get("vendor", "")),
                            feature=feature,
                            control=control,
                            observed=_observed(conds, subject, container),
                            reason="required field is unknown; cannot evaluate control",
                            subject=disambiguator,
                            provenance=provenance,
                        )
                    )
                else:
                    coverage[control.id].passed += 1

    return findings, gaps, verified, coverage


def _provenance_for(result: VerificationResult | None) -> dict[str, dict]:
    """Attach the cryptographic working to findings that rest on it.

    Without this a firmware finding looks like every other YAML-driven finding.
    With it, the report can show the SHA-256 it computed and the signature
    verification it performed, which is the difference between an assertion and
    evidence.
    """
    if result is None or not result.evidence:
        return {}
    return {
        "firmware_verification": {
            "value": result.package_id,
            "provenance": f"cryptographic_verification:{result.verification_strength}",
            "evidence": " | ".join(result.evidence),
        }
    }


# ---------------------------------------------------------------------------
# Rollup
# ---------------------------------------------------------------------------
def rollup(findings: list[Assessment], gaps: list[Assessment]) -> dict[str, Any]:
    """Portfolio view. At 1,300 sites nobody reads a per-device list."""
    by_severity: dict[str, int] = {}
    by_control: dict[str, int] = {}
    by_standard: dict[str, int] = {}
    affected_substations: set[str] = set()

    for a in findings:
        by_severity[a.control.severity] = by_severity.get(a.control.severity, 0) + 1
        by_control[a.control.id] = by_control.get(a.control.id, 0) + 1
        for fw in a.control.frameworks:
            std = str(fw.get("standard", fw.get("name", "?")))
            by_standard[std] = by_standard.get(std, 0) + 1
        sub = a.observed.get("substation_id")
        if sub:
            affected_substations.add(str(sub))

    return {
        "findings": len(findings),
        "gaps": len(gaps),
        "by_severity": by_severity,
        "by_control": dict(sorted(by_control.items())),
        "by_standard": dict(sorted(by_standard.items())),
        "critical": by_severity.get("critical", 0),
    }


def records(assessments: list[Assessment]) -> list[dict]:
    return [to_record(a, evidence=[]) for a in assessments]
