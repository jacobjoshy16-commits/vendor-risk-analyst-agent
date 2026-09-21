"""`vra.py cip onboard` — take a new vendor from documents to a scored record.

The sequence, which is the sequence a supply chain analyst actually performs:

    1. Read the vendor's contract documents.
    2. Detect which CIP-013 R1.2 obligations the procurement process addresses.
    3. Verify every quote the model gave against the source text, and decide in
       code which claims may drive a control.
    4. Register the vendor's published signing key.
    5. Verify each firmware release: SHA-256 first, then Ed25519 signature.
    6. Score CIP-013 and CIP-010 R1.6 against what was established.

Step 3 is the one that matters. Steps 1 and 2 are the model doing work that used
to be a person reading a contract; step 3 is the code refusing to let that work
become a finding unless it can be evidenced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from .cip import Coverage, assess_estate, load_cip_controls
from .cipcrypto import KeyRegistry, VerificationResult
from .config import RunConfig
from .evaluate import Assessment, Control
from .grid import Estate
from .procure import (
    ProcurementExtraction,
    VendorFootprint,
    extract_procurement,
    load_documents,
    write_pending_review,
)


@dataclass
class OnboardingResult:
    vendor: str
    vendor_slug: str
    extraction: ProcurementExtraction | None = None
    vendor_record: dict[str, Any] = field(default_factory=dict)
    key_registry: KeyRegistry = field(default_factory=KeyRegistry)
    releases: list[dict] = field(default_factory=list)
    verified: dict[str, VerificationResult] = field(default_factory=dict)
    findings: list[Assessment] = field(default_factory=list)
    gaps: list[Assessment] = field(default_factory=list)
    coverage: dict[str, Coverage] = field(default_factory=dict)
    pending_review_path: Path | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def clean_releases(self) -> list[VerificationResult]:
        return [r for r in self.verified.values()
                if r.integrity_verified is True and r.source_identity_verified is True]

    @property
    def rejected_releases(self) -> list[VerificationResult]:
        return [r for r in self.verified.values()
                if r.integrity_verified is not True or r.source_identity_verified is not True]


def _read_yaml(path: Path, default):
    if not path.is_file():
        return default
    return yaml.safe_load(path.read_text(encoding="utf-8")) or default


def onboard_vendor(
    vendor: str,
    vendor_dir: Path,
    cfg: RunConfig,
    *,
    slug: str | None = None,
    impact_rating: str = "high",
    controls: list[Control] | None = None,
    when: date | None = None,
    pending_review_root: Path | None = None,
) -> OnboardingResult:
    """Run the whole onboarding sequence for one vendor."""
    when = when or date.today()
    controls = controls or load_cip_controls()
    slug = slug or vendor.lower().replace(" ", "-").replace(",", "").replace(".", "")
    result = OnboardingResult(vendor=vendor, vendor_slug=slug)

    # --- 1 & 2: read the documents, detect the procurement obligations ------
    documents = load_documents(vendor_dir)
    if not documents:
        result.errors.append(f"no readable documents under {vendor_dir}")
        return result

    # --- the key is loaded BEFORE the contract is read ----------------------
    # Whether the entity already holds a trusted key for this vendor is the
    # single most useful thing to know going in: if it does not, CIP-010 R1.6.1
    # is unevaluable for every release this vendor ships, and finding out
    # whether the contract even obliges them to provide one is the priority.
    keys = _read_yaml(vendor_dir / "signing-key.yaml", [])
    result.key_registry = KeyRegistry(keys)
    active = [k for k in result.key_registry.all() if k.status == "active"]
    footprint = VendorFootprint(
        vendor=vendor,
        publishes_signing_key=bool(active),
        trusted_key_ids=[k.key_id for k in active],
        # Nothing is in service yet -- that is what onboarding means. The
        # footprint says so rather than implying a deployed base that does not
        # exist.
        high_impact_devices=0,
        medium_impact_devices=0,
    )

    # --- 3: adjudicate in code ----------------------------------------------
    extraction = extract_procurement(
        vendor, slug, documents, cfg, controls=controls, footprint=footprint
    )
    result.extraction = extraction
    result.pending_review_path = write_pending_review(
        extraction, when=when, root=pending_review_root
    )

    # The register the controls are scored against. Only what the code allowed
    # from the extraction reaches `contract`; everything else stays absent,
    # which the evaluator already treats as unknown -> information gap.
    result.vendor_record = {
        "vendor_slug": slug,
        "vendor": vendor,
        "supplies_impact_rating": impact_rating,
        "contract_id": f"onboarding-{slug}",
        # A vendor in onboarding has, by definition, not had the plan applied to
        # it yet. Asserting otherwise would be the tool inventing evidence of
        # its own implementation.
        "risk_assessment_process_documented": True,
        "plan_implemented": "unknown",
        "plan_approval_age_days": "unknown",
        "contract": extraction.register_contract_block(),
    }

    # --- 5: verify each release, SHA-256 then Ed25519 -----------------------
    releases = _read_yaml(vendor_dir / "releases.yaml", [])
    result.releases = releases

    # An Estate of exactly this vendor. Reusing the estate model rather than a
    # parallel code path means onboarding is scored by the same evaluator, with
    # the same coverage accounting, as a run over all 1,300 substations.
    estate = Estate(
        vendors=[result.vendor_record],
        packages={str(r["package_id"]): r for r in releases},
        registry=result.key_registry,
        root=vendor_dir,
    )
    # One notional in-scope deployment per release, so CIP-010 R1.6 is evaluated
    # against each candidate build before any of it reaches a substation. That
    # is the whole point of checking at onboarding rather than after rollout.
    estate.deployments = [
        {
            "deployment_id": f"onboarding-{r['package_id']}",
            "device_id": f"(candidate) {r.get('target_model', '')}",
            "substation_id": "(pre-deployment)",
            "impact_rating": impact_rating,
            "device_model": r.get("target_model"),
            "vendor": vendor,
            "vendor_slug": slug,
            "package_id": str(r["package_id"]),
            "deployed_on": when.isoformat(),
            "change_ticket": "(onboarding evaluation)",
            "no_verification_method_documented": True,
        }
        for r in releases
    ]

    # --- 6: score -----------------------------------------------------------
    findings, gaps, verified, coverage = assess_estate(estate, controls, when=when)
    result.findings = findings
    result.gaps = gaps
    result.verified = verified
    result.coverage = coverage
    return result
