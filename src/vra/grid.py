"""The simulated Entergy transmission estate, and the model behind it.

SYNTHETIC DATA. Every substation, device, vendor, technician and firmware
image in here is fabricated. Nothing in this module connects to, reads from, or
describes any real operational technology network. The vendor names are
invented deliberately -- see `VENDORS` below.

Why the assets live here and not on a vendor register
-----------------------------------------------------
The SaaS side of this repo keys everything by vendor: `vendors/{slug}.yaml`
holds what that vendor supplies. That is the wrong shape for OT. A protective
relay is *supplied* by a vendor but *owned* by the utility, sits in a
substation the utility operates, and carries a CIP-002 impact rating the
utility assigns. Modelling it as a property of the vendor record makes it
impossible to ask the question CIP-002 forces you to ask -- which requirements
even apply here -- so assets are their own model and vendors keep only what
vendors actually control: releases, signing keys, contract clauses, and the
people they send.

Scale
-----
Entergy operates roughly 1,300 substations across Arkansas, Louisiana,
Mississippi and Texas. The estate is generated deterministically from a seed
rather than committed as YAML: 1,300 substations and ~10,000 devices is
megabytes of fixture nobody would read, and a generator regenerates byte for
byte on any machine while staying one file to review.

Firmware images are the exception. Those are real files on disk with real
signatures over their real bytes, because verifying them is the entire point.
There are only a few dozen distinct releases across the estate -- thousands of
relays run the same handful of builds -- so the artifact set stays small while
the deployment count stays realistic.

Impact rating distribution
--------------------------
Deliberately lopsided: a few control centres and 500 kV stations at high
impact, a minority of transmission stations at medium, and the large majority
of distribution substations at low. That ratio matters. CIP-013 obligations
attach to high and medium impact BES Cyber Systems, so a tool that raises
CIP-013 findings uniformly across 1,300 sites is generating ~84% false
positives and an auditor will say so in the first ten minutes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

from .cipcrypto import KeyRegistry, VerificationResult, verify_package

# ---------------------------------------------------------------------------
# Fictional vendors
# ---------------------------------------------------------------------------
# All invented. Real protective-relay vendors (SEL, GE, Siemens, ABB) are
# deliberately absent: this repository is public, and the scenario it plants is
# a firmware package that fails signature verification. Attaching a real
# company's name to that is an unnecessary risk, and it would also be less
# accurate -- in a real supply-chain compromise the vendor is usually not the
# culprit. The binary is substituted downstream, on a mirror or in transit,
# which is exactly what the planted scenario depicts.
VENDORS = [
    {"slug": "sentinel-protective", "name": "Sentinel Protective Systems", "makes": ["protective_relay"]},
    {"slug": "cascade-grid", "name": "Cascade Grid Controls", "makes": ["rtu"]},
    {"slug": "ironwood-automation", "name": "Ironwood Automation", "makes": ["breaker_controller"]},
    {"slug": "northgate-substation", "name": "Northgate Substation Systems", "makes": ["substation_gateway"]},
    {"slug": "halcyon-instruments", "name": "Halcyon Instruments", "makes": ["merging_unit"]},
]

DEVICE_MODELS = {
    "protective_relay": ["SPS-411", "SPS-421", "SPS-680"],
    "rtu": ["CGC-RTU-200", "CGC-RTU-350"],
    "breaker_controller": ["IW-BC-90", "IW-BC-120"],
    "substation_gateway": ["NG-GW-5000"],
    "merging_unit": ["HAL-MU-40"],
}

OPERATING_COMPANIES = [
    ("Entergy Arkansas", "AR"),
    ("Entergy Louisiana", "LA"),
    ("Entergy Mississippi", "MS"),
    ("Entergy Texas", "TX"),
    ("Entergy New Orleans", "LA"),
]

# Invented place names. Not a list of real Entergy substations.
SITE_WORDS = [
    "Cypress", "Bayou", "Redstone", "Millbrook", "Fairhaven", "Cedar Ridge",
    "Gulfport", "Ashland", "Pinecrest", "Delta", "Longview", "Marshfield",
    "Silver Creek", "Oakvale", "Riverbend", "Hollow Oak", "Windham",
    "Brightwater", "Caldwell", "Stonegate", "Cane River", "Fort Union",
    "Tallow Creek", "Morganza", "Wolf Bay", "Kingsley", "Amberton",
]

VOLTAGE_CLASSES = [500, 230, 161, 138, 115, 69]

IMPACT_HIGH = "high"
IMPACT_MEDIUM = "medium"
IMPACT_LOW = "low"


# ---------------------------------------------------------------------------
# Estate
# ---------------------------------------------------------------------------
@dataclass
class Estate:
    """Everything a CIP run scores, plus the key registry it scores against."""

    substations: list[dict] = field(default_factory=list)
    devices: list[dict] = field(default_factory=list)
    deployments: list[dict] = field(default_factory=list)
    access_sessions: list[dict] = field(default_factory=list)
    personnel: list[dict] = field(default_factory=list)
    vendors: list[dict] = field(default_factory=list)
    packages: dict[str, dict] = field(default_factory=dict)
    registry: KeyRegistry = field(default_factory=KeyRegistry)
    root: Path = field(default_factory=Path)

    def summary(self) -> dict[str, Any]:
        by_impact: dict[str, int] = {}
        for sub in self.substations:
            by_impact[sub["impact_rating"]] = by_impact.get(sub["impact_rating"], 0) + 1
        return {
            "substations": len(self.substations),
            "devices": len(self.devices),
            "firmware_deployments": len(self.deployments),
            "distinct_packages": len(self.packages),
            "vendor_access_sessions": len(self.access_sessions),
            "vendor_personnel": len(self.personnel),
            "vendors": len(self.vendors),
            "trusted_signing_keys": len(self.registry),
            "substations_by_impact": by_impact,
            "in_cip013_scope": by_impact.get(IMPACT_HIGH, 0) + by_impact.get(IMPACT_MEDIUM, 0),
        }

    def verify_all(self, *, when: date | None = None) -> dict[str, VerificationResult]:
        """Verify every distinct firmware package exactly once.

        A verification result is a property of the package, not of the device it
        landed on: the same build flashed to 900 relays has one signature and one
        hash. Verifying per deployment would re-hash the same few dozen images
        thousands of times for an identical answer. Per-deployment facts that do
        depend on the device -- model compatibility in particular -- are computed
        in cip.py against this cache.
        """
        when = when or date.today()
        return {
            pkg_id: verify_package(pkg, self.registry, root=self.root, when=when)
            for pkg_id, pkg in self.packages.items()
        }


# ---------------------------------------------------------------------------
# Loading the committed part of the estate
# ---------------------------------------------------------------------------
def _read_yaml(path: Path) -> Any:
    if not path.is_file():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_estate(
    grid_dir: Path,
    *,
    substations: int = 1300,
    seed: int = 20260920,
    today: date | None = None,
) -> Estate:
    """Load committed keys/packages/vendors, then generate the asset estate."""
    today = today or date.today()
    keys = _read_yaml(grid_dir / "keys.yaml") or []
    packages = _read_yaml(grid_dir / "packages.yaml") or []
    vendors = _read_yaml(grid_dir / "vendors.yaml") or []

    estate = Estate(
        packages={str(p["package_id"]): p for p in packages},
        registry=KeyRegistry(keys),
        vendors=vendors,
        root=grid_dir,
    )
    _generate_assets(estate, substations=substations, seed=seed, today=today)
    return estate


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
def _impact_for(index: int, voltage: int, rng: random.Random) -> str:
    """Assign a CIP-002 impact rating.

    Approximates the real shape rather than the real criteria: control centres
    and the 500 kV backbone at high impact, a slice of >=200 kV transmission at
    medium, everything else low. Real categorisation runs the CIP-002
    Attachment 1 criteria against each BES Cyber System; this is a plausible
    distribution for a demo, not a categorisation method, and the code says so
    rather than implying otherwise.
    """
    if index < 4:
        return IMPACT_HIGH  # the operating companies' control centres
    if voltage >= 500:
        return IMPACT_HIGH
    if voltage >= 230:
        return IMPACT_MEDIUM if rng.random() < 0.65 else IMPACT_LOW
    if voltage >= 161:
        return IMPACT_MEDIUM if rng.random() < 0.18 else IMPACT_LOW
    return IMPACT_LOW


def _generate_assets(estate: Estate, *, substations: int, seed: int, today: date) -> None:
    rng = random.Random(seed)
    packages_by_model: dict[str, list[dict]] = {}
    for pkg in estate.packages.values():
        packages_by_model.setdefault(str(pkg.get("target_model", "")), []).append(pkg)

    for i in range(substations):
        company, state = OPERATING_COMPANIES[i % len(OPERATING_COMPANIES)]
        word = SITE_WORDS[rng.randrange(len(SITE_WORDS))]
        voltage = rng.choices(VOLTAGE_CLASSES, weights=[2, 10, 14, 24, 22, 28])[0]
        impact = _impact_for(i, voltage, rng)
        sub_id = f"{state}-SUB-{i + 1:04d}"
        substation = {
            "substation_id": sub_id,
            "name": f"{word} {'Control Center' if i < 4 else 'Substation'} {i + 1:04d}",
            "operating_company": company,
            "state": state,
            "voltage_kv": voltage,
            "impact_rating": impact,
            "esp_defined": impact in (IMPACT_HIGH, IMPACT_MEDIUM),
        }
        estate.substations.append(substation)

        # Bigger, higher-voltage stations carry more intelligent devices.
        n_devices = {IMPACT_HIGH: rng.randint(14, 22), IMPACT_MEDIUM: rng.randint(8, 14)}.get(
            impact, rng.randint(3, 7)
        )
        for d in range(n_devices):
            kind = rng.choices(
                ["protective_relay", "rtu", "breaker_controller", "substation_gateway", "merging_unit"],
                weights=[46, 16, 18, 8, 12],
            )[0]
            model = rng.choice(DEVICE_MODELS[kind])
            vendor = next(v for v in VENDORS if kind in v["makes"])
            device = {
                "device_id": f"{sub_id}-{kind[:3].upper()}-{d + 1:02d}",
                "substation_id": sub_id,
                "impact_rating": impact,
                "kind": kind,
                "model": model,
                "vendor": vendor["name"],
                "vendor_slug": vendor["slug"],
            }
            estate.devices.append(device)

            candidates = packages_by_model.get(model) or []
            if not candidates:
                continue
            pkg = rng.choice(candidates)
            deployed = today - timedelta(days=rng.randint(1, 240))
            estate.deployments.append(
                {
                    "deployment_id": f"{device['device_id']}-FW",
                    "device_id": device["device_id"],
                    "substation_id": sub_id,
                    "impact_rating": impact,
                    "device_model": model,
                    "vendor": vendor["name"],
                    "vendor_slug": vendor["slug"],
                    "package_id": str(pkg["package_id"]),
                    "deployed_on": deployed.isoformat(),
                    "change_ticket": f"CHG-{rng.randint(100000, 999999)}",
                    # Whether the entity recorded the absence of a vendor
                    # verification method. Only consulted by CIP-06, which
                    # applies when no method is available at all.
                    "no_verification_method_documented": True,
                }
            )

    _generate_vendor_people_and_sessions(estate, rng=rng, today=today)


def _generate_vendor_people_and_sessions(estate: Estate, *, rng: random.Random, today: date) -> None:
    """Vendor technicians and their remote access into substation ESPs.

    Only high and medium impact sites get vendor remote access records: a low
    impact distribution substation with no defined ESP has no Interactive Remote
    Access to govern, and inventing sessions there would manufacture CIP-005 and
    CIP-004 findings that an auditor would throw out.
    """
    in_scope = [s for s in estate.substations if s["impact_rating"] in (IMPACT_HIGH, IMPACT_MEDIUM)]
    first = ["Dana", "Marcus", "Priya", "Tobias", "Renee", "Hollis", "Amara", "Grant", "Yusuf", "Lena"]
    last = ["Okafor", "Brandt", "Naidu", "Whitfield", "Serrano", "Kemp", "Ahmadi", "Lindqvist", "Boone", "Reyes"]

    person_n = 0
    for vendor in VENDORS:
        for _ in range(rng.randint(4, 9)):
            person_n += 1
            pra_days = rng.choices([rng.randint(30, 2000), rng.randint(2558, 3400)], weights=[92, 8])[0]
            train_days = rng.choices([rng.randint(10, 430), rng.randint(457, 700)], weights=[93, 7])[0]
            terminated = rng.random() < 0.06
            estate.personnel.append(
                {
                    "person_id": f"VP-{person_n:04d}",
                    "name": f"{rng.choice(first)} {rng.choice(last)}",
                    "vendor": vendor["name"],
                    "vendor_slug": vendor["slug"],
                    "impact_rating": IMPACT_HIGH if rng.random() < 0.3 else IMPACT_MEDIUM,
                    "has_electronic_access": True,
                    "pra_completed": True,
                    "pra_age_days": pra_days,
                    "training_age_days": train_days,
                    "access_authorization_on_file": rng.random() > 0.03,
                    "access_verification_age_days": rng.choices(
                        [rng.randint(1, 90), rng.randint(93, 160)], weights=[94, 6]
                    )[0],
                    "termination_action": terminated,
                    "hours_to_revocation": rng.choices([rng.randint(1, 20), rng.randint(26, 90)],
                                                       weights=[80, 20])[0] if terminated else None,
                    "shared_accounts_known": terminated and rng.random() < 0.5,
                    "days_to_shared_credential_change": rng.choices(
                        [rng.randint(1, 28), rng.randint(31, 70)], weights=[75, 25]
                    )[0] if terminated else None,
                }
            )

    for n in range(rng.randint(40, 70)):
        sub = rng.choice(in_scope)
        person = rng.choice(estate.personnel)
        active = rng.random() < 0.35
        past_window = active and rng.random() < 0.12
        estate.access_sessions.append(
            {
                "session_id": f"VRA-SESS-{n + 1:04d}",
                "substation_id": sub["substation_id"],
                "impact_rating": sub["impact_rating"],
                "vendor": person["vendor"],
                "vendor_slug": person["vendor_slug"],
                "person_id": person["person_id"],
                "access_type": rng.choice(["interactive_remote_access", "system_to_system"]),
                "status": "active" if active else "closed",
                "session_visibility_method": rng.random() > 0.05,
                "session_disable_method": rng.random() > 0.04,
                "approved_window_end": (today - timedelta(days=rng.randint(0, 3))).isoformat(),
                "past_approved_window": past_window,
                "change_ticket": f"CHG-{rng.randint(100000, 999999)}",
            }
        )
