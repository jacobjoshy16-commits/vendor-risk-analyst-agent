"""Build the committed part of the sandbox estate: keys, packages, firmware.

Run with `python3 vra.py cip build-fixtures`.

Everything here is regenerated from scratch, deterministically, so the estate
is reproducible on any machine and no private key is ever committed. The
signing keys are derived from fixed text labels by `derive_demo_keypair`, which
is a deliberate and clearly-marked demo-only construction.

The planted scenario
--------------------
One package is compromised: `SPS-421-4.7.2`, a protective relay build.

It is constructed the way a real mirror compromise looks, not the way a
convenient demo looks:

    1. The vendor builds and signs the genuine image.
    2. An attacker who controls the distribution mirror replaces the binary.
    3. The attacker also updates the SHA-256 printed beside it -- the hash and
       the binary come down the same channel, so controlling one means
       controlling the other.
    4. The attacker cannot forge the vendor's signature, so the original
       signature is left in place and hopes nobody checks it.

The result is a package that PASSES a hash check and FAILS a signature check.
That is the whole argument of this module: the semi-manual process Entergy
describes -- engineer downloads firmware, compares the hash to the release
notes, records it on a spreadsheet -- returns green on this package. The
cryptography returns red. Every other package in the estate is correctly
signed over its actual bytes and must produce nothing, which is what makes the
red one mean something.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

from .cipcrypto import derive_demo_keypair, encode_public_key, sha256_bytes, sign_blob
from .grid import DEVICE_MODELS, VENDORS

# The compromised release. Named here rather than buried so a reader can find
# the planted case without reverse-engineering the generator.
TAMPERED_PACKAGE = "SPS-421-4.7.2"

# Fixtures are committed, so they must not depend on the day they were built.
# Key validity windows and release dates are all relative to a date, and
# defaulting that to today meant regenerating on a Tuesday rewrote every file
# built on a Monday -- which would either churn the repo or make the
# "fixtures reproduce byte-for-byte" CI check fail for no real reason. Callers
# that need a different date pass one explicitly.
FIXTURE_EPOCH = date(2026, 9, 20)

RELEASES = {
    "SPS-411": ["3.8.0", "3.9.1"],
    "SPS-421": ["4.6.0", "4.7.2"],
    "SPS-680": ["2.1.4", "2.2.0"],
    "CGC-RTU-200": ["7.0.3", "7.1.0"],
    "CGC-RTU-350": ["1.4.2"],
    "IW-BC-90": ["5.5.1", "5.6.0"],
    "IW-BC-120": ["2.0.9"],
    "NG-GW-5000": ["9.2.1", "9.3.0"],
    "HAL-MU-40": ["1.1.7"],
}

VENDOR_BY_MODEL = {
    model: vendor
    for vendor in VENDORS
    for kind in vendor["makes"]
    for model in DEVICE_MODELS[kind]
}


def _firmware_blob(vendor: str, model: str, version: str, *, payload_seed: int) -> bytes:
    """A plausible firmware image.

    Shaped like a real one -- magic bytes, a header naming the vendor, model and
    version, then a padded binary payload -- because the point of the exercise
    is to hash and sign actual file bytes. The payload is deterministic filler;
    it is not executable and does not pretend to be.
    """
    header = (
        f"SPSFW\x00{vendor}\x00{model}\x00{version}\x00"
        f"build={payload_seed:08x}\x00"
    ).encode()
    payload = bytearray()
    state = payload_seed
    while len(payload) < 8192:
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        payload += state.to_bytes(4, "big")
    return b"\x7fFWIMG" + header + bytes(payload[:8192])


def build(grid_dir: Path, *, today: date | None = None) -> dict:
    """Generate keys.yaml, packages.yaml, vendors.yaml and the firmware images."""
    today = today or FIXTURE_EPOCH
    fw_dir = grid_dir / "firmware"
    fw_dir.mkdir(parents=True, exist_ok=True)
    for stale in fw_dir.glob("*.bin"):
        stale.unlink()

    # --- signing keys ------------------------------------------------------
    keys: list[dict] = []
    private_by_vendor = {}
    for vendor in VENDORS:
        priv, pub = derive_demo_keypair(f"{vendor['slug']}-signing-2026")
        private_by_vendor[vendor["slug"]] = priv
        keys.append(
            {
                "key_id": f"{vendor['slug']}-2026",
                "vendor": vendor["name"],
                "public_key": encode_public_key(pub),
                "status": "active",
                "valid_from": (today - timedelta(days=400)).isoformat(),
                "valid_until": (today + timedelta(days=700)).isoformat(),
                "fingerprint_confirmed_out_of_band": True,
                "note": "DEMO KEY. Fictional vendor. Derived deterministically; signs nothing real.",
            }
        )
    # A retired key, kept in the registry so a package signed with it is
    # recognised and rejected rather than reported as an unknown signer.
    _, retired_pub = derive_demo_keypair("sentinel-protective-signing-2021")
    keys.append(
        {
            "key_id": "sentinel-protective-2021",
            "vendor": "Sentinel Protective Systems",
            "public_key": encode_public_key(retired_pub),
            "status": "revoked",
            "valid_from": (today - timedelta(days=1800)).isoformat(),
            "valid_until": (today - timedelta(days=420)).isoformat(),
            "fingerprint_confirmed_out_of_band": True,
            "note": "DEMO KEY. Retired after scheduled rotation.",
        }
    )

    # --- packages and firmware images --------------------------------------
    packages: list[dict] = []
    seed = 1
    for model, versions in RELEASES.items():
        vendor = VENDOR_BY_MODEL[model]
        for version in versions:
            seed += 1
            package_id = f"{model}-{version}"
            genuine = _firmware_blob(vendor["name"], model, version, payload_seed=seed * 7919)
            artifact = fw_dir / f"{package_id}.bin"
            signature = sign_blob(private_by_vendor[vendor["slug"]], genuine)

            if package_id == TAMPERED_PACKAGE:
                # Steps 2-4 of the mirror compromise described in the module
                # docstring. The signature stays over the GENUINE bytes; the
                # file on disk and the published hash are both the attacker's.
                tampered = bytearray(genuine)
                tampered[600:640] = b"\x90" * 40  # substituted payload region
                on_disk = bytes(tampered)
                published_hash = sha256_bytes(on_disk)
                note = (
                    "Binary substituted on the distribution mirror. The published hash "
                    "was updated to match the substituted binary; the vendor signature "
                    "still covers the genuine build and therefore no longer verifies."
                )
            else:
                on_disk = genuine
                published_hash = sha256_bytes(genuine)
                note = ""

            artifact.write_bytes(on_disk)
            packages.append(
                {
                    "package_id": package_id,
                    "vendor": vendor["name"],
                    "vendor_slug": vendor["slug"],
                    "target_model": model,
                    "version": version,
                    "artifact": f"firmware/{package_id}.bin",
                    "published_sha256": published_hash,
                    "signature": signature,
                    "signing_key_id": f"{vendor['slug']}-2026",
                    "released_on": (today - timedelta(days=seed * 11)).isoformat(),
                    "note": note,
                }
            )

    # --- procurement records (CIP-013 R1.1 / R1.2 / R2 / R3) ---------------
    # Mostly compliant, with a few real gaps. A vendor portfolio where every
    # clause is executed makes the CIP-013 controls decorative; one where none
    # are makes the output noise. These are the shapes a mid-size utility
    # actually has.
    clause_profiles = {
        "sentinel-protective": dict(
            incident_notification_clause=True, incident_coordination_clause=True,
            access_termination_notice_clause=True, vulnerability_disclosure_clause=True,
            software_integrity_clause=True, remote_access_coordination_clause=True),
        "cascade-grid": dict(
            incident_notification_clause=True, incident_coordination_clause=False,
            access_termination_notice_clause=True, vulnerability_disclosure_clause=True,
            software_integrity_clause=True, remote_access_coordination_clause=True),
        "ironwood-automation": dict(
            incident_notification_clause=True, incident_coordination_clause=True,
            access_termination_notice_clause=False, vulnerability_disclosure_clause=True,
            software_integrity_clause=True, remote_access_coordination_clause=True),
        "northgate-substation": dict(
            incident_notification_clause=True, incident_coordination_clause=True,
            access_termination_notice_clause=True, vulnerability_disclosure_clause="unknown",
            software_integrity_clause=True, remote_access_coordination_clause=True),
        "halcyon-instruments": dict(
            incident_notification_clause=True, incident_coordination_clause=True,
            access_termination_notice_clause=True, vulnerability_disclosure_clause=True,
            software_integrity_clause=False, remote_access_coordination_clause=True),
    }
    plan_age = {
        "sentinel-protective": 120, "cascade-grid": 300, "ironwood-automation": 210,
        "northgate-substation": 470, "halcyon-instruments": 95,
    }
    vendors_out = []
    for vendor in VENDORS:
        vendors_out.append(
            {
                "vendor_slug": vendor["slug"],
                "vendor": vendor["name"],
                "supplies_impact_rating": "high",
                "contract_id": f"MSA-{vendor['slug'].upper()[:6]}-2024",
                "risk_assessment_process_documented": True,
                "plan_implemented": vendor["slug"] != "halcyon-instruments",
                "plan_approval_age_days": plan_age[vendor["slug"]],
                "contract": clause_profiles[vendor["slug"]],
            }
        )

    (grid_dir / "keys.yaml").write_text(yaml.safe_dump(keys, sort_keys=False), encoding="utf-8")
    (grid_dir / "packages.yaml").write_text(yaml.safe_dump(packages, sort_keys=False), encoding="utf-8")
    (grid_dir / "vendors.yaml").write_text(yaml.safe_dump(vendors_out, sort_keys=False), encoding="utf-8")

    return {
        "keys": len(keys),
        "packages": len(packages),
        "firmware_images": len(list(fw_dir.glob("*.bin"))),
        "vendors": len(vendors_out),
        "tampered_package": TAMPERED_PACKAGE,
    }


# ---------------------------------------------------------------------------
# Onboarding fixtures — a vendor that is NOT part of the estate yet
# ---------------------------------------------------------------------------
# Kestrel Grid Systems is the vendor the end-to-end test onboards from scratch:
# contract documents, a published signing key, and two firmware releases. It is
# deliberately absent from VENDORS, because the point of the exercise is the
# path a new supplier takes before any of its equipment is in service.
ONBOARDING_VENDOR = "Kestrel Grid Systems"
ONBOARDING_SLUG = "kestrel-grid"
ONBOARDING_MODEL = "KG-RTU-100"
ONBOARDING_CLEAN = "KG-RTU-100-2.4.0"
ONBOARDING_TAMPERED = "KG-RTU-100-2.4.1"


def build_onboarding(vendor_dir: Path, *, today: date | None = None) -> dict:
    """Write Kestrel's published key and two signed firmware releases.

    One release is genuine. The other is the same mirror compromise the estate
    carries -- binary substituted, published hash updated to match, signature
    left over the original -- so the onboarding path exercises both outcomes:
    a vendor that verifies, and a release that does not.
    """
    today = today or FIXTURE_EPOCH
    releases = vendor_dir / "releases"
    releases.mkdir(parents=True, exist_ok=True)
    for stale in releases.glob("*.bin"):
        stale.unlink()

    priv, pub = derive_demo_keypair(f"{ONBOARDING_SLUG}-signing-2026")
    key = {
        "key_id": f"{ONBOARDING_SLUG}-2026",
        "vendor": ONBOARDING_VENDOR,
        "public_key": encode_public_key(pub),
        "status": "active",
        "valid_from": (today - timedelta(days=200)).isoformat(),
        "valid_until": (today + timedelta(days=900)).isoformat(),
        # MSA 9.4 obliges the vendor to make the key available through a channel
        # independent of the artifact, and to confirm the fingerprint on request.
        # This records that the entity actually did that -- the difference
        # between a clause and a control.
        "fingerprint_confirmed_out_of_band": True,
        "note": "DEMO KEY. Fictional vendor. Derived deterministically; signs nothing real.",
    }

    out = []
    for package_id, version, tampered in (
        (ONBOARDING_CLEAN, "2.4.0", False),
        (ONBOARDING_TAMPERED, "2.4.1", True),
    ):
        genuine = _firmware_blob(ONBOARDING_VENDOR, ONBOARDING_MODEL, version, payload_seed=0xA5 * len(version))
        signature = sign_blob(priv, genuine)
        if tampered:
            substituted = bytearray(genuine)
            substituted[900:948] = b"\xcc" * 48
            on_disk = bytes(substituted)
            note = ("Substituted on the distribution mirror; published hash updated to "
                    "match, vendor signature still covers the genuine build.")
        else:
            on_disk = genuine
            note = "Genuine release as published by the vendor."

        (releases / f"{package_id}.bin").write_bytes(on_disk)
        out.append({
            "package_id": package_id,
            "vendor": ONBOARDING_VENDOR,
            "vendor_slug": ONBOARDING_SLUG,
            "target_model": ONBOARDING_MODEL,
            "version": version,
            "artifact": f"releases/{package_id}.bin",
            "published_sha256": sha256_bytes(on_disk),
            "signature": signature,
            "signing_key_id": key["key_id"],
            "released_on": (today - timedelta(days=30 if tampered else 90)).isoformat(),
            "note": note,
        })

    (vendor_dir / "signing-key.yaml").write_text(
        yaml.safe_dump([key], sort_keys=False), encoding="utf-8")
    (vendor_dir / "releases.yaml").write_text(
        yaml.safe_dump(out, sort_keys=False), encoding="utf-8")
    return {
        "vendor": ONBOARDING_VENDOR,
        "keys": 1,
        "releases": len(out),
        "clean": ONBOARDING_CLEAN,
        "tampered": ONBOARDING_TAMPERED,
    }


# ---------------------------------------------------------------------------
# Commissioning batch — a new plant's firmware arriving all at once
# ---------------------------------------------------------------------------
# The estate scenario is steady-state: equipment already in service, one bad
# build discovered among it. Commissioning is the other shape, and it is the
# riskier one. A new plant's firmware arrives as a batch, from several vendors,
# against a schedule, and every package has to be verified before energisation.
# That is the moment a substituted package is most likely to pass unexamined,
# because the pressure is to energise rather than to check.
#
# The tampered package here is deliberately the turbine control system: the one
# item in a plant that typically comes from a single supplier, where there is no
# second source to compare against and no option to simply use a different
# vendor's build.
COMMISSIONING_PLANT = "Cypress Bend Energy Center"
COMMISSIONING_SLUG = "cypress-bend"
COMMISSIONING_TAMPERED = "MTS-PICS-9000-3.1.0"

# (vendor, key seed, package id, model, version, tampered?)
COMMISSIONING_BATCH = [
    ("Meridian Turbine Systems", "meridian-turbine", "MTS-PICS-9000-3.1.0", "MTS-PICS-9000", "3.1.0", True),
    ("Meridian Turbine Systems", "meridian-turbine", "MTS-GOV-400-2.0.4", "MTS-GOV-400", "2.0.4", False),
    ("Meridian Turbine Systems", "meridian-turbine", "MTS-EXC-220-1.7.1", "MTS-EXC-220", "1.7.1", False),
    ("Sentinel Protective Systems", "sentinel-protective", "SPS-411-3.9.1", "SPS-411", "3.9.1", False),
    ("Sentinel Protective Systems", "sentinel-protective", "SPS-680-2.2.0", "SPS-680", "2.2.0", False),
    ("Cascade Grid Controls", "cascade-grid", "CGC-RTU-350-1.4.2", "CGC-RTU-350", "1.4.2", False),
    ("Cascade Grid Controls", "cascade-grid", "CGC-RTU-200-7.1.0", "CGC-RTU-200", "7.1.0", False),
    ("Ironwood Automation", "ironwood-automation", "IW-BC-120-2.0.9", "IW-BC-120", "2.0.9", False),
    ("Ironwood Automation", "ironwood-automation", "IW-BC-90-5.6.0", "IW-BC-90", "5.6.0", False),
    ("Northgate Substation Systems", "northgate-substation", "NG-GW-5000-9.3.0", "NG-GW-5000", "9.3.0", False),
    ("Halcyon Instruments", "halcyon-instruments", "HAL-MU-40-1.1.7", "HAL-MU-40", "1.1.7", False),
    ("Halcyon Instruments", "halcyon-instruments", "HAL-MU-40-1.2.0", "HAL-MU-40", "1.2.0", False),
]


def build_commissioning(batch_dir: Path, *, today: date | None = None) -> dict:
    """Write a new plant's commissioning firmware batch.

    Eleven genuine packages and one substituted, built the same way as the
    estate compromise: the binary is replaced on the mirror, the published hash
    is updated to match it, and the vendor signature is left over the original
    build because it cannot be forged.
    """
    today = today or FIXTURE_EPOCH
    firmware = batch_dir / "firmware"
    firmware.mkdir(parents=True, exist_ok=True)
    for stale in firmware.glob("*.bin"):
        stale.unlink()

    keys: list[dict] = []
    privates: dict[str, Any] = {}
    for seed in dict.fromkeys(item[1] for item in COMMISSIONING_BATCH):
        vendor = next(i[0] for i in COMMISSIONING_BATCH if i[1] == seed)
        priv, pub = derive_demo_keypair(f"{seed}-signing-2026")
        privates[seed] = priv
        keys.append({
            "key_id": f"{seed}-2026",
            "vendor": vendor,
            "public_key": encode_public_key(pub),
            "status": "active",
            "valid_from": (today - timedelta(days=400)).isoformat(),
            "valid_until": (today + timedelta(days=700)).isoformat(),
            "fingerprint_confirmed_out_of_band": True,
            "note": "DEMO KEY. Fictional vendor. Derived deterministically; signs nothing real.",
        })

    releases: list[dict] = []
    for n, (vendor, seed, package_id, model, version, tampered) in enumerate(COMMISSIONING_BATCH, 1):
        genuine = _firmware_blob(vendor, model, version, payload_seed=0x5EED + n * 131)
        signature = sign_blob(privates[seed], genuine)
        if tampered:
            substituted = bytearray(genuine)
            substituted[1200:1264] = b"\xde\xad\xbe\xef" * 16
            on_disk = bytes(substituted)
            note = ("Substituted in transit; published hash updated to match, vendor "
                    "signature still covers the genuine build.")
        else:
            on_disk = genuine
            note = "Genuine release as published by the vendor."
        (firmware / f"{package_id}.bin").write_bytes(on_disk)
        releases.append({
            "package_id": package_id,
            "vendor": vendor,
            "vendor_slug": seed,
            "target_model": model,
            "version": version,
            "artifact": f"firmware/{package_id}.bin",
            "published_sha256": sha256_bytes(on_disk),
            "signature": signature,
            "signing_key_id": f"{seed}-2026",
            "released_on": (today - timedelta(days=45 + n)).isoformat(),
            "note": note,
        })

    (batch_dir / "signing-key.yaml").write_text(yaml.safe_dump(keys, sort_keys=False), encoding="utf-8")
    (batch_dir / "releases.yaml").write_text(yaml.safe_dump(releases, sort_keys=False), encoding="utf-8")
    return {
        "plant": COMMISSIONING_PLANT,
        "vendors": len(keys),
        "packages": len(releases),
        "tampered": COMMISSIONING_TAMPERED,
    }
