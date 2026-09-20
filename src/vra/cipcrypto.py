"""Real firmware signature and hash verification for the NERC CIP module.

Nothing in this file is simulated. `verify_package` reads the actual bytes off
disk, computes an actual SHA-256, and performs an actual Ed25519 signature
verification through `cryptography`. Flip one byte in a firmware blob and the
result changes, because the result is a cryptographic fact rather than a field
somebody typed into YAML.

That property is the whole point. A tool that reports `signature_valid: false`
because a human wrote `signature_valid: false` evidences nothing, and the first
engineer who asks what it is actually doing will say so.

Algorithm choice
----------------
Ed25519. Deterministic, no padding or curve parameters to get wrong, and a
64-byte signature. Real protective-relay vendors more commonly sign with RSA or
ECDSA under an X.509 chain; `verify_signature` is the only place that knows the
algorithm, so swapping it is a local change. The CIP-010 R1.6 obligation is
about verifying source identity and integrity, not about a named algorithm.

CIP-010 R1.6 mapping, and one judgement call worth stating plainly
------------------------------------------------------------------
    R1.6.1  "Verify the identity of the software source."
            -> source_identity_verified = signature is cryptographically valid
               AND the key that made it is currently trusted.

    R1.6.2  "Verify the integrity of the software obtained from the software
             source."
            -> integrity_verified = the signature covers these exact bytes.

The judgement call is what a matching published hash proves on its own. It
proves the bytes match *a published string*. It does not prove that string came
from the vendor: an attacker who can substitute the binary on a distribution
mirror can usually substitute the hash printed beside it. So when the vendor
publishes a signing key, integrity rests on the signature and a hash match
alone does NOT satisfy R1.6.2 -- it is recorded, and reported, but it does not
close the control. When the vendor publishes no key at all, the hash is the
only method available from the source, integrity rests on it, and the result is
marked `verification_strength: hash_only` so the evidence pack never presents
the weaker check as though it were the stronger one.

This is the distinction the spreadsheet process cannot make, and it is why a
firmware package can be green on a checklist and still fail CIP-010 R1.6.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CHUNK = 1024 * 1024

# Key states a registry entry can carry. `unknown` is distinct from `revoked`:
# a key we have never seen is an information gap, a key we have withdrawn is a
# finding. Collapsing them would let an unrecognised signer read as an
# administrative oversight.
KEY_ACTIVE = "active"
KEY_REVOKED = "revoked"
KEY_EXPIRED = "expired"
KEY_UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    """SHA-256 of a file, streamed.

    Firmware images for a substation gateway run to tens of megabytes and an
    estate-wide run hashes thousands of them, so this never loads a whole image
    into memory.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def hashes_equal(left: str | None, right: str | None) -> bool:
    """Case- and whitespace-insensitive hex comparison.

    Vendors publish hashes in every casing and with every kind of surrounding
    whitespace. A comparison that says "mismatch" because one side was
    upper-case would be a false positive on a critical control, and a false
    critical is how people learn to ignore the tool.
    """
    if not left or not right:
        return False
    return left.strip().lower() == right.strip().lower()


# ---------------------------------------------------------------------------
# Signing keys
# ---------------------------------------------------------------------------
def load_public_key(encoded: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded))


def encode_public_key(key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return base64.b64encode(
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()


def key_fingerprint(encoded_public_key: str) -> str:
    """A short, stable fingerprint an engineer can read over the phone.

    CIP-010 R1.6.1 is about establishing *source identity*, and in practice that
    means somebody confirming a fingerprint through a channel the attacker does
    not control. A 64-character base64 blob is not something anyone confirms out
    of band; four hex groups is.
    """
    raw = hashlib.sha256(base64.b64decode(encoded_public_key)).hexdigest()[:16].upper()
    return ":".join(raw[i : i + 4] for i in range(0, 16, 4))


def derive_demo_keypair(seed_label: str) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Deterministically derive a DEMO-ONLY keypair from a text label.

    Used solely to build the sandbox estate, so the fixtures regenerate byte for
    byte on any machine and no private key is ever committed to the repository.
    Deriving a signing key from a public string is obviously unacceptable for a
    real key; it is correct here precisely because these keys sign fictional
    firmware for fictional vendors and must be reproducible.
    """
    seed = hashlib.sha256(f"vra-cip-demo-key::{seed_label}".encode()).digest()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return private, private.public_key()


def sign_blob(private: Ed25519PrivateKey, blob: bytes) -> str:
    return base64.b64encode(private.sign(blob)).decode()


def verify_signature(encoded_public_key: str, signature_b64: str, blob: bytes) -> bool:
    """True only if `signature_b64` is a valid Ed25519 signature over `blob`.

    Every failure mode -- malformed base64, wrong key length, a signature over
    different bytes -- returns False rather than raising. A verification routine
    that throws on a malformed signature turns an attacker-supplied value into a
    crash in the middle of an estate-wide run, and a crashed run verifies
    nothing.
    """
    try:
        load_public_key(encoded_public_key).verify(base64.b64decode(signature_b64), blob)
        return True
    except (InvalidSignature, ValueError, TypeError, Exception):  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Key registry
# ---------------------------------------------------------------------------
@dataclass
class SigningKey:
    key_id: str
    vendor: str
    public_key: str
    status: str = KEY_ACTIVE
    valid_from: str | None = None
    valid_until: str | None = None
    fingerprint_confirmed_out_of_band: bool | None = None
    note: str = ""

    def status_on(self, when: date) -> str:
        """Effective status on a date: explicit revocation beats the window."""
        if self.status == KEY_REVOKED:
            return KEY_REVOKED
        if self.valid_from and when < _as_date(self.valid_from):
            return KEY_EXPIRED
        if self.valid_until and when > _as_date(self.valid_until):
            return KEY_EXPIRED
        return self.status

    @property
    def fingerprint(self) -> str:
        return key_fingerprint(self.public_key)


def _as_date(value: Any) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


class KeyRegistry:
    """The set of vendor signing keys the entity has chosen to trust.

    Trust is a decision the entity records, not a property of the key material.
    A key that verifies a signature perfectly but is not in this registry has
    established no source identity under CIP-010 R1.6.1 -- which is exactly the
    case a signature-only check misses.
    """

    def __init__(self, keys: list[dict] | None = None):
        self._by_id: dict[str, SigningKey] = {}
        for raw in keys or []:
            key = SigningKey(
                key_id=str(raw["key_id"]),
                vendor=str(raw.get("vendor", "")),
                public_key=str(raw["public_key"]),
                status=str(raw.get("status", KEY_ACTIVE)),
                valid_from=raw.get("valid_from"),
                valid_until=raw.get("valid_until"),
                fingerprint_confirmed_out_of_band=raw.get("fingerprint_confirmed_out_of_band"),
                note=str(raw.get("note", "")),
            )
            self._by_id[key.key_id] = key

    def get(self, key_id: str | None) -> SigningKey | None:
        return self._by_id.get(str(key_id)) if key_id else None

    def for_vendor(self, vendor: str) -> list[SigningKey]:
        low = vendor.strip().lower()
        return [k for k in self._by_id.values() if k.vendor.strip().lower() == low]

    def __len__(self) -> int:
        return len(self._by_id)

    def all(self) -> list[SigningKey]:
        return list(self._by_id.values())


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
@dataclass
class VerificationResult:
    """The outcome of verifying one firmware package.

    Every boolean here is computed from bytes on disk. `evidence` records the
    operations performed so the audit pack can show its working rather than
    asserting a conclusion.
    """

    package_id: str
    artifact_path: str
    artifact_present: bool = False
    size_bytes: int = 0

    computed_sha256: str | None = None
    published_sha256: str | None = None
    published_hash_available: bool = False
    hash_match: bool | None = None

    signature_present: bool = False
    signature_verified: bool | None = None
    signing_key_id: str | None = None
    signing_key_fingerprint: str | None = None
    signing_key_status: str = KEY_UNKNOWN
    signing_key_trusted: bool | None = None

    verification_method_available: bool = False
    verification_strength: str = "none"  # signature | hash_only | none

    source_identity_verified: bool | None = None
    integrity_verified: bool | None = None

    evidence: list[str] = field(default_factory=list)

    def as_fields(self) -> dict[str, Any]:
        """Flatten into the fields cip_controls.yaml evaluates.

        The control file uses only the ordinary operators (`equals`, `in`,
        `gt`). Materialising cryptographic outcomes as plain fields is what lets
        that work without teaching the evaluator about signatures -- the
        evaluator stays the same deterministic thing it already was, and the
        crypto stays in one auditable place.
        """
        return {
            "artifact_present": self.artifact_present,
            "computed_sha256": self.computed_sha256,
            "published_sha256": self.published_sha256,
            "published_hash_available": self.published_hash_available,
            "hash_match": self.hash_match,
            "signature_present": self.signature_present,
            "signature_verified": self.signature_verified,
            "signing_key_id": self.signing_key_id,
            "signing_key_fingerprint": self.signing_key_fingerprint,
            "signing_key_status": self.signing_key_status,
            "signing_key_trusted": self.signing_key_trusted,
            "verification_method_available": self.verification_method_available,
            "verification_strength": self.verification_strength,
            "source_identity_verified": self.source_identity_verified,
            "integrity_verified": self.integrity_verified,
        }


def verify_package(
    package: dict,
    registry: KeyRegistry,
    *,
    root: Path,
    when: date | None = None,
) -> VerificationResult:
    """Verify one firmware package against the trusted key registry.

    `package` describes what the vendor shipped: the artifact path, the hash the
    vendor published, the signature, and the key id it claims to be signed with.
    Nothing in it is trusted; it is the claim being checked.
    """
    when = when or date.today()
    result = VerificationResult(
        package_id=str(package.get("package_id", "")),
        artifact_path=str(package.get("artifact", "")),
    )

    # --- the artifact itself ------------------------------------------------
    artifact = root / result.artifact_path if result.artifact_path else None
    if artifact is None or not artifact.is_file():
        # A missing binary is an unevaluable control, not a passing one. It
        # becomes a gap downstream, which is an honest "we could not check
        # this" rather than a silent green.
        result.evidence.append(f"artifact not found at {result.artifact_path or '(unset)'}")
        return result

    blob = artifact.read_bytes()
    result.artifact_present = True
    result.size_bytes = len(blob)
    result.computed_sha256 = sha256_bytes(blob)
    result.evidence.append(
        f"read {len(blob)} bytes from {result.artifact_path}; "
        f"computed SHA-256 {result.computed_sha256}"
    )

    # --- published hash -----------------------------------------------------
    published = package.get("published_sha256")
    if published:
        result.published_sha256 = str(published)
        result.published_hash_available = True
        result.hash_match = hashes_equal(result.computed_sha256, result.published_sha256)
        result.evidence.append(
            f"vendor published SHA-256 {result.published_sha256}: "
            f"{'MATCH' if result.hash_match else 'MISMATCH'}"
        )
    else:
        result.evidence.append("vendor published no SHA-256 for this release")

    # --- signature ----------------------------------------------------------
    signature = package.get("signature")
    claimed_key_id = package.get("signing_key_id")
    result.signing_key_id = str(claimed_key_id) if claimed_key_id else None
    key = registry.get(claimed_key_id)

    if signature:
        result.signature_present = True
        if key is None:
            # Signed by a key the entity never chose to trust. The signature may
            # be perfectly valid; that is not the question CIP-010 R1.6.1 asks.
            result.signature_verified = False
            result.signing_key_status = KEY_UNKNOWN
            result.signing_key_trusted = False
            result.evidence.append(
                f"signing key id {result.signing_key_id!r} is not in the trusted key "
                f"registry; source identity cannot be established"
            )
        else:
            result.signing_key_fingerprint = key.fingerprint
            result.signature_verified = verify_signature(key.public_key, str(signature), blob)
            result.signing_key_status = key.status_on(when)
            result.signing_key_trusted = result.signing_key_status == KEY_ACTIVE
            result.evidence.append(
                f"Ed25519 verify against key {key.key_id} "
                f"(fingerprint {key.fingerprint}, status {result.signing_key_status} "
                f"on {when.isoformat()}): "
                f"{'VALID' if result.signature_verified else 'INVALID'}"
            )
            if key.fingerprint_confirmed_out_of_band is False:
                result.evidence.append(
                    "key fingerprint has NOT been confirmed with the vendor out of band"
                )
    else:
        result.evidence.append("vendor supplied no signature for this release")

    # --- what method was actually available from the source -----------------
    # CIP-010 R1.6 is conditioned on the verification method being available
    # from the software source. A vendor that publishes a signing key offers the
    # strong method; one that publishes only a hash offers the weak one.
    vendor_publishes_key = bool(registry.for_vendor(str(package.get("vendor", ""))))
    if vendor_publishes_key or result.signature_present:
        result.verification_method_available = True
        result.verification_strength = "signature"
    elif result.published_hash_available:
        result.verification_method_available = True
        result.verification_strength = "hash_only"
    else:
        result.verification_method_available = False
        result.verification_strength = "none"

    # --- R1.6.1 source identity, R1.6.2 integrity ---------------------------
    if result.verification_strength == "signature":
        result.source_identity_verified = bool(
            result.signature_verified and result.signing_key_trusted
        )
        # Deliberately NOT `or hash_match`. See the module docstring: when the
        # vendor publishes a key, a matching hash from the same channel as the
        # binary adds no assurance about the source, and letting it close the
        # control is precisely the spreadsheet-era mistake this module exists to
        # surface.
        result.integrity_verified = bool(result.signature_verified)
        if result.hash_match and not result.signature_verified:
            result.evidence.append(
                "published hash MATCHES but the signature does not verify: the bytes "
                "match a published string, which does not establish that the string "
                "came from the vendor. CIP-010 R1.6.2 is not satisfied by hash alone "
                "where a signing key is published."
            )
    elif result.verification_strength == "hash_only":
        # The hash is the only method the source makes available, so it is the
        # method R1.6 requires -- recorded as the weaker check, not dressed up.
        result.source_identity_verified = None
        result.integrity_verified = result.hash_match
        result.evidence.append(
            "vendor publishes no signing key; integrity rests on the published hash "
            "alone (verification_strength=hash_only)"
        )
    else:
        result.source_identity_verified = None
        result.integrity_verified = None
        result.evidence.append(
            "no verification method available from the software source; CIP-010 R1.6 "
            "is conditioned on availability, but the absence must be documented"
        )

    return result


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
