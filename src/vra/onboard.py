"""Vendor onboarding — turn a vendor name + a trust-center URL into a register.

Phase 1 was hand-authored YAML and nothing else. That is the gap this module
closes: a new vendor arrives and someone has to guess the schema, find the
artifact URLs, and copy the first snapshot by hand. Onboarding automates the
mechanical part and — critically — *tries the subprocessor parse on day one*,
so AIV-03 either has coverage or is explicitly flagged as gated/blocked with a
drafted outreach, instead of being silently unassessable until a real change
arrives.

Flow:

    name + URLs -> fetch -> platform detect (SafeBase/Whistic/Vanta/PDF/HTML)
                 -> artifact discovery (changelog / subprocessors / DPA)
                 -> subprocessor parse attempt
                 -> register scaffold + artifact cache + outreach draft
                 -> (optional) first assessment run

The register it writes is deliberately conservative: contract facts default to
``false``/empty, `ai_surface` is seeded only from AI-related subprocessors that
were actually parsed, and everything unknown is written as ``unknown`` so the
gap machinery drafts the questions instead of the analyst inventing answers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import PENDING_REVIEW_DIR, REPO_ROOT, RunConfig
from .extract import discover_links, looks_like_pdf
from .observe import ParseStatus, parse_subprocessors
from .watch import SOURCE_KINDS, _ingest, fetch, watch_vendor

# Public, no-auth subprocessor pages. `vra bootstrap Slack` needs no URL.
PUBLIC_CATALOG: dict[str, dict[str, str]] = {
    "slack": {
        "name": "Slack",
        "category": "collaboration",
        "trust_center": "https://slack.com/trust",
        "subprocessors": "https://slack.com/slack-subprocessors",
    },
    "atlassian": {
        "name": "Atlassian",
        "category": "collaboration",
        "trust_center": "https://www.atlassian.com/trust",
        "subprocessors": "https://www.atlassian.com/legal/sub-processors",
    },
    "zoom": {
        "name": "Zoom",
        "category": "collaboration",
        "trust_center": "https://www.zoom.com/en/trust/",
        "subprocessors": "https://www.zoom.com/en/trust/subprocessors/",
    },
    "notion": {
        "name": "Notion",
        "category": "collaboration",
        "trust_center": "https://www.notion.so/help/notion-ai-security-practices",
        "subprocessors": (
            "https://notion.notion.site/"
            "Notion-s-List-of-Subprocessors-268fa5bcfa0f46b6bc29436b21676734"
        ),
    },
    "datadog": {
        "name": "Datadog",
        "category": "observability",
        "trust_center": "https://www.datadoghq.com/trust/",
        "subprocessors": "https://www.datadoghq.com/legal/subprocessors/",
    },
}


def lookup_catalog(name: str) -> dict[str, str] | None:
    key = slugify(name).split("-")[0]
    if key in PUBLIC_CATALOG:
        return PUBLIC_CATALOG[key]
    low = name.strip().lower()
    for slug, entry in PUBLIC_CATALOG.items():
        if slug == low or entry["name"].lower() == low:
            return entry
    return None

ARTIFACT_ROOT = REPO_ROOT / "artifacts" / "vendors"
DEFAULT_VERSION = "v1"

TIERS = ("critical", "high", "medium", "low")

SRC_LABEL = {
    "changelog": "changelog / release notes",
    "trust_center": "trust center",
    "subprocessors": "subprocessor list",
    "dpa": "DPA / BAA text",
}

# Sources that may legitimately not exist for every vendor.
OPTIONAL_SOURCES = {"changelog", "dpa"}


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "vendor"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------


@dataclass
class OnboardResult:
    vendor_name: str
    slug: str
    tier: str
    register_path: Path | None
    platform: str | None
    platform_blocked: bool
    discovered_urls: dict[str, str]
    parse_status: ParseStatus
    parsed_rows: list[Any]
    seeded_features: list[dict]
    blockers: list[str]
    warnings: list[str]
    outreach_path: Path | None = None
    bootstrap_path: Path | None = None
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_name": self.vendor_name,
            "slug": self.slug,
            "tier": self.tier,
            "register_path": str(self.register_path) if self.register_path else None,
            "platform": self.platform,
            "platform_blocked": self.platform_blocked,
            "discovered_urls": self.discovered_urls,
            "subprocessor_parse": {
                "status": self.parse_status.status,
                "platform": self.parse_status.platform,
                "rows": self.parse_status.rows,
                "reason": self.parse_status.reason,
            },
            "subprocessors": [
                {
                    "name": r.name,
                    "purpose": r.purpose,
                    "region": r.region,
                    "baa_marker": r.baa_marker,
                    "ai_related": r.is_ai_related,
                    "baa_covered": r.baa_covered,
                }
                for r in self.parsed_rows
            ],
            "seeded_features": self.seeded_features,
            "blockers": self.blockers,
            "warnings": self.warnings,
            "outreach_path": str(self.outreach_path) if self.outreach_path else None,
            "bootstrap_path": str(self.bootstrap_path) if self.bootstrap_path else None,
            "dry_run": self.dry_run,
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        steps = []
        if not self.dry_run and self.register_path:
            steps.append(f"Register written to {self.register_path}. Review it before relying on it.")
        if self.blockers:
            steps.append("Resolve the blocker(s) above (outreach drafted), then re-run onboarding or fix the watch URL.")
        else:
            steps.append("Subprocessor disclosure is parsed — AIV-03 has coverage from day one.")
        steps.append(f"Run the first assessment:  python3 vra.py --vendor {self.slug}  (add --snapshot v1)")
        steps.append("Leave the monitor running to keep watching this vendor and its NHIs:  python3 vra.py monitor --offline --webui")
        if not self.seeded_features:
            steps.append("No AI features seeded. As the vendor's AI features are confirmed, add "
                         "`ai_surface` entries to the register — model triage will propose them.")
        return steps


# ---------------------------------------------------------------------------
# Register scaffold
# ---------------------------------------------------------------------------


def _seed_features(rows: list[Any]) -> list[dict]:
    """Provisional ai_surface entries from parsed AI-related subprocessors.

    One feature per distinct AI-related provider, capped at three. Every field
    beyond the provider identity stays ``unknown`` so the gap machinery turns
    them into the initial vendor questionnaire.
    """
    out: list[dict] = []
    for sp in rows:
        if not sp.is_ai_related:
            continue
        purpose = re.sub(r"\s+", " ", sp.purpose or "").strip()
        name = purpose[:60] or "AI service"
        if len(purpose) > 60:
            name += "…"
        feature = {
            "feature": f"AI service: {sp.name} — {name}" if name else f"AI service: {sp.name}",
            "status": "available",
            "autonomy": "unknown",
            "data_reach": [],
            "model_provider": sp.name,
            "training_on_customer_data": "unknown",
            "human_in_loop": "unknown",
            "retention_days": "unknown",
            "output_logged": "unknown",
            "change_notification": "unknown",
            "error_rate_disclosed": "unknown",
            "prompt_injection_tested": "unknown",
            "data_residency": "unknown",
            "bias_tested_clinical": "unknown",
            "ai_incident_process": "unknown",
            "customer_disableable": "unknown",
        }
        out.append(feature)
        if len(out) >= 3:
            break
    return out


def _scaffold(
    vendor_name: str,
    slug: str,
    tier: str,
    category: str,
    description: str,
    watch: dict[str, str],
    parsed_rows: list[Any],
    parse_status: ParseStatus,
    discovered: dict[str, str],
    trust_center_url: str | None,
    blockers: list[str],
) -> dict:
    today = date.today().isoformat()
    now = datetime.now(timezone.utc).isoformat()
    features = _seed_features(parsed_rows)
    return {
        "vendor": vendor_name,
        "slug": slug,
        "tier": tier,
        "category": category,
        "description": description,
        "contract": {
            "baa_on_file": False,
            "ai_addendum_signed": False,
            "last_review": today,
            "baa_covered_subprocessors": [],
        },
        "ai_surface": features,
        "nhis": [],
        "watch": watch,
        "onboarding": {
            "onboarded_at": now,
            "by": "vra onboard",
            "trust_center_url": trust_center_url,
            "platform": parse_status.platform or None,
            "platform_blocked": parse_status.status == "blocked",
            "discovered_urls": discovered,
            "subprocessor_parse": {
                "status": parse_status.status,
                "platform": parse_status.platform,
                "rows": parse_status.rows,
                "reason": parse_status.reason,
            },
            "blockers": blockers,
            "seeded_features": [f["feature"] for f in features],
            "notes": (
                "Auto-scaffolded by `vra onboard`. Contract facts default to false/empty; "
                "ai_surface is seeded only from AI-related subprocessors that were parsed. "
                "Everything left 'unknown' is an information gap the assessment drafts as a "
                "vendor question. Replace watch paths with live URLs to watch continuously."
            ),
        },
        "state": {
            "last_assessed": None,
            "snapshot_hashes": {},
        },
    }


# ---------------------------------------------------------------------------
# Outreach draft for blockers (deterministic — no model needed)
# ---------------------------------------------------------------------------


def draft_blocker_outreach(vendor_name: str, blockers: list[str]) -> dict[str, str]:
    bullet = "\n".join(f"- {b}" for b in blockers)
    return {
        "subject": f"Vendor AI risk onboarding — {vendor_name} — subprocessor disclosure access",
        "body": (
            f"Hello,\n\nAs part of onboarding {vendor_name} as a vendor that processes or may "
            "process protected health information, we need to complete our AI risk assessment, "
            "including control AIV-03 (every model provider named as a subprocessor and covered "
            "by an executed BAA).\n\n"
            "We could not complete that step:\n" + bullet +
            "\n\nPlease either:\n"
            "1. Grant us guest or NDA-gated access to your trust portal subprocessor page, or\n"
            "2. Send the complete, current subprocessor list with BAA coverage status for each "
            "entity, including every model or AI service provider.\n\n"
            "We are a HIPAA covered entity and this item affects our assessment of protected "
            "health information processed by your service. Please respond within 21 days.\n\n"
            "Regards,\nVendor Risk Management"
        ),
    }


# ---------------------------------------------------------------------------
# Bootstrap — model reads FULL artifacts (not a diff) and proposes a register
# ---------------------------------------------------------------------------

BOOTSTRAP_SYSTEM = """You are a healthcare GRC analyst proposing an INITIAL vendor AI-surface \
register from the vendor's current public artifacts. This is not a diff. Read the full text.

Rules:
- Answer ONLY with a single JSON object.
- Propose only features the text actually names. Do not invent products.
- Every field you cannot quote from the text must be "unknown".
- You do not assign severity or findings.
- evidence_excerpt must be copied verbatim from the artifacts."""

BOOTSTRAP_PROMPT = """TASK: BOOTSTRAP_REGISTER

vendor: {vendor}

The artifacts below are the vendor's current public disclosures, read in full.

--- BEGIN ARTIFACTS ---
{artifacts}
--- END ARTIFACTS ---

Return JSON:
{{
  "features": [
    {{
      "feature": "name of the AI feature",
      "status": "available",
      "autonomy": "unknown",
      "model_provider": "named provider or unknown",
      "human_in_loop": "unknown",
      "training_on_customer_data": "unknown",
      "evidence_excerpt": "verbatim phrase from the artifacts"
    }}
  ],
  "notes": "one or two sentences on what you could and could not see"
}}

If the artifacts name no AI feature, return an empty features list."""


def _bootstrap_schema(obj: dict) -> str | None:
    if "features" not in obj or not isinstance(obj["features"], list):
        return "missing features list"
    if "notes" not in obj or not isinstance(obj.get("notes"), str):
        return "missing notes"
    for feat in obj["features"]:
        if not isinstance(feat, dict) or "feature" not in feat:
            return "each feature needs a feature name"
    return None


def bootstrap_register(
    vendor_name: str,
    slug: str,
    artifact_text: str,
    cfg: RunConfig,
    *,
    _root: Path | None = None,
) -> Path | None:
    """Read artifacts in full, propose an ai_surface, quarantine it.

    The proposal never touches vendors/{slug}.yaml. Same rule as triage.
    """
    from .llm import call_json

    if cfg.dry_run:
        return None
    prompt = BOOTSTRAP_PROMPT.format(
        vendor=vendor_name,
        artifacts=(artifact_text or "")[:14000],
    )
    result = call_json(
        system=BOOTSTRAP_SYSTEM,
        prompt=prompt,
        cfg=cfg,
        schema_check=_bootstrap_schema,
        task="bootstrap_register",
        context={"vendor": slug},
    )
    root = _root or REPO_ROOT
    dest = root / "pending_review" if _root else PENDING_REVIEW_DIR
    dest.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = dest / f"{slug}-bootstrap-{stamp}.json"
    payload = {
        "vendor": vendor_name,
        "slug": slug,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "backend": result.backend,
        "llm_ok": result.ok,
        "error": result.error,
        "instructions": (
            "BOOTSTRAP PROPOSAL — NOT APPLIED. The model read the vendor's current "
            "artifacts in full (not a diff) and proposed an initial ai_surface. "
            f"To accept, edit vendors/{slug}.yaml by hand, then delete this file. "
            "The tool will never write these fields to the register on its own."
        ),
        "proposed_ai_surface": (result.data or {}).get("features") if result.ok else [],
        "notes": (result.data or {}).get("notes", "") if result.ok else "",
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Core onboarding
# ---------------------------------------------------------------------------


def _validate(name: str, tier: str) -> None:
    if not name or not name.strip():
        raise ValueError("vendor name is required")
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}, got {tier!r}")


def _fetch_and_ingest(url: str, cfg: RunConfig) -> tuple[Any, str | None]:
    """Fetch one artifact URL and run it through the normal watcher ingest path."""
    raw, ctype, err = fetch(url, cfg)
    if err:
        return None, err
    (snap,) = _ingest(raw, url, ctype)
    return snap, None


def _cache_artifact(
    slug: str, source: str, url: str, cfg: RunConfig, artifact_root: Path | None = None
) -> str | None:
    """Copy a fetched artifact into the local cache; return the cache path.

    The watch entry points at the cache (offline-reproducible). Gated or failed
    artifacts are not cached — their watch entry stays the remote URL so a later
    online run retries.
    """
    if cfg.dry_run:
        return None
    raw, ctype, err = fetch(url, cfg)
    if err:
        return None
    ext = "pdf" if looks_like_pdf(raw, url, ctype) else \
        "html" if raw[:4096].lstrip().lower().startswith((b"<!doctype html", b"<html")) else "txt"
    cache_dir = (artifact_root or ARTIFACT_ROOT) / slug / "snapshots" / DEFAULT_VERSION
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{source}.{ext}"
    path.write_bytes(raw)
    return f"artifacts/vendors/{slug}/snapshots/{{version}}/{source}.{ext}"


def onboard_vendor(
    name: str,
    *,
    tier: str = "high",
    category: str = "other",
    description: str | None = None,
    trust_center_url: str | None = None,
    urls: dict[str, str] | None = None,
    cfg: RunConfig | None = None,
    bootstrap: bool = False,
    _root: Path | None = None,
) -> OnboardResult:
    cfg = cfg or RunConfig()
    urls = dict(urls or {})
    catalog = lookup_catalog(name)
    if catalog:
        name = catalog.get("name") or name
        if not urls.get("subprocessors") and catalog.get("subprocessors"):
            urls["subprocessors"] = catalog["subprocessors"]
        if not trust_center_url and catalog.get("trust_center"):
            trust_center_url = catalog["trust_center"]
        if category in ("other", "", None) and catalog.get("category"):
            category = catalog["category"]
    _validate(name, tier)
    slug = slugify(name)

    # _root is a test seam: onboarding against a scratch tree instead of the
    # live repository. Real usage never passes it.
    root = _root or REPO_ROOT
    artifact_root = root / "artifacts" / "vendors"
    register_path = root / "vendors" / f"{slug}.yaml"
    if register_path.exists():
        raise ValueError(
            f"vendor {name!r} already onboarded: {register_path} exists. "
            "Edit the register instead of re-onboarding."
        )

    blockers: list[str] = []
    warnings: list[str] = []
    platform: str | None = None
    platform_blocked = False
    discovered: dict[str, str] = {}
    watch: dict[str, str] = {}
    parse_status = ParseStatus("missing", reason="no subprocessor disclosure URL was supplied or discovered.")
    parsed_rows: list[Any] = []
    artifact_blobs: list[str] = []

    # --- 1) trust center: fetch, platform-detect, discover artifact links ----
    tc_raw_html = ""
    if trust_center_url:
        raw, ctype, tc_err = fetch(trust_center_url, cfg)
        if tc_err:
            blockers.append(f"trust center could not be fetched: {tc_err}")
        else:
            (tc_snap,) = _ingest(raw, trust_center_url, ctype)
            platform = tc_snap.platform or platform
            platform_blocked = tc_snap.portal_blocked or platform_blocked
            if tc_snap.raw_kind == "html":
                # Discover artifact links from the raw HTML (normalized text
                # has no anchors).
                tc_raw_html = raw.decode("utf-8", errors="replace")
                discovered = discover_links(tc_raw_html, trust_center_url)
            if tc_snap.text:
                artifact_blobs.append(f"[trust_center]\n{tc_snap.text}")
                if not discovered:
                    warnings.append("no watchable artifact links discovered on the trust center page.")
            if tc_snap.portal_blocked:
                blockers.append(
                    f"trust center is a {platform or 'gated'} portal behind a click-through NDA; "
                    "artifact pages cannot be fetched without guest access."
                )

    # --- 2) resolve final artifact URLs: explicit beats discovered -----------
    # The trust center itself is excluded from the watch set: it is the entry
    # point already ingested above. A discovered "trust center" subpage is
    # redundant with it and is dropped.
    discovered.pop("trust_center", None)
    final_urls: dict[str, str] = {}
    for source in SOURCE_KINDS:
        if source == "trust_center":
            continue
        if urls.get(source):
            final_urls[source] = urls[source]
        elif discovered.get(source):
            final_urls[source] = discovered[source]

    placeholder_links = {k: v for k, v in final_urls.items()
                         if v.startswith("https://vendor.trust-center.local/")}
    for source, url in placeholder_links.items():
        final_urls.pop(source)
        warnings.append(
            f"{SRC_LABEL.get(source, source)} link ({url}) resolves against the placeholder "
            "host from local-file onboarding. Supply a real URL or local file path to watch it."
        )
        if source == "subprocessors":
            blockers.append(
                "subprocessor disclosure link resolves against the placeholder host from "
                "local-file onboarding; supply the real URL with --subprocessors so AIV-03 "
                "has observed data."
            )

    if "subprocessors" not in final_urls and not any("subprocessors" in b for b in blockers):
        blockers.append(
            "no subprocessor disclosure URL found — AIV-03 has no observed data. "
            "Supply one with --subprocessors or discover the trust center first."
        )

    # Cache the trust center itself (when the user supplied one) so the watch
    # set is reproducible offline.
    if trust_center_url and not cfg.dry_run:
        cached_tc = _cache_artifact(slug, "trust_center", trust_center_url, cfg, artifact_root)
        if cached_tc:
            watch["trust_center"] = cached_tc

    # --- 3) fetch and parse the subprocessor artifact ------------------------
    sp_snap: Any = None
    if final_urls.get("subprocessors"):
        sp_snap, sp_err = _fetch_and_ingest(final_urls["subprocessors"], cfg)
        if sp_err:
            blockers.append(f"subprocessor disclosure could not be fetched: {sp_err}")
            parse_status = ParseStatus("error", reason=sp_err)
            watch["subprocessors"] = final_urls["subprocessors"]
        else:
            parsed_rows, parse_status = parse_subprocessors(
                sp_snap.text,
                source="subprocessors",
                tables=sp_snap.tables,
                platform=sp_snap.platform,
                portal_blocked=sp_snap.portal_blocked,
                portal_evidence=sp_snap.portal_evidence,
                raw_kind=sp_snap.raw_kind,
            )
            if parse_status.status != "parsed":
                blockers.append(parse_status.reason)
            if sp_snap.text:
                artifact_blobs.append(f"[subprocessors]\n{sp_snap.text}")
            cached = _cache_artifact(slug, "subprocessors", final_urls["subprocessors"], cfg, artifact_root)
            watch["subprocessors"] = cached or final_urls["subprocessors"]

    # --- 4) fetch the other artifacts (best effort) ---------------------------
    for source in SOURCE_KINDS:
        if source == "subprocessors" or source not in final_urls:
            continue
        snap, err = _fetch_and_ingest(final_urls[source], cfg)
        if err or (snap and snap.error):
            reason = err or snap.error
            if source not in OPTIONAL_SOURCES:
                blockers.append(f"{SRC_LABEL[source]} could not be fetched: {reason}")
            watch[source] = final_urls[source]
            continue
        cached = _cache_artifact(slug, source, final_urls[source], cfg, artifact_root)
        watch[source] = cached or final_urls[source]

    # --- 5) scaffold the register -------------------------------------------
    desc = description or (
        f"Onboarded {date.today().isoformat()} via `vra onboard`. "
        "Contract facts default to false/empty and ai_surface is seeded only from "
        "parsed AI-related subprocessors — review before relying on this register."
    )
    register = _scaffold(
        vendor_name=name, slug=slug, tier=tier, category=category, description=desc,
        watch=watch, parsed_rows=parsed_rows, parse_status=parse_status,
        discovered=discovered, trust_center_url=trust_center_url, blockers=blockers,
    )

    # --- 6) persist -----------------------------------------------------------
    outreach_path: Path | None = None
    if not cfg.dry_run:
        register_path.write_text(
            yaml.safe_dump(register, sort_keys=False, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
        if blockers:
            outreach_dir = root / "pending_review"
            outreach_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            outreach_path = outreach_dir / f"{slug}-onboarding-outreach-{stamp}.txt"
            draft = draft_blocker_outreach(name, blockers)
            outreach_path.write_text(
                f"Subject: {draft['subject']}\n\n{draft['body']}\n", encoding="utf-8"
            )
        # Establish the runtime baseline snapshot set immediately. Skipped when
        # onboarding against a scratch tree (tests): the runtime snapshot store
        # lives in the live repo.
        if root == REPO_ROOT:
            vendor = {"slug": slug, "vendor": name, "watch": watch}
            try:
                watch_vendor(vendor, cfg)
            except Exception as exc:  # pragma: no cover - defensive
                warnings.append(f"baseline snapshot failed: {exc}")

    bootstrap_path: Path | None = None
    if bootstrap:
        blob = "\n\n".join(artifact_blobs)
        if parsed_rows:
            blob += "\n\n[parsed_subprocessors]\n" + "\n".join(
                f"{r.name} | {r.purpose} | {r.region} | {r.baa_marker}" for r in parsed_rows
            )
        try:
            bootstrap_path = bootstrap_register(
                name, slug, blob, cfg, _root=_root,
            )
        except Exception as exc:  # pragma: no cover - never fail the scaffold
            warnings.append(f"bootstrap proposal failed: {exc}")

    seeded = _seed_features(parsed_rows)
    result = OnboardResult(
        vendor_name=name, slug=slug, tier=tier,
        register_path=None if cfg.dry_run else register_path,
        platform=platform or parse_status.platform,
        platform_blocked=platform_blocked or parse_status.status == "blocked",
        discovered_urls={**discovered, **{k: v for k, v in urls.items() if v}},
        parse_status=parse_status,
        parsed_rows=parsed_rows,
        seeded_features=seeded,
        blockers=blockers,
        warnings=warnings,
        outreach_path=outreach_path,
        bootstrap_path=bootstrap_path,
        dry_run=cfg.dry_run,
    )
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vra onboard",
        description="Onboard a vendor: fetch its trust center, discover artifact URLs, "
                    "attempt the subprocessor parse, and scaffold the register.",
    )
    p.add_argument("name", help="vendor name (e.g. \"Acme Corp\")")
    p.add_argument("--tier", default="high", choices=TIERS,
                   help="vendor tier. Default: high")
    p.add_argument("--category", default="other",
                   help="vendor category, e.g. collaboration, identity_provider, revenue_cycle")
    p.add_argument("--description", default=None,
                   help="one-line description recorded in the register")
    p.add_argument("--trust-center", dest="trust_center_url", default=None,
                   help="trust center / security page URL (http(s) or a local HTML file path)")
    p.add_argument("--changelog", default=None, help="explicit changelog / release notes URL")
    p.add_argument("--subprocessors", default=None,
                   help="explicit subprocessor list URL (HTML, PDF, or local file path)")
    p.add_argument("--dpa", default=None, help="explicit DPA / BAA URL")
    p.add_argument("--offline", action="store_true",
                   help="no network: use local file paths only, deterministic backend")
    p.add_argument("--dry-run", action="store_true",
                   help="assess and print the scaffold, persist nothing")
    p.add_argument("--assess", action="store_true",
                   help="after onboarding, run the first assessment for this vendor")
    p.add_argument("--bootstrap", action="store_true",
                   help="read current artifacts in full (not a diff) and drop a model-"
                        "proposed register in pending_review/ for human acceptance")
    return p


def _print_summary(r: OnboardResult) -> None:
    print()
    print("=" * 68)
    print(f"  Onboarded : {r.vendor_name}  ({r.slug})")
    print(f"  Tier      : {r.tier}")
    print(f"  Platform  : {r.platform or 'unknown'}"
          + ("  (BLOCKED behind click-through)" if r.platform_blocked else ""))
    print(f"  Parse     : {r.parse_status.status} "
          f"({r.parse_status.rows} subprocessor row(s))")
    print("=" * 68)
    if r.discovered_urls:
        print("  Discovered artifact URLs:")
        for src, url in sorted(r.discovered_urls.items()):
            print(f"    {SRC_LABEL.get(src, src):<20} {url}")
    if r.parsed_rows:
        print("  Subprocessors parsed:")
        for row in r.parsed_rows[:15]:
            tag = "AI " if row.is_ai_related else "   "
            cov = "covered" if row.baa_covered else "NOT BAA-COVERED"
            print(f"    [{tag}] {row.name:<28} {row.purpose or '':<40} {cov}")
        if len(r.parsed_rows) > 15:
            print(f"    … and {len(r.parsed_rows) - 15} more")
    for b in r.blockers:
        print(f"  ! BLOCKER: {b}")
    for w in r.warnings:
        print(f"  ! warning: {w}")
    print()
    print("  Next steps:")
    for step in r._next_steps():
        print(f"    - {step}")
    if r.outreach_path:
        print(f"  Outreach draft: {r.outreach_path}")
    print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = RunConfig(offline=args.offline, dry_run=args.dry_run)
    urls = {
        "changelog": args.changelog,
        "subprocessors": args.subprocessors,
        "dpa": args.dpa,
    }
    urls = {k: v for k, v in urls.items() if v}
    try:
        result = onboard_vendor(
            args.name,
            tier=args.tier,
            category=args.category,
            description=args.description,
            trust_center_url=args.trust_center_url,
            urls=urls,
            cfg=cfg,
            bootstrap=args.bootstrap,
        )
    except ValueError as exc:
        print(f"vra onboard: {exc}", file=sys.stderr)
        return 2

    _print_summary(result)
    if result.dry_run:
        print("(dry-run — nothing persisted)")
        return 0

    if args.assess:
        print(f"vra: running first assessment for '{result.slug}' …")
        from .cli import run as run_assessment

        assess_cfg = RunConfig(
            offline=args.offline, vendors=[result.slug], fail_on_critical=True
        )
        code = run_assessment(assess_cfg)
        print(f"vra: assessment exit code {code}")
        return code
    return 0
