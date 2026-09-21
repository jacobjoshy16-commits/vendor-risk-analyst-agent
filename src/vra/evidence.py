"""CIP audit evidence pack.

The other half of the output. `rollup` answers "what is wrong"; this answers
"show me you checked", which is the question a NERC audit actually opens with.

An audit does not accept a list of exceptions. It asks what population was in
scope, why the rest was out of scope, what method was applied, how many
subjects passed, and what the working was for the ones that did not. So the
pack is organised by requirement rather than by finding, every requirement
carries its denominator, and firmware exceptions print the SHA-256 that was
computed and the signature verification that was performed.

Two deliberate refusals
-----------------------
1. The pack never says the entity is compliant. It says what was checked, on
   what date, with what result. Compliance is a determination a Regional Entity
   makes; a tool that claims it is selling a liability.

2. While any citation in cip_controls.yaml has `citation_verified: false`, the
   pack prints an unmissable banner saying the standard revisions and part
   numbers have not been checked against the enforceable standards. NERC
   revises these and part numbering moves between revisions. Printing a
   confident-looking citation nobody verified is worse than printing none.
"""

from __future__ import annotations

import html
import json
from datetime import date
from pathlib import Path
from typing import Any

from .cip import Coverage, cip_citation, citation_status, citations_verified
from .cipcrypto import VerificationResult, utc_now_iso
from .evaluate import Assessment, Control, to_record
from .grid import Estate

DISCLAIMER = (
    "SYNTHETIC DEMONSTRATION DATA. This pack was produced from a simulated "
    "substation estate with fabricated vendors, devices, personnel and firmware. "
    "It is not connected to, and does not describe, any real operational "
    "technology network."
)

SCOPE_NOTE = (
    "Population scoping follows the CIP-002 impact rating recorded on each asset. "
    "CIP-013, CIP-010 R1.6, CIP-005 R2 and CIP-004 obligations in this pack are "
    "evaluated against high and medium impact BES Cyber Systems. Low impact assets "
    "are reported as not applicable rather than as passing, so the denominator "
    "reflects what was actually in scope."
)


def _requirement_groups(controls: list[Control]) -> dict[str, list[Control]]:
    """Group controls under the standard they evidence, in citation order."""
    groups: dict[str, list[Control]] = {}
    for control in controls:
        std = str((control.frameworks or [{}])[0].get("standard", "OTHER"))
        groups.setdefault(std, []).append(control)
    return dict(sorted(groups.items()))


def build_pack(
    estate: Estate,
    controls: list[Control],
    findings: list[Assessment],
    gaps: list[Assessment],
    verified: dict[str, VerificationResult],
    coverage: dict[str, Coverage],
    *,
    entity: str = "Entergy Corporation (simulated)",
    when: date | None = None,
) -> dict[str, Any]:
    """Assemble the pack as data. Renderers below format it; neither adds facts."""
    when = when or date.today()
    ok, total = citations_verified(controls)
    cites = citation_status(controls, when)
    by_control: dict[str, list[Assessment]] = {}
    for a in findings:
        by_control.setdefault(a.control.id, []).append(a)

    requirements = []
    for standard, group in _requirement_groups(controls).items():
        for control in group:
            cov = coverage.get(control.id)
            if cov is None:
                continue
            exceptions = by_control.get(control.id, [])
            requirements.append(
                {
                    "standard": standard,
                    "control_id": control.id,
                    "citation": cip_citation(control),
                    "requirement_text": " ".join(
                        str((control.frameworks or [{}])[0].get("text", "")).split()
                    ),
                    "citation_verified": bool(
                        (control.frameworks or [{}])[0].get("citation_verified")
                    ),
                    "question": control.question,
                    "severity": control.severity,
                    "subject": control.subject,
                    "coverage": cov.as_dict(),
                    "exception_count": len(exceptions),
                    # A pack that inlines 131 identical exceptions is unreadable
                    # and, worse, hides the fact that they are one incident. So
                    # exceptions are grouped by root cause first -- for firmware
                    # that is the package, and 131 relays running one bad build
                    # is a single remediation, not 131. The sample rows stay for
                    # the auditor who wants to see named assets; the full list
                    # is in findings.json.
                    "root_causes": _root_causes(exceptions, verified),
                    "exception_sample": [
                        _exception_row(a) for a in exceptions[:5]
                    ],
                    "remediation": control.remediation,
                }
            )

    return {
        "entity": entity,
        "generated_at": utc_now_iso(),
        "assessment_date": when.isoformat(),
        "disclaimer": DISCLAIMER,
        "scope_note": SCOPE_NOTE,
        "citations_verified": ok,
        "citations_total": total,
        "citations_unverified": total - ok,
        # A verified citation has a shelf life. NERC revisions have effective
        # dates, so the pack records which verified citations are close to
        # being superseded and which already are, rather than presenting a
        # one-time check as permanent.
        "citations_expiring": cites.expiring,
        "citations_expired": cites.expired,
        "estate": estate.summary(),
        "totals": {
            "findings": len(findings),
            "gaps": len(gaps),
            "critical": sum(1 for a in findings if a.control.severity == "critical"),
            "packages_verified": len(verified),
            "packages_failing": sum(
                1
                for r in verified.values()
                if r.integrity_verified is not True or r.source_identity_verified is not True
            ),
        },
        "verification_log": [
            {
                "package_id": r.package_id,
                "artifact": r.artifact_path,
                "size_bytes": r.size_bytes,
                "computed_sha256": r.computed_sha256,
                "published_sha256": r.published_sha256,
                "hash_match": r.hash_match,
                "signature_verified": r.signature_verified,
                "signing_key_id": r.signing_key_id,
                "signing_key_fingerprint": r.signing_key_fingerprint,
                "signing_key_status": r.signing_key_status,
                "verification_strength": r.verification_strength,
                "source_identity_verified": r.source_identity_verified,
                "integrity_verified": r.integrity_verified,
                "evidence": r.evidence,
            }
            for r in sorted(verified.values(), key=lambda x: x.package_id)
        ],
        "requirements": requirements,
    }


def _exception_row(a: Assessment) -> dict[str, Any]:
    return {
        "subject": a.feature,
        "vendor": a.vendor_name,
        "observed": a.observed,
        "reason": a.reason,
    }


def _root_causes(
    exceptions: list[Assessment], verified: dict[str, VerificationResult]
) -> list[dict[str, Any]]:
    """Collapse exceptions onto the thing that actually has to be fixed.

    131 relays failing CIP-010 R1.6.2 is not 131 problems. It is one substituted
    firmware package deployed 131 times, and an evidence pack that does not say
    so buries the only sentence that matters under a list. Grouping is by
    package where the provenance names one, and by the distinct observed values
    otherwise, so the same collapse works for the non-firmware controls.
    """
    groups: dict[str, dict[str, Any]] = {}
    for a in exceptions:
        prov = (a.provenance or {}).get("firmware_verification") or {}
        key = str(prov.get("value") or "|".join(f"{k}={v}" for k, v in sorted(a.observed.items())))
        group = groups.setdefault(
            key,
            {
                "cause": key,
                "affected": 0,
                "vendor": a.vendor_name,
                "evidence": prov.get("evidence", ""),
                "example_subjects": [],
            },
        )
        group["affected"] += 1
        if len(group["example_subjects"]) < 3:
            group["example_subjects"].append(a.feature)
    return sorted(groups.values(), key=lambda g: -g["affected"])


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def render_markdown(pack: dict[str, Any]) -> str:
    L: list[str] = []
    add = L.append
    add(f"# NERC CIP Audit Evidence Pack — {pack['entity']}")
    add("")
    add(f"> **{pack['disclaimer']}**")
    add("")
    if pack["citations_verified"]:
        add(
            f"> ✓ **{pack['citations_verified']} of {pack['citations_total']} citations "
            f"verified** against the enforceable NERC standards."
        )
        add("")
    for entry in pack.get("citations_expired", []):
        add(
            f"> ✗ **SUPERSEDED CITATION.** {entry['control_id']} cites "
            f"{entry['citation']}, which stopped being enforceable on "
            f"{entry['enforceable_until']}. Re-cite to {entry['superseded_by']}."
        )
        add("")
    for entry in pack.get("citations_expiring", []):
        add(
            f"> ⚠ **CITATION EXPIRES SOON.** {entry['control_id']} cites "
            f"{entry['citation']}, enforceable until {entry['enforceable_until']} "
            f"({entry['days']} days), then superseded by {entry['superseded_by']}."
        )
        add("")
    if pack["citations_unverified"]:
        add(
            f"> ⚠ **CITATIONS NOT VERIFIED.** {pack['citations_unverified']} of "
            f"{pack['citations_total']} standard citations in this pack have not been "
            f"checked against the enforceable NERC standards. Standard revisions and "
            f"part numbering change between versions. Set `citation_verified: true` in "
            f"`cip_controls.yaml` once each has been confirmed against nerc.com."
        )
        add("")
    add(f"- **Assessment date:** {pack['assessment_date']}")
    add(f"- **Generated:** {pack['generated_at']}")
    add("")
    add("This pack records what was examined and what was found. It does not assert")
    add("compliance; that determination belongs to the Regional Entity.")
    add("")
    add("## Scope")
    add("")
    add(pack["scope_note"])
    add("")
    est = pack["estate"]
    add(f"| Population | Count |")
    add("| --- | ---: |")
    add(f"| Substations | {est['substations']:,} |")
    add(f"| — high impact | {est['substations_by_impact'].get('high', 0):,} |")
    add(f"| — medium impact | {est['substations_by_impact'].get('medium', 0):,} |")
    add(f"| — low impact (out of scope) | {est['substations_by_impact'].get('low', 0):,} |")
    add(f"| Cyber assets | {est['devices']:,} |")
    add(f"| Firmware deployments | {est['firmware_deployments']:,} |")
    add(f"| Distinct firmware packages | {est['distinct_packages']:,} |")
    add(f"| Vendor remote access sessions | {est['vendor_access_sessions']:,} |")
    add(f"| Vendor personnel with ESP access | {est['vendor_personnel']:,} |")
    add(f"| Trusted vendor signing keys | {est['trusted_signing_keys']:,} |")
    add("")
    t = pack["totals"]
    add("## Result summary")
    add("")
    add(f"- **Exceptions:** {t['findings']:,} ({t['critical']:,} critical)")
    add(f"- **Information gaps:** {t['gaps']:,}")
    add(
        f"- **Firmware packages cryptographically verified:** {t['packages_verified']:,}, "
        f"of which **{t['packages_failing']:,} failed**"
    )
    add("")
    add("## Requirement-by-requirement")
    add("")
    current = None
    for req in pack["requirements"]:
        if req["standard"] != current:
            current = req["standard"]
            add(f"### {current}")
            add("")
        c = req["coverage"]
        if not c["applicable"]:
            add(
                f"**{req['control_id']} — {req['citation']}** · not applicable to any "
                f"subject in this population ({c['in_population']:,} examined)"
            )
            add("")
            continue
        flag = "" if req["citation_verified"] else "  ⚠ citation unverified"
        add(f"**{req['control_id']} — {req['citation']}**{flag}")
        add("")
        if req["requirement_text"]:
            add(f"> {req['requirement_text']}")
            add("")
        add(f"*Control question:* {req['question']}")
        add("")
        add(
            f"| Population | Applicable | Not applicable | Passed | Exceptions | Gaps |"
        )
        add("| ---: | ---: | ---: | ---: | ---: | ---: |")
        add(
            f"| {c['in_population']:,} | {c['applicable']:,} | {c['not_applicable']:,} "
            f"| {c['passed']:,} | {c['failed']:,} | {c['gapped']:,} |"
        )
        add("")
        if req["root_causes"]:
            causes = req["root_causes"]
            add(
                f"**Root causes: {len(causes)}** accounting for "
                f"{req['exception_count']:,} exception(s).")
            add("")
            for cause in causes:
                add(f"- `{cause['cause']}` — **{cause['affected']:,} affected**"
                    f"{(' · ' + cause['vendor']) if cause['vendor'] else ''}")
                add(f"  - example assets: {', '.join(cause['example_subjects'])}"
                    + (f", … (+{cause['affected'] - len(cause['example_subjects']):,} more)"
                       if cause["affected"] > len(cause["example_subjects"]) else ""))
                if cause["evidence"]:
                    add("  - verification log:")
                    for line in cause["evidence"].split(" | "):
                        add(f"    - {line}")
            add("")
            add(f"*Remediation:* {req['remediation']}")
            add("")

    add("## Firmware verification log")
    add("")
    add("Every distinct package examined, with the operations performed on it.")
    add("")
    add("| Package | Hash match | Signature | Key status | R1.6.1 source | R1.6.2 integrity |")
    add("| --- | :---: | :---: | --- | :---: | :---: |")
    for v in pack["verification_log"]:
        add(
            f"| `{v['package_id']}` | {_tick(v['hash_match'])} | "
            f"{_tick(v['signature_verified'])} | {v['signing_key_status']} | "
            f"{_tick(v['source_identity_verified'])} | {_tick(v['integrity_verified'])} |"
        )
    add("")
    for v in pack["verification_log"]:
        if v["integrity_verified"] is True and v["source_identity_verified"] is True:
            continue
        add(f"**`{v['package_id']}` — verification detail**")
        add("")
        for line in v["evidence"]:
            add(f"- {line}")
        add("")
    return "\n".join(L) + "\n"


def _tick(value: Any) -> str:
    if value is True:
        return "PASS"
    if value is False:
        return "**FAIL**"
    return "n/a"


def render_html(pack: dict[str, Any]) -> str:
    """Static, self-contained, print-friendly.

    The thing a compliance lead forwards internally after the conversation ends,
    which is the actual conversion event at a career fair.
    """
    e = html.escape
    est = pack["estate"]
    t = pack["totals"]

    banner = ""
    if pack["citations_unverified"]:
        banner = (
            f'<div class="warn"><strong>Citations not verified.</strong> '
            f'{pack["citations_unverified"]} of {pack["citations_total"]} standard '
            f'citations have not been checked against the enforceable NERC standards. '
            f'Revisions and part numbering change between versions.</div>'
        )

    rows = []
    for req in pack["requirements"]:
        c = req["coverage"]
        if not c["applicable"]:
            continue
        status = "fail" if c["failed"] else ("gap" if c["gapped"] else "pass")
        label = "EXCEPTIONS" if c["failed"] else ("GAP" if c["gapped"] else "PASS")
        rows.append(
            f"<tr class='{status}'>"
            f"<td><code>{e(req['control_id'])}</code></td>"
            f"<td class='cite'>{e(req['citation'])}</td>"
            f"<td class='q'>{e(req['question'])}</td>"
            f"<td class='n'>{c['applicable']:,}</td>"
            f"<td class='n'>{c['passed']:,}</td>"
            f"<td class='n'>{c['failed']:,}</td>"
            f"<td class='n'>{c['gapped']:,}</td>"
            f"<td class='st'>{label}</td></tr>"
        )

    vrows = []
    for v in pack["verification_log"]:
        bad = v["integrity_verified"] is not True or v["source_identity_verified"] is not True
        vrows.append(
            f"<tr class='{'fail' if bad else 'pass'}'>"
            f"<td><code>{e(v['package_id'])}</code></td>"
            f"<td class='st'>{_tick(v['hash_match']).replace('**','')}</td>"
            f"<td class='st'>{_tick(v['signature_verified']).replace('**','')}</td>"
            f"<td>{e(str(v['signing_key_status']))}</td>"
            f"<td class='st'>{_tick(v['source_identity_verified']).replace('**','')}</td>"
            f"<td class='st'>{_tick(v['integrity_verified']).replace('**','')}</td>"
            f"<td class='hash'><code>{e(str(v['computed_sha256'] or '')[:16])}…</code></td>"
            f"</tr>"
        )

    detail = []
    for req in pack["requirements"]:
        if not req["root_causes"]:
            continue
        items = []
        for cause in req["root_causes"]:
            log = ""
            if cause["evidence"]:
                log = "<ul class='log'>" + "".join(
                    f"<li>{e(line)}</li>" for line in cause["evidence"].split(" | ")
                ) + "</ul>"
            more = cause["affected"] - len(cause["example_subjects"])
            items.append(
                f"<li><code>{e(cause['cause'])}</code> — "
                f"<strong>{cause['affected']:,} affected</strong>"
                f"<div class='ex'>{e(', '.join(cause['example_subjects']))}"
                f"{f', … (+{more:,} more)' if more > 0 else ''}</div>{log}</li>"
            )
        detail.append(
            f"<h3>{e(req['control_id'])} — {e(req['citation'])} "
            f"<span class='cnt'>{req['exception_count']:,} exception(s), "
            f"{len(req['root_causes'])} root cause(s)</span></h3>"
            f"<ul class='causes'>{''.join(items)}</ul>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NERC CIP Evidence Pack</title>
<style>
  :root {{
    --bg:#fbfbfa; --fg:#1a1a18; --muted:#6b6b63; --line:#e0e0da;
    --card:#fff; --fail:#a3321f; --failbg:#fdeeea; --pass:#2d6a4a;
    --gap:#8a6a14; --gapbg:#fdf6e3; --accent:#1f3a5f;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg:#16161a; --fg:#ececea; --muted:#9a9a92; --line:#2e2e34;
      --card:#1e1e23; --fail:#ff8f75; --failbg:#3a1e18; --pass:#7fd1a6;
      --gap:#e0bc5c; --gapbg:#332b12; --accent:#8fb3dd;
    }}
  }}
  :root[data-theme="dark"] {{
    --bg:#16161a; --fg:#ececea; --muted:#9a9a92; --line:#2e2e34;
    --card:#1e1e23; --fail:#ff8f75; --failbg:#3a1e18; --pass:#7fd1a6;
    --gap:#e0bc5c; --gapbg:#332b12; --accent:#8fb3dd;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:40px 16px 80px; }}
  h1 {{ font-size:1.7rem; margin:0 0 4px; letter-spacing:-.02em; }}
  h2 {{ font-size:1.15rem; margin:40px 0 12px; padding-bottom:6px;
    border-bottom:1px solid var(--line); letter-spacing:-.01em; }}
  h3 {{ font-size:.95rem; margin:22px 0 6px; }}
  .sub {{ color:var(--muted); margin:0 0 20px; }}
  .synth {{ background:var(--card); border:1px solid var(--line); border-left:3px solid var(--accent);
    padding:12px 14px; border-radius:6px; font-size:.86rem; color:var(--muted); margin:0 0 14px; }}
  .warn {{ background:var(--gapbg); border:1px solid var(--gap); color:var(--fg);
    padding:12px 14px; border-radius:6px; font-size:.86rem; margin:0 0 14px; }}
  .tiles {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin:18px 0 8px; }}
  .tile {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:14px 16px; }}
  .tile .v {{ font-size:1.5rem; font-weight:620; letter-spacing:-.02em; }}
  .tile .k {{ font-size:.72rem; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); margin-top:3px; }}
  .tile.bad .v {{ color:var(--fail); }}
  table {{ width:100%; border-collapse:collapse; font-size:.83rem; margin:10px 0 6px; }}
  th {{ text-align:left; font-size:.7rem; text-transform:uppercase; letter-spacing:.06em;
    color:var(--muted); font-weight:600; padding:7px 9px; border-bottom:1px solid var(--line); }}
  td {{ padding:7px 9px; border-bottom:1px solid var(--line); vertical-align:top; }}
  td.n, th.n {{ text-align:right; font-variant-numeric:tabular-nums; }}
  td.st {{ text-align:center; font-size:.7rem; font-weight:700; letter-spacing:.05em; }}
  td.q {{ color:var(--muted); max-width:380px; }}
  td.cite {{ white-space:nowrap; font-size:.78rem; }}
  tr.fail td.st {{ color:var(--fail); }}
  tr.fail {{ background:var(--failbg); }}
  tr.pass td.st {{ color:var(--pass); }}
  tr.gap td.st {{ color:var(--gap); }}
  code {{ font:.84em ui-monospace,SFMono-Regular,Menlo,monospace; }}
  ul.log {{ font-size:.8rem; color:var(--muted); padding-left:18px; margin:5px 0 0; }}
  ul.log li {{ margin:3px 0; }}
  ul.causes {{ padding-left:18px; }}
  ul.causes > li {{ margin:10px 0; }}
  .ex {{ font-size:.78rem; color:var(--muted); margin-top:2px; }}
  .cnt {{ font-weight:400; font-size:.78rem; color:var(--muted); margin-left:6px; }}
  footer {{ margin-top:40px; padding-top:14px; border-top:1px solid var(--line);
    font-size:.78rem; color:var(--muted); }}
  @media print {{ body {{ background:#fff; }} .wrap {{ padding:0; }} }}
</style></head><body><div class="wrap">
<h1>NERC CIP Audit Evidence Pack</h1>
<p class="sub">{e(pack['entity'])} · assessed {e(pack['assessment_date'])} · generated {e(pack['generated_at'])}</p>
<div class="synth">{e(pack['disclaimer'])}</div>
{banner}
<div class="synth">This pack records what was examined and what was found. It does not
assert compliance; that determination belongs to the Regional Entity.</div>

<div class="tiles">
  <div class="tile"><div class="v">{est['substations']:,}</div><div class="k">Substations</div></div>
  <div class="tile"><div class="v">{est['in_cip013_scope']:,}</div><div class="k">High / medium impact</div></div>
  <div class="tile"><div class="v">{est['devices']:,}</div><div class="k">Cyber assets</div></div>
  <div class="tile"><div class="v">{est['distinct_packages']:,}</div><div class="k">Packages verified</div></div>
  <div class="tile bad"><div class="v">{t['packages_failing']:,}</div><div class="k">Packages failing</div></div>
  <div class="tile bad"><div class="v">{t['findings']:,}</div><div class="k">Exceptions</div></div>
</div>

<h2>Scope</h2>
<p class="sub">{e(pack['scope_note'])}</p>

<h2>Requirement-by-requirement</h2>
<table><thead><tr>
<th>Control</th><th>NERC citation</th><th>Question</th>
<th class="n">Applicable</th><th class="n">Passed</th><th class="n">Exceptions</th>
<th class="n">Gaps</th><th>Status</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table>

<h2>Firmware verification log</h2>
<table><thead><tr>
<th>Package</th><th>Hash</th><th>Signature</th><th>Key status</th>
<th>R1.6.1 source</th><th>R1.6.2 integrity</th><th>Computed SHA-256</th>
</tr></thead><tbody>{''.join(vrows)}</tbody></table>

<h2>Exception detail</h2>
{''.join(detail) or '<p class="sub">No control produced an exception.</p>'}

<footer>Produced by the vendor risk analyst CIP module. Every hash and signature
result above was computed from the artifact bytes at assessment time.</footer>
</div></body></html>
"""


def write_pack(pack: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "markdown": out_dir / "evidence-pack.md",
        "html": out_dir / "evidence-pack.html",
        "json": out_dir / "evidence-pack.json",
    }
    paths["markdown"].write_text(render_markdown(pack), encoding="utf-8")
    paths["html"].write_text(render_html(pack), encoding="utf-8")
    paths["json"].write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")
    return paths


def write_findings(findings: list[Assessment], gaps: list[Assessment], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "findings.json"
    path.write_text(
        json.dumps(
            [to_record(a) for a in findings] + [to_record(a) for a in gaps],
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return path
