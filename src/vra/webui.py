"""Local onboarding console — a zero-dependency browser UI.

Serves a single self-contained HTML page (no CDNs, works fully offline) plus a
small JSON API. It is the answer to "how do vendors get onboarded": paste a
trust-center URL, see what platform it is, whether the subprocessor list parses
(or is gated behind a SafeBase/Whistic/Vanta click-through NDA), review the
scaffolded register, and run the first assessment — all without hand-writing a
YAML file or memorizing the schema.

    python3 vra.py webui --host 0.0.0.0 --port 8765

Endpoints:

    GET  /                         the console page
    GET  /api/summary              portfolio counts
    GET  /api/vendors              register + onboarding parse status
    GET  /api/vendors/<slug>       raw register YAML
    GET  /api/controls             control set summary
    GET  /api/monitor              daemon heartbeat / last cycle
    GET  /api/nhis                 portfolio NHI inventory
    POST /api/onboard              run onboarding (JSON body, see _onboard)
    POST /api/assess               run an assessment for one vendor
    POST /api/discover             page Okta / Auth0 (or a recorded fixture) for NHIs
    POST /api/monitor/start        spawn the autonomous monitor
    POST /api/monitor/stop         signal the monitor to exit

The server only ever talks to the local filesystem and (unless the UI checkbox
"offline" is unchecked) makes no network calls. Bind to 0.0.0.0 so the preview
proxy can reach it.
"""

from __future__ import annotations

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import yaml

from .config import DATA_DIR, VENDORS_DIR, RunConfig
from .evaluate import load_controls

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vendor NHI Monitor — NIST 800-53 / SOC 2</title>
<style>
  :root {
    --bg:#0f1420; --panel:#171e2e; --panel2:#1d2640; --line:#2a3552;
    --text:#e8ecf4; --muted:#93a0ba; --accent:#5b8cff; --ok:#3ddc84;
    --warn:#ffb454; --bad:#ff5c6c; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  header { padding:20px 28px; border-bottom:1px solid var(--line);
           display:flex; align-items:baseline; gap:16px; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; }
  header .sub { color:var(--muted); font-size:13px; }
  main { padding:24px 28px; max-width:1200px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:22px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
  .card .n { font-size:26px; font-weight:700; }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:22px; align-items:start; }
  @media (max-width:900px){ .grid{ grid-template-columns:1fr; } }
  section { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:18px 20px; }
  section h2 { font-size:14px; margin:0 0 14px; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
  .badge { display:inline-block; padding:2px 9px; border-radius:99px; font-size:11px; font-weight:600; }
  .b-ok { background:rgba(61,220,132,.14); color:var(--ok); }
  .b-warn { background:rgba(255,180,84,.14); color:var(--warn); }
  .b-bad { background:rgba(255,92,108,.14); color:var(--bad); }
  .b-mut { background:rgba(147,160,186,.14); color:var(--muted); }
  label { display:block; font-size:12px; color:var(--muted); margin:10px 0 4px; }
  input,select,textarea { width:100%; background:var(--panel2); color:var(--text);
    border:1px solid var(--line); border-radius:8px; padding:9px 11px; font-size:14px; }
  textarea { font-family:var(--mono); font-size:12px; }
  button { background:var(--accent); color:#fff; border:0; border-radius:8px;
    padding:10px 16px; font-size:14px; font-weight:600; cursor:pointer; margin-top:14px; }
  button.secondary { background:var(--panel2); border:1px solid var(--line); color:var(--text); }
  button:disabled { opacity:.5; cursor:wait; }
  .check { display:flex; align-items:center; gap:8px; margin-top:12px; }
  .check input { width:auto; }
  .result { margin-top:22px; background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:18px 20px; display:none; }
  .result.show { display:block; }
  pre { background:#0b1018; border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto; font-size:12px; font-family:var(--mono); }
  .blocker { background:rgba(255,92,108,.08); border:1px solid rgba(255,92,108,.35); border-radius:8px; padding:8px 12px; margin:6px 0; font-size:13px; }
  .muted { color:var(--muted); font-size:12px; }
  .row-actions button { margin:0 6px 0 0; padding:5px 10px; font-size:12px; }
  .spin { display:inline-block; width:14px; height:14px; border:2px solid var(--line); border-top-color:var(--accent); border-radius:50%; animation:sp 1s linear infinite; vertical-align:-2px; margin-right:6px; }
  @keyframes sp { to { transform:rotate(360deg); } }
  .pill { display:inline-flex; align-items:center; gap:8px; padding:4px 12px;
          border-radius:99px; font-size:12px; border:1px solid var(--line); }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--muted); }
  .dot.on { background:var(--ok); box-shadow:0 0 0 3px rgba(61,220,132,.18); }
  .dot.stale { background:var(--warn); }
  .dot.off { background:var(--bad); }
  header .grow { flex:1; }
  header button { margin:0; padding:6px 12px; font-size:12px; }
  .stack { display:flex; flex-direction:column; gap:22px; margin-top:22px; }
</style>
</head>
<body>
<header>
  <h1>Vendor AI Risk Analyst</h1>
  <span class="sub">local console — onboard, monitor, inventory NHIs</span>
  <span class="sub" id="model-note"></span>
  <span class="grow"></span>
  <span class="pill" id="mon-pill"><span class="dot off" id="mon-dot"></span><span id="mon-label">monitor: stopped</span></span>
  <button id="mon-toggle" class="secondary" type="button">Start monitor</button>
</header>
<main>
  <div class="cards" id="cards"></div>

  <div class="grid">
    <section>
      <h2>Onboard a vendor</h2>
      <form id="ob-form">
        <label>Vendor name *</label>
        <input id="f-name" required placeholder="e.g. Acme Corp">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div><label>Tier</label>
            <select id="f-tier"><option>high</option><option>critical</option><option>medium</option><option>low</option></select>
          </div>
          <div><label>Category</label>
            <input id="f-category" placeholder="collaboration">
          </div>
        </div>
        <label>Trust center URL (or local HTML file path)</label>
        <input id="f-tc" placeholder="https://acme.safebase.io  |  /path/to/trust_center.html">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div><label>Subprocessor list URL</label><input id="f-sp" placeholder="https://…/subprocessors (optional)"></div>
          <div><label>Changelog URL</label><input id="f-cl" placeholder="https://…/changelog (optional)"></div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div><label>DPA / BAA URL</label><input id="f-dpa" placeholder="https://…/dpa (optional)"></div>
          <div><label>Description</label><input id="f-desc" placeholder="one line (optional)"></div>
        </div>
        <div class="check"><input type="checkbox" id="f-offline" checked><label style="margin:0">offline (no network; use local files only)</label></div>
        <button id="ob-go" type="submit">Onboard vendor</button>
      </form>
    </section>

    <section>
      <h2>Vendors in register</h2>
      <div id="vendors"><span class="muted">loading…</span></div>
    </section>
  </div>

  <div class="stack">
    <section>
      <h2>Continuous monitor</h2>
      <div id="mon-body"><span class="muted">loading…</span></div>
    </section>
    <section>
      <h2>Non-human identities</h2>
      <p class="muted">Pulled from the IdP API (Okta / Auth0), not typed into YAML. Token stays in an environment variable — never paste it here.</p>
      <form id="disc-form" style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end;margin:10px 0 16px">
        <div><label>Provider</label>
          <select id="d-provider">
            <option value="okta">Okta (your IdP)</option>
            <option value="auth0">Auth0 (your IdP)</option>
            <option value="atlassian">Atlassian (Rovo / tokens)</option>
            <option value="slack">Slack (bots)</option>
          </select>
        </div>
        <div><label>Org URL / domain</label>
          <input id="d-base" placeholder="https://your-org.okta.com">
        </div>
        <div><label>Token env var</label>
          <input id="d-token-env" placeholder="OKTA_API_TOKEN">
        </div>
        <button id="d-go" type="submit">Discover</button>
      </form>
      <div id="nhis"><span class="muted">loading…</span></div>
    </section>
  </div>

  <div class="result" id="result">
    <h2 style="color:var(--muted);text-transform:uppercase;font-size:14px;letter-spacing:.07em;margin:0 0 12px">Onboarding result</h2>
    <div id="result-body"></div>
  </div>
</main>

<script>
"use strict";
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function badge(kind, text) {
  const cls = {parsed:"b-ok", ok:"b-ok", covered:"b-ok", blocked:"b-bad", error:"b-bad",
               parse_failed:"b-bad", empty:"b-warn", missing:"b-warn", critical:"b-bad",
               high:"b-warn", medium:"b-mut", low:"b-mut", true:"b-ok", false:"b-bad"}[kind] || "b-mut";
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

async function j(method, url, body) {
  const r = await fetch(url, {method, headers: body ? {"Content-Type":"application/json"} : {},
                              body: body ? JSON.stringify(body) : undefined});
  if (!r.ok) { let t = ""; try { t = await r.text(); } catch {} throw new Error(t || r.statusText); }
  return r.json();
}

function renderMonitor(m) {
  const st = m.status || "stopped";
  const dot = $("mon-dot");
  dot.className = "dot " + (st === "running" ? "on" : st === "stale" ? "stale" : "off");
  $("mon-label").textContent = "monitor: " + st
    + (m.cycles_completed ? ` · cycle ${m.cycles_completed}` : "")
    + (m.next_cycle_at ? ` · next ${String(m.next_cycle_at).slice(11,19)} UTC` : "");
  const btn = $("mon-toggle");
  btn.textContent = st === "running" ? "Stop monitor" : "Start monitor";
  btn.disabled = false;
  const last = m.last_cycle || {};
  const hist = (m.history || []).slice(-5).reverse();
  $("mon-body").innerHTML = `
    <table>
      <tr><th>Status</th><td>${badge(st === "running" ? "ok" : st === "stale" ? "empty" : "missing", st)}
        <span class="muted">pid ${esc(m.pid || "—")} · interval ${esc(m.interval_seconds || "—")}s · offline ${m.offline ? "yes" : "no"}</span></td></tr>
      <tr><th>Heartbeat</th><td>${esc(m.last_heartbeat || "—")}</td></tr>
      <tr><th>Last cycle</th><td>vendors ${esc(last.vendor_count ?? "—")} · NHIs ${esc(last.nhi_count ?? "—")} ·
        changed ${esc(last.changed_sources ?? "—")} · critical ${esc(last.critical ?? "—")} ·
        ${esc(last.duration_seconds ?? "—")}s</td></tr>
    </table>
    ${hist.length ? `<div class="muted" style="margin:10px 0 6px">Recent cycles</div>
      <table><thead><tr><th>Finished</th><th>Vendors</th><th>NHIs</th><th>Changed</th><th>Critical</th><th>Exit</th></tr></thead>
      <tbody>${hist.map(h => `<tr><td>${esc(h.finished_at || "")}</td><td>${esc(h.vendor_count)}</td>
        <td>${esc(h.nhi_count)}</td><td>${esc(h.changed_sources)}</td>
        <td>${esc(h.critical)}</td><td>${esc(h.exit_code)}</td></tr>`).join("")}</tbody></table>` : '<p class="muted">No cycles yet. Start the monitor to assess on a timer while this machine is on.</p>'}`;
}

function renderNhis(rows) {
  if (!rows.length) {
    $("nhis").innerHTML = '<span class="muted">No NHIs inventoried yet. Run an assessment or start the monitor.</span>';
    return;
  }
  $("nhis").innerHTML = `<table><thead><tr>
    <th>Vendor</th><th>Identity</th><th>Kind</th><th>Write scopes</th><th>Owner</th><th>Source</th></tr></thead>
    <tbody>${rows.map(n => {
      const flags = [];
      if (n.orphan) flags.push(badge("blocked", "orphan"));
      if (n.cross_vendor) flags.push(badge("empty", "cross-vendor"));
      const writes = (n.write_scopes || []).join(", ") || "none";
      return `<tr>
        <td><b>${esc(n.vendor_name || n.vendor)}</b><div class="muted">${esc(n.vendor)}</div></td>
        <td>${esc(n.name || n.principal || "—")}<div class="muted">${esc(n.principal || "")} ${flags.join(" ")}</div></td>
        <td>${esc(n.kind || "—")}</td>
        <td>${n.write_scopes && n.write_scopes.length ? badge("bad", writes) : badge("ok", "none")}</td>
        <td>${esc(n.owner || "unknown")}</td>
        <td>${esc(n.source || "—")}</td></tr>`;
    }).join("")}</tbody></table>`;
}

async function refresh() {
  const [s, v, m, n] = await Promise.all([
    j("GET","/api/summary"), j("GET","/api/vendors"),
    j("GET","/api/monitor"), j("GET","/api/nhis")
  ]);
  $("cards").innerHTML = [
    ["Vendors tracked", s.vendors], ["Open findings", s.open_findings],
    ["Gaps", s.gaps], ["NHIs", s.nhis],
    ["Parse-blocked", s.blocked_parses], ["Sources watched", s.watch_sources]
  ].map(([l,n]) => `<div class="card"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`).join("");
  renderMonitor(m);
  renderNhis(n);

  if (!v.length) { $("vendors").innerHTML = '<span class="muted">No vendors yet — onboard the first one.</span>'; return; }
  $("vendors").innerHTML = `
    <table><thead><tr><th>Vendor</th><th>Tier</th><th>Platform</th><th>Subprocessor parse</th><th></th></tr></thead>
    <tbody>${v.map(x => {
      const ps = x.parse || {};
      const pbadge = ps.status === "parsed" ? badge("parsed", `parsed · ${ps.rows} rows`) :
                     ps.status ? badge(ps.status, ps.status) : badge("missing", "no source");
      return `<tr>
        <td><b>${esc(x.vendor)}</b><div class="muted">${esc(x.slug)} · ${esc(x.category||"")}</div></td>
        <td>${badge(x.tier, x.tier)}</td>
        <td>${esc(x.platform || "—")}${x.blocked ? " " + badge("blocked","gated") : ""}</td>
        <td>${pbadge}</td>
        <td class="row-actions">
          <button data-act="assess" data-vendor="${esc(x.slug)}" class="secondary">Assess</button>
          <button data-act="register" data-vendor="${esc(x.slug)}" class="secondary">Register</button>
        </td></tr>`;
    }).join("")}</tbody></table>`;
  document.querySelectorAll("button[data-act]").forEach(b => b.onclick = () => onRowAction(b));
}

async function onRowAction(btn) {
  const slug = btn.dataset.vendor, act = btn.dataset.act;
  if (act === "register") {
    const r = await j("GET", `/api/vendors/${slug}`);
    showResult({title:`vendors/${slug}.yaml`, blocks:[`<pre>${esc(r.yaml)}</pre>`]});
    return;
  }
  btn.disabled = true; btn.innerHTML = '<span class="spin"></span>assessing';
  try {
    const r = await j("POST", "/api/assess", {vendor: slug, offline: $("f-offline").checked});
    showResult({title:`Assessment — ${slug}`, blocks: [
      `<div class="muted">report: ${esc(r.report)}</div>`,
      `<table><tr><th>Findings</th><td>${r.findings} (critical ${r.critical})</td></tr>
       <tr><th>Gaps</th><td>${r.gaps}</td></tr><tr><th>Exit code</th><td>${r.exit_code}</td></tr></table>`
    ]});
  } catch (e) { showResult({title:"Assessment failed", blocks:[`<div class="blocker">${esc(e.message)}</div>`]}); }
  btn.disabled = false; btn.textContent = "Assess";
  refresh();
}

function showResult({title, blocks}) {
  const r = $("result"); r.classList.add("show");
  $("result-body").innerHTML = `<div class="muted" style="margin-bottom:10px">${esc(title)}</div>` + blocks.join("");
  r.scrollIntoView({behavior:"smooth", block:"nearest"});
}

function renderOnboardResult(res) {
  const ps = res.subprocessor_parse || {};
  const rows = (res.subprocessors || []).map(s => `
    <tr><td>${esc(s.name)}</td><td>${esc(s.purpose)}</td><td>${esc(s.region)}</td>
    <td>${esc(s.baa_marker)}</td><td>${s.ai_related ? badge("ok","AI") : "—"} ${s.baa_covered ? badge("ok","covered") : badge("bad","no BAA")}</td></tr>`).join("");
  const blockers = (res.blockers || []).map(b => `<div class="blocker">${esc(b)}</div>`).join("");
  const steps = (res.next_steps || []).map(s => `<li>${esc(s)}</li>`).join("");
  showResult({title: `${res.vendor_name} (${res.slug}) — tier ${res.tier}`, blocks: [
    `<table>
      <tr><th>Trust platform</th><td>${esc(res.platform || "unknown")} ${res.platform_blocked ? badge("blocked","click-through") : badge("ok","reachable")}</td></tr>
      <tr><th>Subprocessor parse</th><td>${ps.status ? badge(ps.status, ps.status + (ps.rows ? ` · ${ps.rows} rows` : "")) : "—"} <span class="muted">${esc(ps.reason || "")}</span></td></tr>
      <tr><th>Register</th><td>${esc(res.register_path || "(dry-run)")}</td></tr>
      ${res.outreach_path ? `<tr><th>Outreach draft</th><td>${esc(res.outreach_path)}</td></tr>` : ""}
    </table>`,
    blockers,
    `<b class="muted">Next steps</b><ol style="margin:6px 0 0;font-size:13px">${steps}</ol>`,
    (res.discovered_urls && Object.keys(res.discovered_urls).length)
      ? `<b class="muted">Discovered artifact URLs</b><pre>${esc(JSON.stringify(res.discovered_urls, null, 2))}</pre>` : "",
    rows ? `<b class="muted">Subprocessors parsed (${(res.subprocessors||[]).length})</b>
      <table><thead><tr><th>Entity</th><th>Purpose</th><th>Region</th><th>BAA marker</th><th>Flags</th></tr></thead><tbody>${rows}</tbody></table>` : ""
  ]});
}

$("ob-form").addEventListener("submit", async e => {
  e.preventDefault();
  const go = $("ob-go"); go.disabled = true; go.innerHTML = '<span class="spin"></span>onboarding';
  try {
    const res = await j("POST", "/api/onboard", {
      name: $("f-name").value.trim(), tier: $("f-tier").value, category: $("f-category").value.trim(),
      description: $("f-desc").value.trim(), trust_center_url: $("f-tc").value.trim(),
      changelog_url: $("f-cl").value.trim(), subprocessors_url: $("f-sp").value.trim(),
      dpa_url: $("f-dpa").value.trim(), offline: $("f-offline").checked
    });
    renderOnboardResult(res);
    refresh();
  } catch (err) {
    showResult({title:"Onboarding failed", blocks:[`<div class="blocker">${esc(err.message)}</div>`]});
  }
  go.disabled = false; go.textContent = "Onboard vendor";
});

$("disc-form").addEventListener("submit", async e => {
  e.preventDefault();
  const go = $("d-go"); go.disabled = true; go.innerHTML = '<span class="spin"></span>discovering';
  try {
    const res = await j("POST", "/api/discover", {
      provider: $("d-provider").value,
      base_url: $("d-base").value.trim(),
      token_env: $("d-token-env").value.trim() || undefined,
      offline: $("f-offline").checked
    });
    showResult({title: `Discovered ${res.count || 0} NHI(s) from ${esc(res.provider || "IdP")}`, blocks: [
      `<div class="muted">pages ${esc(res.pages_fetched)} · truncated ${res.truncated ? "yes" : "no"} · ${esc(res.error || "ok")}</div>`,
      res.warning ? `<div class="blocker">${esc(res.warning)}</div>` : ""
    ]});
    refresh();
  } catch (err) {
    showResult({title:"Discovery failed", blocks:[`<div class="blocker">${esc(err.message)}</div>`]});
  }
  go.disabled = false; go.textContent = "Discover";
});

$("mon-toggle").addEventListener("click", async () => {
  const btn = $("mon-toggle");
  btn.disabled = true;
  try {
    const m = await j("GET", "/api/monitor");
    if (m.status === "running") await j("POST", "/api/monitor/stop", {});
    else await j("POST", "/api/monitor/start", {offline: $("f-offline").checked, interval: 120});
  } catch (e) {
    showResult({title:"Monitor", blocks:[`<div class="blocker">${esc(e.message)}</div>`]});
  }
  setTimeout(refresh, 800);
});

j("GET", "/api/summary").then(s => { $("model-note").textContent = `model: ${s.model} · backend: ${s.backend}`; }).catch(() => {});
refresh();
setInterval(() => { refresh().catch(() => {}); }, 4000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "VRA-WebUI/1.0"

    # --- helpers -----------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, indent=2, default=str).encode("utf-8"))

    def _error(self, message: str, code: int = 400) -> None:
        self._json({"error": message}, code)

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        print(f"[webui] {self.address_string()} {fmt % args}")

    # --- routing -----------------------------------------------------------
    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if path == "/":
                return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            if path == "/api/summary":
                return self._json(_summary())
            if path == "/api/vendors":
                return self._json(_list_vendors())
            if path.startswith("/api/vendors/"):
                slug = path.rsplit("/", 1)[-1]
                yaml_text = _vendor_yaml(slug)
                if yaml_text is None:
                    return self._error(f"no register for vendor {slug!r}", 404)
                return self._json({"slug": slug, "yaml": yaml_text})
            if path == "/api/controls":
                return self._json(_controls())
            if path == "/api/monitor":
                return self._json(_monitor())
            if path == "/api/nhis":
                return self._json(_list_nhis())
            return self._error(f"not found: {path}", 404)
        except Exception as exc:  # pragma: no cover - surface, don't hang the UI
            return self._error(f"server error: {exc}", 500)

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            if path == "/api/onboard":
                return self._onboard(body)
            if path == "/api/assess":
                return self._assess(body)
            if path == "/api/monitor/start":
                return self._monitor_start(body)
            if path == "/api/monitor/stop":
                return self._monitor_stop()
            if path == "/api/discover":
                return self._discover(body)
            return self._error(f"not found: {path}", 404)
        except Exception as exc:
            return self._error(f"server error: {exc}", 500)

    # --- actions -----------------------------------------------------------
    def _onboard(self, body: dict) -> None:
        from .onboard import onboard_vendor

        name = (body.get("name") or "").strip()
        if not name:
            return self._error("name is required")
        cfg = RunConfig(offline=bool(body.get("offline")))
        urls = {k: (body.get(k) or "").strip() for k in
                ("changelog_url", "subprocessors_url", "dpa_url")}
        urls = {k.replace("_url", ""): v for k, v in urls.items() if v}
        result = onboard_vendor(
            name,
            tier=body.get("tier") or "high",
            category=body.get("category") or "other",
            description=body.get("description") or None,
            trust_center_url=(body.get("trust_center_url") or "").strip() or None,
            urls=urls,
            cfg=cfg,
        )
        self._json(result.to_dict())

    def _assess(self, body: dict) -> None:
        from .cli import run as run_assessment

        slug = (body.get("vendor") or "").strip()
        if not slug:
            return self._error("vendor slug is required")
        cfg = RunConfig(offline=bool(body.get("offline")), vendors=[slug])
        try:
            code = run_assessment(cfg)
        except Exception as exc:
            return self._error(f"assessment failed: {exc}", 500)
        report = {}
        latest = cfg.out_dir / "latest.json"
        if latest.exists():
            blob = json.loads(latest.read_text(encoding="utf-8"))
            report = {
                "findings": len(blob.get("findings", [])),
                "critical": len([f for f in blob.get("findings", []) if f.get("severity") == "critical"]),
                "gaps": len(blob.get("gaps", [])),
            }
        self._json({
            "vendor": slug, "exit_code": code,
            "report": str(cfg.out_dir / "latest.md"),
            **report,
        })

    def _monitor_start(self, body: dict) -> None:
        from .monitor import parse_interval, spawn_monitor

        interval = parse_interval(body.get("interval") or 900)
        pid = spawn_monitor(
            offline=bool(body.get("offline", True)),
            interval=interval,
            snapshot=str(body.get("snapshot") or "v1"),
        )
        self._json({"ok": True, "pid": pid, "interval": interval})

    def _monitor_stop(self) -> None:
        from .monitor import stop_monitor

        self._json({"ok": True, "signalled": stop_monitor()})

    def _discover(self, body: dict) -> None:
        """Page the IdP. The token is read from an env var name, never from the body."""
        from .discover import build_parser, run_discover
        from .nhi import NHIInventory

        if body.get("token") or body.get("client_secret"):
            return self._error(
                "do not send tokens in the request body; set an env var and pass token_env"
            )
        argv: list[str] = []
        provider = (body.get("provider") or "").strip()
        base = (body.get("base_url") or body.get("domain") or "").strip()
        fixture = (body.get("fixture") or "").strip()
        vendor = (body.get("vendor") or "").strip()
        if provider:
            argv.extend(["--provider", provider])
        if base:
            argv.extend(["--base-url", base])
        if body.get("token_env"):
            argv.extend(["--token-env", str(body["token_env"])])
        if fixture:
            argv.extend(["--fixture", fixture])
        if vendor:
            argv.extend(["--vendor", vendor])
        if body.get("offline"):
            argv.append("--offline")
        if not fixture and not base and not vendor:
            argv.extend(["--fixture", "sandbox/probe/idp/okta_pages.json"])
        try:
            args = build_parser().parse_args(argv)
            code = run_discover(args)
        except Exception as exc:
            return self._error(f"discover failed: {exc}", 500)
        rows = NHIInventory().all()
        self._json({
            "ok": code == 0,
            "exit_code": code,
            "count": len(rows),
            "provider": provider or None,
            "identities": rows[:200],
        })


# ---------------------------------------------------------------------------
# API data
# ---------------------------------------------------------------------------


def _load_registers() -> list[dict]:
    out = []
    for path in sorted(VENDORS_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data["_path"] = str(path)
            out.append(data)
    return out


def _findings_blob() -> dict:
    path = DATA_DIR / "findings.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _summary() -> dict:
    vendors = _load_registers()
    blob = _findings_blob()
    findings = blob.get("findings", [])
    open_findings = [f for f in findings if f.get("state") != "closed"]
    blocked = 0
    watch_sources = 0
    for v in vendors:
        onboarding = v.get("onboarding") or {}
        sp = onboarding.get("subprocessor_parse") or {}
        if sp.get("status") in ("blocked", "error", "empty", "missing", "parse_failed"):
            blocked += 1
        watch_sources += len(v.get("watch") or {})
    nhis = 0
    nhi_path = DATA_DIR / "nhis.json"
    if nhi_path.exists():
        try:
            nhis = len(json.loads(nhi_path.read_text(encoding="utf-8")).get("identities", []))
        except Exception:
            nhis = 0
    if not nhis:
        nhis = sum(len(v.get("nhis") or []) for v in vendors)
    return {
        "vendors": len(vendors),
        "open_findings": len(open_findings),
        "gaps": len([g for g in findings if g.get("kind") == "gap"]),
        "blocked_parses": blocked,
        "watch_sources": watch_sources,
        "nhis": nhis,
        "model": os.environ.get("VRA_MODEL", "qwen2.5:7b-instruct"),
        "backend": "offline-heuristic",
    }


def _monitor() -> dict:
    from .monitor import read_status

    return read_status()


def _list_nhis() -> list[dict]:
    path = DATA_DIR / "nhis.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8")).get("identities", [])
        except Exception:
            pass
    out = []
    for v in _load_registers():
        for n in v.get("nhis") or []:
            out.append({
                "vendor": v.get("slug"),
                "vendor_name": v.get("vendor"),
                "name": n.get("name"),
                "kind": n.get("kind"),
                "principal": n.get("principal"),
                "write_scopes": n.get("write_scopes") or [],
                "owner": n.get("owner"),
                "source": "register",
                "cross_vendor": bool(n.get("resides_in") and n.get("resides_in") != v.get("slug")),
                "orphan": False,
            })
    return out


def _list_vendors() -> list[dict]:
    out = []
    for v in _load_registers():
        onboarding = v.get("onboarding") or {}
        sp = onboarding.get("subprocessor_parse") or {}
        out.append({
            "vendor": v.get("vendor", "?"),
            "slug": v.get("slug", "?"),
            "tier": v.get("tier", "?"),
            "category": v.get("category", ""),
            "platform": onboarding.get("platform"),
            "blocked": bool(onboarding.get("platform_blocked")),
            "parse": sp,
            "features": len(v.get("ai_surface") or []),
        })
    return out


def _vendor_yaml(slug: str) -> str | None:
    path = VENDORS_DIR / f"{slug}.yaml"
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _controls() -> list[dict]:
    return [
        {
            "id": c.id,
            "question": c.question,
            "severity": c.severity,
            "citation": c.citation,
        }
        for c in load_controls()
    ]


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    cfg = RunConfig()
    p = argparse.ArgumentParser(
        prog="vra webui",
        description="Local onboarding console. Open the printed URL in a browser.",
    )
    p.add_argument("--host", default=cfg.webui_host, help=f"bind address (default {cfg.webui_host})")
    p.add_argument("--port", type=int, default=cfg.webui_port, help=f"bind port (default {cfg.webui_port})")
    return p


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True


def start_server(host: str, port: int, background: bool = False) -> ThreadingHTTPServer:
    """Bind the console. ``background=True`` serves on a daemon thread (monitor --webui)."""
    server = _Server((host, port), _Handler)
    if background:
        thread = threading.Thread(target=server.serve_forever, name="vra-webui", daemon=True)
        thread.start()
    return server


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = start_server(args.host, args.port)
    host, port = server.server_address
    print(f"vra webui: console on http://{host}:{port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nvra webui: stopped")
    return 0
