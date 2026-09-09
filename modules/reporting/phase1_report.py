"""Phase 1 (Reconnaissance) - self-contained HTML report generator.

This module turns the engagement state produced by Phase 1 (hosts,
services, domains, users, findings, ...) into a single, dependency-free
HTML file. The output embeds its own CSS so the report can be opened in
any browser or shared as a standalone artefact - no templating engine
and no external assets are required.

Usage (standalone)::

    python3 -m modules.reporting.phase1_report loot/state.json reports/phase1.html

Usage (programmatic)::

    from modules.reporting.phase1_report import generate_from_state_file
    generate_from_state_file("loot/state.json", "reports/phase1.html")
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.methodology import explain

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Severity ordering, highest first. Drives sorting and the summary counters.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Well-known AD-related ports mapped to a short, human-readable role. Used to
# annotate the per-host service table so the report reads at a glance.
_PORT_ROLES = {
    53: "DNS",
    88: "Kerberos",
    135: "RPC / EPM",
    139: "NetBIOS",
    389: "LDAP",
    445: "SMB",
    464: "kpasswd",
    636: "LDAPS",
    1433: "MSSQL",
    3268: "Global Catalog",
    3269: "Global Catalog (TLS)",
    3389: "RDP",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    8080: "HTTP (alt)",
    8443: "HTTPS (alt)",
}


# ---------------------------------------------------------------------------
# Small HTML helpers
# ---------------------------------------------------------------------------

def _esc(value: Any) -> str:
    """HTML-escape any value, rendering ``None`` as an em dash."""
    if value is None or value == "":
        return "-"
    return html.escape(str(value))


def _badge(text: str, kind: str = "neutral") -> str:
    return f'<span class="badge badge-{kind}">{_esc(text)}</span>'


def _copyable(value: Any, *, kind: str = "cmd") -> str:
    """Render a value in a wrapping box with a "Copy" button.

    Used for long, copy-and-continue strings (commands, Kerberos tickets) that
    would otherwise overflow the table. The real (unescaped) value is placed in
    a ``data-copy`` attribute the inline script reads on click.
    """
    if value is None or value == "":
        return "-"
    raw = str(value)
    # The visible text is HTML-escaped; the copy payload rides in an attribute
    # (also escaped so quotes/brackets cannot break out of it).
    return (
        f'<div class="copybox copybox-{kind}">'
        f'<button class="copy-btn" type="button" data-copy="{_esc(raw)}" '
        f'aria-label="Copy to clipboard">Copy</button>'
        f'<code class="copybox-val">{_esc(raw)}</code>'
        f"</div>"
    )


def _command_block(command: Any) -> str:
    """Render the command that produced a finding, with a copy button."""
    if not command:
        return ""
    return (
        '<div class="finding-command">'
        '<span class="method-label">Command</span>'
        f"{_copyable(command, kind='cmd')}"
        "</div>"
    )


def _sev_badge(severity: str) -> str:
    sev = (severity or "info").lower()
    if sev not in _SEVERITY_ORDER:
        sev = "info"
    return f'<span class="sev sev-{sev}">{sev.upper()}</span>'


def _fmt_ts(ts: str) -> str:
    """Render an ISO timestamp as ``YYYY-MM-DD HH:MM:SS`` (best effort)."""
    if not ts:
        return "-"
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return _esc(ts)


def _ip_sort_key(ip: str) -> tuple:
    """Numeric sort key for an IPv4 string; falls back to the raw string."""
    try:
        return tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (ip,)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_summary(state: dict) -> str:
    hosts = state.get("hosts", {}) or {}
    domains = state.get("domains", {}) or {}
    users = state.get("users", []) or []
    findings = state.get("findings", []) or []
    creds = state.get("credentials", []) or []
    cas = state.get("certificate_authorities", []) or []

    dc_count = sum(1 for h in hosts.values() if h.get("is_dc"))
    relay_targets = sum(
        1 for h in hosts.values() if (h.get("smb_signing") or "").lower() == "disabled"
    )

    sev_counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    cards = [
        ("Hosts", len(hosts), "primary"),
        ("Domain Controllers", dc_count, "accent"),
        ("Domains", len(domains), "primary"),
        ("Users", len(users), "primary"),
        ("Credentials", len(creds), "primary"),
        ("Cert. Authorities", len(cas), "primary"),
        ("SMB relay targets", relay_targets, "warn" if relay_targets else "muted"),
        ("Findings", len(findings), "primary"),
    ]

    card_html = "\n".join(
        f'<div class="stat stat-{kind}"><div class="stat-num">{val}</div>'
        f'<div class="stat-label">{_esc(label)}</div></div>'
        for label, val, kind in cards
    )

    # Severity breakdown strip.
    sev_html = "".join(
        f'<span class="sev-pill sev-{s}">{s.upper()}: {sev_counts[s]}</span>'
        for s in _SEVERITY_ORDER
        if sev_counts[s]
    ) or '<span class="muted">No findings recorded.</span>'

    return f"""
    <section id="overview">
      <h2>Overview</h2>
      <div class="stats-grid">{card_html}</div>
      <div class="sev-strip">{sev_html}</div>
    </section>"""


def _render_domains(state: dict) -> str:
    domains = state.get("domains", {}) or {}
    if not domains:
        return ""

    rows = []
    for name in sorted(domains.keys()):
        dom = domains[name]
        ncs = dom.get("naming_contexts") or []
        nc_html = (
            "<ul class='nc-list'>"
            + "".join(f"<li><code>{_esc(nc)}</code></li>" for nc in ncs)
            + "</ul>"
            if ncs
            else "-"
        )
        rows.append(
            f"<tr><td><strong>{_esc(dom.get('name', name))}</strong></td>"
            f"<td><code>{_esc(dom.get('dns'))}</code></td>"
            f"<td>{nc_html}</td></tr>"
        )

    return f"""
    <section id="domains">
      <h2>Domains &amp; Forest Structure</h2>
      <table>
        <thead><tr><th>Domain</th><th>DNS host</th><th>Naming contexts</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>"""


def _render_host_table(hosts: list[dict]) -> str:
    """Compact one-row-per-host index table."""
    rows = []
    for h in hosts:
        flags = []
        if h.get("is_dc"):
            flags.append(_badge("DC", "accent"))
        if h.get("is_adcs"):
            flags.append(_badge("ADCS", "accent"))
        smb = (h.get("smb_signing") or "").lower()
        if smb == "disabled":
            flags.append(_badge("SMB relay", "warn"))
        for tag in h.get("tags", []):
            if tag in ("smb-null-session", "ldap-anon-bind"):
                flags.append(_badge(tag, "info"))
        flag_html = " ".join(flags) or "-"

        ip = h.get("ip", "")
        rows.append(
            f"<tr>"
            f'<td><a href="#host-{_esc(ip)}"><code>{_esc(ip)}</code></a></td>'
            f"<td>{_esc(h.get('hostname'))}</td>"
            f"<td>{_esc(h.get('os'))}</td>"
            f"<td>{_esc(h.get('domain'))}</td>"
            f"<td>{len(h.get('services', []))}</td>"
            f"<td>{flag_html}</td>"
            f"</tr>"
        )

    return f"""
      <table>
        <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Domain</th>
        <th>Ports</th><th>Flags</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>"""


def _signing_badge(value: str | None) -> str:
    v = (value or "").lower()
    if v in ("required", "enabled"):
        return _badge(value, "ok")
    if v in ("disabled", "not-required"):
        return _badge(value, "warn")
    if not v:
        return "-"
    return _badge(value, "neutral")


def _render_host_detail(h: dict) -> str:
    ip = h.get("ip", "")

    # Header flags.
    flags = []
    if h.get("is_dc"):
        flags.append(_badge("Domain Controller", "accent"))
    if h.get("is_adcs"):
        flags.append(_badge("ADCS", "accent"))
    flag_html = " ".join(flags)

    # Service table with inferred roles.
    svc_rows = []
    for s in sorted(h.get("services", []), key=lambda x: x.get("port", 0)):
        port = s.get("port", "")
        role = _PORT_ROLES.get(port, "")
        svc_rows.append(
            f"<tr><td><code>{_esc(port)}/{_esc(s.get('proto', 'tcp'))}</code></td>"
            f"<td>{_esc(s.get('name'))}</td>"
            f"<td>{_esc(role) if role else '-'}</td>"
            f"<td>{_esc(s.get('banner'))}</td></tr>"
        )
    svc_table = (
        "<table class='inner'><thead><tr><th>Port</th><th>Service</th>"
        "<th>Role</th><th>Banner</th></tr></thead><tbody>"
        + "".join(svc_rows)
        + "</tbody></table>"
        if svc_rows
        else "<p class='muted'>No open ports recorded.</p>"
    )

    # Shares.
    shares = h.get("shares") or []
    if shares:
        share_rows = "".join(
            f"<tr><td><code>{_esc(sh.get('name'))}</code></td>"
            f"<td>{_esc(sh.get('remark') or sh.get('comment'))}</td></tr>"
            for sh in shares
        )
        share_html = (
            "<h4>SMB shares</h4><table class='inner'><thead><tr><th>Share</th>"
            f"<th>Remark</th></tr></thead><tbody>{share_rows}</tbody></table>"
        )
    else:
        share_html = ""

    # RID-brute users.
    rid_users = h.get("rid_users") or []
    if rid_users:
        rid_rows = "".join(
            f"<tr><td><code>{_esc(u.get('rid'))}</code></td>"
            f"<td>{_esc(u.get('name'))}</td>"
            f"<td>{_esc(u.get('type'))}</td></tr>"
            for u in rid_users
        )
        rid_html = (
            "<h4>RID-brute results</h4><table class='inner'><thead><tr>"
            "<th>RID</th><th>Name</th><th>Type</th></tr></thead>"
            f"<tbody>{rid_rows}</tbody></table>"
        )
    else:
        rid_html = ""

    # Tags.
    tag_html = (
        " ".join(_badge(t, "info") for t in h.get("tags", []))
        if h.get("tags")
        else "-"
    )

    meta = f"""
      <table class='kv'>
        <tr><th>IP</th><td><code>{_esc(ip)}</code></td>
            <th>Hostname</th><td>{_esc(h.get('hostname'))}</td></tr>
        <tr><th>OS</th><td>{_esc(h.get('os'))}</td>
            <th>Domain</th><td>{_esc(h.get('domain'))}</td></tr>
        <tr><th>MAC</th><td><code>{_esc(h.get('mac'))}</code></td>
            <th>Tags</th><td>{tag_html}</td></tr>
        <tr><th>SMB signing</th><td>{_signing_badge(h.get('smb_signing'))}</td>
            <th>LDAP signing</th><td>{_signing_badge(h.get('ldap_signing'))}</td></tr>
      </table>"""

    return f"""
      <article class="host-card" id="host-{_esc(ip)}">
        <div class="host-head">
          <h3><code>{_esc(ip)}</code> - {_esc(h.get('hostname') or 'unknown')}</h3>
          <div>{flag_html}</div>
        </div>
        {meta}
        <h4>Services ({len(h.get('services', []))})</h4>
        {svc_table}
        {share_html}
        {rid_html}
      </article>"""


def _render_hosts(state: dict) -> str:
    hosts_dict = state.get("hosts", {}) or {}
    if not hosts_dict:
        return """
    <section id="hosts"><h2>Hosts</h2>
    <p class="muted">No live hosts recorded.</p></section>"""

    # DCs first, then by IP.
    hosts = sorted(
        hosts_dict.values(),
        key=lambda h: (not h.get("is_dc"), _ip_sort_key(h.get("ip", ""))),
    )

    index = _render_host_table(hosts)
    details = "\n".join(_render_host_detail(h) for h in hosts)

    return f"""
    <section id="hosts">
      <h2>Hosts ({len(hosts)})</h2>
      {index}
      <h3 class="sub">Host details</h3>
      {details}
    </section>"""


def _render_findings(state: dict) -> str:
    findings = state.get("findings", []) or []
    if not findings:
        return """
    <section id="findings"><h2>Findings</h2>
    <p class="muted">No findings recorded.</p></section>"""

    def _key(f: dict) -> tuple:
        sev = (f.get("severity") or "info").lower()
        rank = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
        return (rank, f.get("host", ""), f.get("id", ""))

    rows = []
    for f in sorted(findings, key=_key):
        # "How it was found" - detailed methodology, plus any captured evidence.
        method = explain(f).detail
        method_html = (
            f'<div class="finding-method">'
            f'<span class="method-label">How it was found</span> {_esc(method)}'
            f"</div>"
        )
        evidence = f.get("evidence")
        evidence_html = (
            f'<pre class="evidence">{_esc(evidence)}</pre>' if evidence else ""
        )
        command_html = _command_block(f.get("command"))
        desc_cell = (
            f'<div class="finding-desc">{_esc(f.get("description"))}</div>'
            f"{method_html}{command_html}{evidence_html}"
        )
        rows.append(
            f"<tr>"
            f"<td>{_sev_badge(f.get('severity'))}</td>"
            f"<td><code>{_esc(f.get('id'))}</code></td>"
            f"<td>{_esc(f.get('title'))}</td>"
            f"<td><code>{_esc(f.get('host'))}</code></td>"
            f"<td>{desc_cell}</td>"
            f"<td>{_esc(f.get('remediation'))}</td>"
            f"</tr>"
        )

    return f"""
    <section id="findings">
      <h2>Findings ({len(findings)})</h2>
      <table>
        <thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Host</th>
        <th>Description &amp; methodology</th><th>Remediation</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>"""


def _render_users(state: dict) -> str:
    users = sorted(state.get("users", []) or [])
    if not users:
        return ""
    items = "".join(f"<li><code>{_esc(u)}</code></li>" for u in users)
    return f"""
    <section id="users">
      <h2>Enumerated Users ({len(users)})</h2>
      <ul class="user-grid">{items}</ul>
    </section>"""


def _render_credentials(state: dict) -> str:
    creds = state.get("credentials", []) or []
    if not creds:
        return ""

    rows = []
    for c in creds:
        # Each secret gets a labelled, wrapping copy box so long blobs (AS-REP /
        # TGS tickets, hashes) do not overflow the table horizontally.
        secrets = []
        for label, key in (
            ("password", "password"), ("NT hash", "nt_hash"),
            ("LM hash", "lm_hash"), ("ticket", "ticket"),
        ):
            if c.get(key):
                secrets.append(
                    f'<div class="secret-row"><span class="secret-label">{label}</span>'
                    f"{_copyable(c.get(key), kind='secret')}</div>"
                )
        secret_html = "".join(secrets) or "-"
        valid_on = ", ".join(c.get("valid_on", []) or []) or "-"
        rows.append(
            f"<tr><td>{_esc(c.get('username'))}</td>"
            f"<td>{_esc(c.get('domain'))}</td>"
            f"<td>{secret_html}</td>"
            f"<td>{_esc(c.get('source'))}</td>"
            f"<td>{valid_on}</td></tr>"
        )

    return f"""
    <section id="credentials">
      <h2>Credentials ({len(creds)})</h2>
      <p class="muted">Secret values are shown in cleartext.</p>
      <table>
        <thead><tr><th>Username</th><th>Domain</th><th>Secrets</th>
        <th>Source</th><th>Valid on</th></tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>"""


def _render_cas(state: dict) -> str:
    cas = state.get("certificate_authorities", []) or []
    if not cas:
        return ""
    rows = "".join(
        f"<tr><td><code>{_esc(c.get('ip'))}</code></td>"
        f"<td>{_esc(c.get('ca_name'))}</td>"
        f"<td><code>{_esc(c.get('web_enrollment_url'))}</code></td>"
        f"<td>{' '.join(_badge(t, 'info') for t in c.get('tags', [])) or '-'}</td></tr>"
        for c in cas
    )
    return f"""
    <section id="cas">
      <h2>Certificate Authorities ({len(cas)})</h2>
      <table>
        <thead><tr><th>IP</th><th>CA name</th><th>Web enrollment</th><th>Tags</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


# ---------------------------------------------------------------------------
# Page assembly
# ---------------------------------------------------------------------------

_CSS = """
:root{
  --navy:#1b2440; --navy2:#2a3a66; --accent:#5b8def; --accent2:#3a6fd8;
  --bg:#f4f6fb; --card:#ffffff; --ink:#1f2733; --muted:#7a869a;
  --line:#e2e7f0; --ok:#1f9d6b; --warn:#d97706; --warnbg:#fff4e5;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  line-height:1.5;font-size:14px}
code{font-family:"JetBrains Mono",Consolas,Menlo,monospace;font-size:.9em;
  background:#eef1f7;padding:.05rem .35rem;border-radius:4px}
.wrap{max-width:1180px;margin:0 auto;padding:0 1.5rem 4rem}
header.page{background:linear-gradient(120deg,var(--navy),var(--navy2));
  color:#fff;padding:2.2rem 0 2rem;margin-bottom:1.5rem;
  box-shadow:0 2px 12px rgba(0,0,0,.18)}
header.page .wrap{padding-bottom:0}
header.page h1{margin:0 0 .3rem;font-size:1.7rem;letter-spacing:.3px}
header.page .phase{color:var(--accent);font-weight:600}
header.page .meta{color:#c6cfe2;font-size:.9rem;margin-top:.6rem}
header.page .meta span{margin-right:1.4rem}
nav.toc{margin:.4rem 0 0;display:flex;flex-wrap:wrap;gap:.5rem}
nav.toc a{color:#dce4f7;text-decoration:none;font-size:.85rem;
  border:1px solid rgba(255,255,255,.25);padding:.2rem .7rem;border-radius:20px}
nav.toc a:hover{background:rgba(255,255,255,.12)}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;
  padding:1.3rem 1.5rem;margin-bottom:1.4rem;box-shadow:0 1px 3px rgba(20,30,60,.05)}
h2{margin:0 0 1rem;font-size:1.25rem;color:var(--navy);
  border-bottom:2px solid var(--line);padding-bottom:.5rem}
h3{color:var(--navy2);margin:.2rem 0 .6rem}
h3.sub{margin-top:1.6rem;font-size:1.05rem;color:var(--muted);
  text-transform:uppercase;letter-spacing:.08em;font-weight:600}
h4{margin:1rem 0 .4rem;color:var(--navy2);font-size:.95rem}
.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;margin:.4rem 0 .2rem;font-size:.9rem}
th,td{border:1px solid var(--line);padding:.45rem .6rem;text-align:left;vertical-align:top}
thead th{background:var(--navy);color:#fff;font-weight:600;white-space:nowrap}
tbody tr:nth-child(even){background:#fafbfe}
table.inner thead th{background:var(--navy2)}
table.kv th{background:#f0f3fa;color:var(--navy2);width:13%;white-space:nowrap}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.9rem}
.stat{border:1px solid var(--line);border-radius:10px;padding:1rem;text-align:center;
  background:#fbfcff}
.stat-num{font-size:1.9rem;font-weight:700;color:var(--navy)}
.stat-label{color:var(--muted);font-size:.8rem;text-transform:uppercase;
  letter-spacing:.05em;margin-top:.2rem}
.stat-accent .stat-num{color:var(--accent2)}
.stat-warn{background:var(--warnbg);border-color:#f3d9b0}
.stat-warn .stat-num{color:var(--warn)}
.stat-muted .stat-num{color:var(--muted)}
.sev-strip{margin-top:1rem;display:flex;flex-wrap:wrap;gap:.5rem}
.sev-pill{padding:.25rem .7rem;border-radius:20px;font-size:.78rem;font-weight:700;color:#fff}
.badge{display:inline-block;padding:.12rem .55rem;border-radius:20px;font-size:.74rem;
  font-weight:600;border:1px solid transparent;white-space:nowrap}
.badge-neutral{background:#eef1f7;color:#41506b}
.badge-info{background:#e7eefc;color:#2a4fa0;border-color:#cfddf8}
.badge-accent{background:var(--accent);color:#fff}
.badge-ok{background:#e3f6ee;color:var(--ok);border-color:#bfe9d6}
.badge-warn{background:#fdeada;color:#b45309;border-color:#f6d4a8}
.sev{display:inline-block;padding:.12rem .55rem;border-radius:6px;font-size:.74rem;
  font-weight:700;color:#fff;white-space:nowrap}
.sev-critical,.sev-pill.sev-critical{background:#b00020}
.sev-high,.sev-pill.sev-high{background:#e05a00}
.sev-medium,.sev-pill.sev-medium{background:#c79100}
.sev-low,.sev-pill.sev-low{background:#3d8b40}
.sev-info,.sev-pill.sev-info{background:#6b7280}
.host-card{border:1px solid var(--line);border-radius:10px;padding:1rem 1.2rem;
  margin:1rem 0;background:#fcfdff}
.host-head{display:flex;justify-content:space-between;align-items:center;
  flex-wrap:wrap;gap:.5rem;border-bottom:1px solid var(--line);
  padding-bottom:.5rem;margin-bottom:.6rem}
.host-head h3{margin:0}
.nc-list{margin:.2rem 0;padding-left:1.1rem}
.nc-list li{margin:.1rem 0}
.user-grid{list-style:none;padding:0;margin:0;display:grid;
  grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.3rem}
.user-grid li{padding:.15rem 0}
.finding-desc{margin-bottom:.45rem}
.finding-method{font-size:.85rem;color:var(--navy2);background:#f0f4fc;
  border-left:3px solid var(--accent);border-radius:4px;padding:.4rem .6rem}
.finding-method .method-label{display:inline-block;font-weight:700;
  text-transform:uppercase;letter-spacing:.04em;font-size:.7rem;color:var(--accent2);
  margin-right:.4rem}
pre.evidence{margin:.5rem 0 0;padding:.5rem .6rem;background:#1b2440;color:#dce4f7;
  border-radius:6px;font-family:"JetBrains Mono",Consolas,Menlo,monospace;
  font-size:.78rem;line-height:1.4;white-space:pre-wrap;word-break:break-word;
  max-height:240px;overflow:auto}
.finding-command{margin-top:.45rem;font-size:.85rem}
.finding-command .method-label{display:inline-block;font-weight:700;
  text-transform:uppercase;letter-spacing:.04em;font-size:.7rem;color:var(--accent2);
  margin-bottom:.2rem}
/* Copy box: wrapping code + a Copy button; keeps long blobs from overflowing. */
.copybox{display:flex;align-items:flex-start;gap:.4rem;margin:.15rem 0;
  max-width:100%}
.copybox-val{flex:1 1 auto;min-width:0;display:block;background:#1b2440;color:#dce4f7;
  border-radius:6px;padding:.4rem .55rem;
  font-family:"JetBrains Mono",Consolas,Menlo,monospace;font-size:.78rem;
  line-height:1.4;white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere}
.copybox-secret .copybox-val{max-height:120px;overflow:auto}
.copy-btn{flex:0 0 auto;cursor:pointer;border:1px solid var(--line);
  background:var(--accent);color:#fff;border-radius:6px;padding:.25rem .6rem;
  font-size:.72rem;font-weight:700;letter-spacing:.03em}
.copy-btn:hover{background:var(--accent2)}
.copy-btn.copied{background:var(--ok);border-color:var(--ok)}
.secret-row{display:flex;align-items:flex-start;gap:.4rem;margin:.2rem 0}
.secret-label{flex:0 0 auto;font-weight:600;color:var(--navy2);font-size:.8rem;
  padding-top:.45rem;min-width:64px}
footer.page{color:var(--muted);font-size:.8rem;text-align:center;margin-top:1rem}
a{color:var(--accent2)}
"""


# Inline clipboard script (no external deps - the report is a standalone file).
# The report is usually opened from disk (file://). Browsers treat file:// as a
# secure context, yet navigator.clipboard.writeText frequently fails there
# (document-not-focused / permission), and its async rejection lands OUTSIDE the
# click's user-activation window, so an execCommand fallback fired from the
# rejection handler is a no-op. We therefore run the synchronous
# execCommand('copy') FIRST - inside the user gesture, where it works on file://
# in Chrome/Firefox - and only reach for the async Clipboard API if it fails.
_COPY_JS = """
<script>
(function () {
  function execCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    // position:fixed + top:0/left:0 + opacity:0 avoids scroll jump on focus.
    ta.style.position = 'fixed';
    ta.style.top = '0';
    ta.style.left = '0';
    ta.style.width = '1px';
    ta.style.height = '1px';
    ta.style.padding = '0';
    ta.style.border = 'none';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    var sel = document.getSelection();
    var prev = sel && sel.rangeCount > 0 ? sel.getRangeAt(0) : null;
    ta.focus();
    ta.select();
    try { ta.setSelectionRange(0, text.length); } catch (e) {}
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    if (prev && sel) { sel.removeAllRanges(); sel.addRange(prev); }
    return ok;
  }
  function flash(btn, ok) {
    btn.textContent = ok ? 'Copied' : 'Press Ctrl+C';
    btn.classList.add('copied');
    setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1400);
  }
  document.addEventListener('click', function (e) {
    var btn = e.target && e.target.closest ? e.target.closest('.copy-btn') : null;
    if (!btn) return;
    e.preventDefault();
    var text = btn.getAttribute('data-copy') || '';
    // Synchronous path first: preserves user activation, works on file://.
    if (execCopy(text)) { flash(btn, true); return; }
    // Last resort: async Clipboard API (served pages / browsers without execCommand).
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { flash(btn, true); },
        function () { flash(btn, false); }
      );
    } else {
      flash(btn, false);
    }
  });
})();
</script>
"""


def render_html(state: dict, meta: dict | None = None) -> str:
    """Return the full HTML document for the given engagement state."""
    meta = meta or {}
    name = meta.get("name") or "Mavama engagement"
    operator = meta.get("operator") or "unknown"
    started_at = _fmt_ts(state.get("started_at", ""))
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scope = ", ".join(meta.get("scope", []) or []) or "-"

    sections = [
        _render_summary(state),
        _render_domains(state),
        _render_hosts(state),
        _render_findings(state),
        _render_users(state),
        _render_credentials(state),
        _render_cas(state),
    ]
    body = "\n".join(s for s in sections if s)

    # Table of contents - only link sections that were rendered.
    toc_items = [
        ("overview", "Overview"),
        ("domains", "Domains"),
        ("hosts", "Hosts"),
        ("findings", "Findings"),
        ("users", "Users"),
        ("credentials", "Credentials"),
        ("cas", "Cert. Authorities"),
    ]
    toc = "".join(
        f'<a href="#{anchor}">{label}</a>'
        for anchor, label in toc_items
        if f'id="{anchor}"' in body
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mavama - AD Audit Report - {_esc(name)}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="page">
  <div class="wrap">
    <h1>Mavama - <span class="phase">Active Directory Audit Report</span></h1>
    <div class="meta">
      <span><strong>Engagement:</strong> {_esc(name)}</span>
      <span><strong>Operator:</strong> {_esc(operator)}</span>
      <span><strong>Scope:</strong> {scope}</span>
    </div>
    <div class="meta">
      <span><strong>Engagement started:</strong> {started_at}</span>
      <span><strong>Report generated:</strong> {generated_at}</span>
    </div>
    <nav class="toc">{toc}</nav>
  </div>
</header>
<div class="wrap">
{body}
  <footer class="page">
    Generated by Mavama - Active Directory audit report.
    For authorized security testing only.
  </footer>
</div>
{_COPY_JS}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def generate_report(
    state: dict,
    output_path: str | Path,
    meta: dict | None = None,
) -> Path:
    """Render ``state`` to ``output_path`` and return the written path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(state, meta), encoding="utf-8")
    return out


def generate_from_state_file(
    state_path: str | Path,
    output_path: str | Path,
    meta: dict | None = None,
) -> Path:
    """Load a ``state.json`` produced by Phase 1 and render the report."""
    with Path(state_path).open("r", encoding="utf-8") as fh:
        state = json.load(fh)
    return generate_report(state, output_path, meta)


def generate_from_target_manager(
    tm: Any,
    output_path: str | Path,
    meta: dict | None = None,
) -> Path:
    """Render directly from a live :class:`TargetManager` instance."""
    return generate_report(tm.to_dict(), output_path, meta)


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python3 -m modules.reporting.phase1_report "
            "<state.json> [output.html]",
            file=sys.stderr,
        )
        raise SystemExit(2)

    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else "reports/phase1_report.html"
    path = generate_from_state_file(src, dst)
    print(f"[+] Phase 1 report written to {path}")
