"""reportgen.py — Master report generator: aggregate ALL omega JSON findings into PDF+HTML."""
from __future__ import annotations
import json, re, os, time, webbrowser
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **kw): print(*a)
    console = Console()
    Table = Panel = box = None

BANNER = r"""
██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  OMEGA-CLI v1.7.0 — OSINT & Passive Recon Toolkit
"""

CSS = """
:root {
  --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
  --border: #30363d; --accent: #ff2d78; --accent2: #58a6ff;
  --text: #c9d1d9; --dim: #8b949e; --green: #3fb950; --red: #f85149;
  --yellow: #d29922; --orange: #e3b341;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
.header { background: linear-gradient(135deg, #0d1117, #161b22); border-bottom: 2px solid var(--accent); padding: 32px 40px; }
.logo { font-size: 2.2rem; font-weight: 900; color: var(--accent); letter-spacing: 2px; }
.logo span { color: var(--accent2); }
.meta { color: var(--dim); margin-top: 8px; font-size: 13px; }
.target-badge { display: inline-block; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 4px 12px; margin-top: 10px; color: var(--accent2); font-family: monospace; font-size: 15px; }
.container { max-width: 1200px; margin: 0 auto; padding: 32px 40px; }
.section { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 24px; overflow: hidden; }
.section-header { background: var(--bg3); padding: 14px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
.section-title { font-size: 1rem; font-weight: 700; color: var(--text); }
.section-badge { background: var(--accent); color: #fff; border-radius: 12px; padding: 2px 8px; font-size: 11px; font-weight: 700; }
.section-body { padding: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 16px; margin-bottom: 20px; }
.stat-card { background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
.stat-num { font-size: 2rem; font-weight: 900; color: var(--accent2); }
.stat-label { color: var(--dim); font-size: 12px; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
table { width: 100%; border-collapse: collapse; }
th { background: var(--bg3); padding: 10px 14px; text-align: left; color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
td { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 13px; word-break: break-all; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg3); }
.tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; margin: 1px; }
.tag-red { background: rgba(248,81,73,0.15); color: var(--red); border: 1px solid rgba(248,81,73,0.3); }
.tag-green { background: rgba(63,185,80,0.15); color: var(--green); border: 1px solid rgba(63,185,80,0.3); }
.tag-yellow { background: rgba(210,153,34,0.15); color: var(--yellow); border: 1px solid rgba(210,153,34,0.3); }
.tag-blue { background: rgba(88,166,255,0.15); color: var(--accent2); border: 1px solid rgba(88,166,255,0.3); }
.risk-bar { height: 8px; border-radius: 4px; background: var(--border); overflow: hidden; margin-top: 6px; }
.risk-fill { height: 100%; border-radius: 4px; }
pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-family: 'Fira Code', monospace; font-size: 12px; line-height: 1.6; }
.finding { padding: 10px 14px; border-left: 3px solid var(--border); margin-bottom: 8px; background: var(--bg); border-radius: 0 6px 6px 0; }
.finding.critical { border-color: var(--red); }
.finding.high { border-color: var(--orange); }
.finding.medium { border-color: var(--yellow); }
.finding.low { border-color: var(--green); }
.toc { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; }
.toc a { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 6px 14px; color: var(--accent2); text-decoration: none; font-size: 13px; transition: all 0.2s; }
.toc a:hover { background: var(--bg3); border-color: var(--accent2); }
footer { text-align: center; padding: 24px; color: var(--dim); font-size: 12px; border-top: 1px solid var(--border); margin-top: 40px; }
"""

MODULE_ICONS = {
    "dns": "🔍", "whois": "📋", "ssl": "🔐", "headers": "📡",
    "sub": "🌐", "harvest": "📧", "breach": "🚨", "wayback": "📅",
    "shodan": "🛰", "censys": "🔎", "virustotal": "🦠", "cve": "🔴",
    "geo": "🌍", "tech": "⚙", "phish": "🎣", "typo": "✏",
    "riskcore": "⚖", "exfil": "📤", "persona": "👤", "cloud2": "☁",
    "codetrace": "👨‍💻", "threatfeed": "📡", "phoneosint": "📞",
    "imgosint": "🖼", "docosint": "📄", "autocorr": "🔗",
    "briefing": "📋", "vuln2": "🔴", "webcrawl": "🕷",
    "ipdossier": "🌐", "apiosint": "⚙", "socmint": "👤",
    "cryptoosint": "₿", "reportgen": "📊",
}


def _load_reports(target: str, report_dir: str = "", hours: int = 0) -> list[dict]:
    if report_dir:
        search_dir = Path(report_dir)
    else:
        search_dir = Path.home() / ".omega" / "reports"
    if not search_dir.exists():
        return []
    safe_target = re.sub(r"[^\w.-]", "_", target)
    cutoff = time.time() - hours * 3600 if hours > 0 else 0
    reports = []
    for f in sorted(search_dir.glob(f"*{safe_target}*.json")):
        if cutoff and f.stat().st_mtime < cutoff:
            continue
        try:
            data = json.loads(f.read_text())
            module = f.stem.split("_")[0]
            reports.append({"module": module, "file": str(f), "data": data, "mtime": f.stat().st_mtime})
        except Exception:
            pass
    return reports


def _extract_key_findings(reports: list[dict]) -> list[dict]:
    findings = []
    for r in reports:
        d = r["data"]
        mod = r["module"]
        # Risk scores
        if isinstance(d.get("risk_score"), (int, float)) and d["risk_score"] > 0:
            findings.append({
                "module": mod, "severity": d.get("risk_level", "MEDIUM"),
                "title": f"Risk score {d['risk_score']}/100",
                "detail": str(d.get("risk_flags", "")),
            })
        # CVEs
        for vuln in (d.get("vulns") or d.get("cves") or [])[:5]:
            findings.append({"module": mod, "severity": "HIGH", "title": f"CVE: {vuln}", "detail": ""})
        # Sanctions
        if d.get("sanctions"):
            findings.append({"module": mod, "severity": "CRITICAL", "title": "Sanctioned blockchain address", "detail": ""})
        # Secrets
        for s in (d.get("secrets") or [])[:5]:
            findings.append({"module": mod, "severity": "CRITICAL", "title": "Secret/credential exposed in JS/HTML", "detail": str(s)[:100]})
        # Open ports (Shodan)
        ports = d.get("ports") or (d.get("shodan_internetdb") or {}).get("ports") or []
        if ports:
            findings.append({"module": mod, "severity": "INFO", "title": f"Open ports: {', '.join(str(p) for p in ports[:10])}", "detail": ""})
        # Breaches
        if d.get("breaches") and len(d["breaches"]) > 0:
            findings.append({"module": mod, "severity": "HIGH", "title": f"{len(d['breaches'])} data breaches found", "detail": ""})
        # Blacklists
        listed = [b for b in (d.get("dnsbl") or []) if b.get("listed")]
        if listed:
            findings.append({"module": mod, "severity": "HIGH", "title": f"Listed on {len(listed)} blacklists", "detail": ", ".join(b["blacklist"] for b in listed)})
    return findings


def _severity_color(sev: str) -> str:
    return {"CRITICAL": "tag-red", "HIGH": "tag-red", "MEDIUM": "tag-yellow",
            "LOW": "tag-green", "INFO": "tag-blue"}.get(sev.upper(), "tag-blue")


def _build_html(target: str, reports: list[dict], findings: list[dict], generated: str) -> str:
    toc_items = "".join(f'<a href="#{r["module"]}">{MODULE_ICONS.get(r["module"],"📄")} {r["module"]}</a>' for r in reports)
    stats_html = f"""
    <div class="grid">
      <div class="stat-card"><div class="stat-num">{len(reports)}</div><div class="stat-label">Modules Run</div></div>
      <div class="stat-card"><div class="stat-num">{len(findings)}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card"><div class="stat-num">{sum(1 for f in findings if f['severity'] in ('CRITICAL','HIGH'))}</div><div class="stat-label">Critical/High</div></div>
      <div class="stat-card"><div class="stat-num">{len(set(r['module'] for r in reports))}</div><div class="stat-label">Unique Modules</div></div>
    </div>
    """

    findings_html = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev_findings = [f for f in findings if f["severity"].upper() == sev]
        if sev_findings:
            findings_html += f'<h4 style="color:var(--dim);margin:12px 0 6px;font-size:12px;text-transform:uppercase">{sev} ({len(sev_findings)})</h4>'
            for f in sev_findings:
                findings_html += f'<div class="finding {sev.lower()}"><strong>[{f["module"]}]</strong> {f["title"]}'
                if f["detail"]:
                    findings_html += f'<div style="color:var(--dim);font-size:12px;margin-top:4px">{f["detail"][:200]}</div>'
                findings_html += "</div>"

    modules_html = ""
    for r in reports:
        icon = MODULE_ICONS.get(r["module"], "📄")
        d = r["data"]
        ts = datetime.fromtimestamp(r["mtime"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Build a summary table from top-level scalar fields
        rows = ""
        for k, v in d.items():
            if isinstance(v, (str, int, float, bool)) and v and k not in ("target",):
                rows += f"<tr><td style='color:var(--dim);width:160px'>{k}</td><td>{str(v)[:200]}</td></tr>"

        # Lists (up to 5 items)
        for k, v in d.items():
            if isinstance(v, list) and v and k not in ("transactions",):
                items = v[:5]
                display = ", ".join(str(i)[:60] if not isinstance(i, dict) else str(list(i.values())[:2])[:60] for i in items)
                rows += f"<tr><td style='color:var(--dim);width:160px'>{k} ({len(v)})</td><td>{display}</td></tr>"

        modules_html += f"""
        <div class="section" id="{r['module']}">
          <div class="section-header">
            <span style="font-size:1.3rem">{icon}</span>
            <span class="section-title">{r['module']}</span>
            <span style="flex:1"></span>
            <span style="color:var(--dim);font-size:12px">{ts}</span>
          </div>
          <div class="section-body">
            <table>{rows}</table>
          </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OMEGA Report — {target}</title>
<style>{CSS}</style>
</head>
<body>
<div class="header">
  <div class="logo">OMEGA<span>-CLI</span></div>
  <div class="meta">Intelligence Report &nbsp;|&nbsp; Generated {generated}</div>
  <div class="target-badge">{target}</div>
</div>
<div class="container">
  <div class="toc">{toc_items}</div>

  <div class="section">
    <div class="section-header">
      <span style="font-size:1.3rem">📊</span>
      <span class="section-title">Executive Summary</span>
      <span class="section-badge">{len(findings)} findings</span>
    </div>
    <div class="section-body">
      {stats_html}
      {findings_html}
    </div>
  </div>

  {modules_html}
</div>
<footer>
  OMEGA-CLI v1.7.0 &nbsp;|&nbsp; {generated} &nbsp;|&nbsp; For authorized use only
</footer>
</body>
</html>"""


def _build_markdown(target: str, reports: list[dict], findings: list[dict], generated: str) -> str:
    lines = [
        f"# OMEGA Intelligence Report — {target}",
        f"**Generated:** {generated}  ",
        f"**Modules:** {len(reports)}  |  **Findings:** {len(findings)}",
        "",
        "## Executive Summary",
        "",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        for f in findings:
            if f["severity"].upper() == sev:
                icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}.get(sev,"•")
                lines.append(f"- {icon} **[{f['module']}]** {f['title']}")
                if f["detail"]:
                    lines.append(f"  - _{f['detail'][:120]}_")
    lines.append("")
    lines.append("## Module Reports")
    lines.append("")
    for r in reports:
        icon = MODULE_ICONS.get(r["module"], "📄")
        lines.append(f"### {icon} {r['module']}")
        d = r["data"]
        for k, v in d.items():
            if isinstance(v, (str, int, float, bool)) and v and k not in ("target",):
                lines.append(f"- **{k}:** {str(v)[:200]}")
            elif isinstance(v, list) and v:
                lines.append(f"- **{k}:** {len(v)} items")
        lines.append("")
    lines.append("---")
    lines.append(f"*OMEGA-CLI v1.7.0 | {generated} | For authorized use only*")
    return "\n".join(lines)


def run(target: str, report_dir: str = "", output: str = "", hours: int = 0,
        fmt: str = "html", open_browser: bool = False):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"📊  Master Report Generator — {target}", style="bold cyan"))

    reports = _load_reports(target, report_dir=report_dir, hours=hours)
    console.print(f"[cyan]Reports found:[/cyan] {len(reports)}")

    if not reports:
        console.print("[yellow]⚠ No omega JSON reports found for this target.[/yellow]")
        console.print(f"[dim]Run some omega commands first, reports saved to ~/.omega/reports/[/dim]")
        return

    for r in reports:
        ts = datetime.fromtimestamp(r["mtime"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        console.print(f"  [green]✓[/green] {r['module']:20s}  [dim]{ts}[/dim]")

    findings = _extract_key_findings(reports)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", target)
    base_path = Path(output) if output else out_dir / f"report_{safe}"

    saved = []

    if fmt in ("html", "both"):
        html = _build_html(target, reports, findings, generated)
        html_path = base_path.with_suffix(".html")
        html_path.write_text(html, encoding="utf-8")
        console.print(f"[green]HTML report → {html_path}[/green]")
        saved.append(str(html_path))
        if open_browser:
            webbrowser.open(html_path.as_uri())

    if fmt in ("md", "both"):
        md = _build_markdown(target, reports, findings, generated)
        md_path = base_path.with_suffix(".md")
        md_path.write_text(md, encoding="utf-8")
        console.print(f"[green]Markdown report → {md_path}[/green]")
        saved.append(str(md_path))

    # Try PDF with weasyprint
    if fmt in ("pdf", "both"):
        try:
            from weasyprint import HTML as WHTML
            html = _build_html(target, reports, findings, generated)
            pdf_path = base_path.with_suffix(".pdf")
            WHTML(string=html).write_pdf(str(pdf_path))
            console.print(f"[green]PDF report → {pdf_path}[/green]")
            saved.append(str(pdf_path))
        except ImportError:
            console.print("[dim]weasyprint not available — skipping PDF[/dim]")
        except Exception as e:
            console.print(f"[yellow]PDF generation failed: {e}[/yellow]")

    console.print(f"\n[bold]Summary:[/bold] {len(reports)} modules | {len(findings)} findings | "
                  f"{sum(1 for f in findings if f['severity'] in ('CRITICAL','HIGH'))} critical/high")
