"""attackmap.py — MITRE ATT&CK mapper: map omega IOCs/TTPs to ATT&CK techniques."""
from __future__ import annotations
import json, re, time
from pathlib import Path
from typing import Optional
import urllib.request, urllib.error

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
  OMEGA-CLI v1.8.0 — OSINT & Passive Recon Toolkit
"""

# Curated mapping: omega finding type → ATT&CK technique(s)
FINDING_TO_ATTACK = {
    # Discovery
    "open_ports":         [("T1046", "Network Service Discovery",        "Discovery")],
    "subdomains":         [("T1590.001", "DNS — Domain Names",           "Reconnaissance")],
    "whois":              [("T1590.002", "WHOIS",                        "Reconnaissance")],
    "ssl_cert":           [("T1590.003", "Network Trust Dependencies",   "Reconnaissance")],
    "tech_stack":         [("T1592.002", "Software Discovery",           "Reconnaissance")],
    "cloud_buckets":      [("T1530", "Data from Cloud Storage",          "Collection")],
    "github_repos":       [("T1593.003", "Code Repositories",            "Reconnaissance")],
    "email_harvest":      [("T1589.002", "Email Addresses",              "Reconnaissance")],
    "employees":          [("T1589.003", "Employee Names",               "Reconnaissance")],
    # Credential / Breach
    "breaches":           [("T1589.001", "Credentials",                  "Reconnaissance"),
                           ("T1078", "Valid Accounts",                    "Defense Evasion")],
    "secrets":            [("T1552.001", "Credentials in Files",         "Credential Access")],
    "default_creds":      [("T1078.001", "Default Accounts",             "Defense Evasion")],
    # Exfil / C2
    "dns_tunnel":         [("T1071.004", "DNS C2",                       "Command and Control"),
                           ("T1048.003", "DNS Exfiltration",             "Exfiltration")],
    "dga":                [("T1568.002", "Domain Generation Algorithms", "Command and Control")],
    "c2":                 [("T1071", "Application Layer Protocol",       "Command and Control")],
    # Vulnerabilities
    "cves":               [("T1190", "Exploit Public-Facing Application","Initial Access")],
    "vulns":              [("T1190", "Exploit Public-Facing Application","Initial Access")],
    "log4j":              [("T1190", "Exploit Public-Facing Application","Initial Access"),
                           ("T1059", "Command Scripting Interpreter",    "Execution")],
    # Web
    "open_redirect":      [("T1566.002", "Spearphishing Link",           "Initial Access")],
    "forms":              [("T1056.003", "Web Portal Capture",           "Collection")],
    "js_endpoints":       [("T1592", "Gather Victim Host Information",   "Reconnaissance")],
    "cors_misconfig":     [("T1557", "Adversary-in-the-Middle",          "Collection")],
    # Crypto / Finance
    "sanctions":          [("T1657", "Financial Theft",                  "Impact")],
    "mixing":             [("T1565", "Data Manipulation",                "Impact")],
    # Social
    "social_profiles":    [("T1591.001", "Physical Locations",           "Reconnaissance"),
                           ("T1589", "Gather Victim Identity Info",      "Reconnaissance")],
    "phone":              [("T1589.001", "Credentials via Phone",        "Reconnaissance")],
    # Firmware / IoT
    "firmware_vulns":     [("T1195.001", "Compromise SW Supply Chain",  "Initial Access")],
    "default_credentials":[("T1078.001", "Default Accounts",            "Defense Evasion")],
    # Phishing
    "phishing_sites":     [("T1566.001", "Spearphishing Attachment",    "Initial Access")],
    "typosquat":          [("T1583.001", "Typosquatting Domains",        "Resource Development")],
}

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

TACTIC_COLORS = {
    "Reconnaissance":      "blue",
    "Resource Development":"purple",
    "Initial Access":      "red",
    "Execution":           "red",
    "Persistence":         "orange3",
    "Privilege Escalation":"orange3",
    "Defense Evasion":     "yellow",
    "Credential Access":   "yellow",
    "Discovery":           "cyan",
    "Lateral Movement":    "green",
    "Collection":          "green",
    "Command and Control": "red",
    "Exfiltration":        "red",
    "Impact":              "bold red",
}


def _load_reports(target: str, report_dir: str = "") -> list[dict]:
    search_dir = Path(report_dir) if report_dir else Path.home() / ".omega" / "reports"
    if not search_dir.exists():
        return []
    safe = re.sub(r"[^\w.-]", "_", target)
    reports = []
    for f in sorted(search_dir.glob(f"*{safe}*.json")):
        try:
            data = json.loads(f.read_text())
            module = f.stem.split("_")[0]
            reports.append({"module": module, "data": data})
        except Exception:
            pass
    return reports


def _extract_finding_keys(report: dict) -> list[str]:
    """Determine which finding types are present in a report."""
    d = report["data"]
    keys = []
    # Presence checks
    checks = {
        "open_ports":          lambda d: bool(d.get("ports") or (d.get("shodan_internetdb") or {}).get("ports")),
        "subdomains":          lambda d: bool(d.get("subdomains")),
        "whois":               lambda d: report["module"] == "whois",
        "ssl_cert":            lambda d: report["module"] == "ssl",
        "tech_stack":          lambda d: bool(d.get("technologies") or d.get("tech")),
        "cloud_buckets":       lambda d: bool(d.get("open_buckets") or d.get("buckets")),
        "github_repos":        lambda d: bool(d.get("repos") or d.get("repositories")),
        "email_harvest":       lambda d: bool(d.get("emails")),
        "employees":           lambda d: bool(d.get("employees") or d.get("names")),
        "breaches":            lambda d: bool(d.get("breaches") and len(d.get("breaches", [])) > 0),
        "secrets":             lambda d: bool(d.get("secrets")),
        "default_creds":       lambda d: bool(d.get("default_creds")),
        "dns_tunnel":          lambda d: bool(d.get("dns_tunnel") or d.get("tunnel_detected")),
        "dga":                 lambda d: bool(d.get("dga_detected")),
        "cves":                lambda d: bool(d.get("cves") or d.get("vulns")),
        "vulns":               lambda d: bool(d.get("vulns") or d.get("vulnerabilities")),
        "forms":               lambda d: bool(d.get("forms")),
        "js_endpoints":        lambda d: bool(d.get("js_endpoints")),
        "cors_misconfig":      lambda d: bool(d.get("cors_vulnerable")),
        "sanctions":           lambda d: bool(d.get("sanctions")),
        "mixing":              lambda d: bool((d.get("mixing") or {}).get("detected")),
        "social_profiles":     lambda d: bool(d.get("found") and report["module"] == "socmint"),
        "phone":               lambda d: report["module"] == "phoneosint",
        "firmware_vulns":      lambda d: report["module"] == "firmware",
        "phishing_sites":      lambda d: bool(d.get("phishing_sites")),
        "typosquat":           lambda d: bool(d.get("variants") or d.get("typos")),
    }
    for key, check_fn in checks.items():
        try:
            if check_fn(d):
                keys.append(key)
        except Exception:
            pass
    return keys


def _generate_heatmap_html(tactic_techniques: dict, target: str) -> str:
    tactic_cells = ""
    for tactic in TACTIC_ORDER:
        techs = tactic_techniques.get(tactic, [])
        color = "#f85149" if techs else "#21262d"
        border = "2px solid #ff2d78" if techs else "1px solid #30363d"
        count = f'<div style="font-size:11px;color:#8b949e">{len(techs)} technique{"s" if len(techs)!=1 else ""}</div>' if techs else ""
        tech_list = "".join(
            f'<div style="font-size:10px;padding:2px 0;border-bottom:1px solid #30363d">'
            f'<span style="color:#ff2d78">{tid}</span> {name}</div>'
            for tid, name in techs[:5]
        )
        tactic_cells += f"""
        <div style="background:#161b22;border:{border};border-radius:6px;padding:10px;min-height:80px">
          <div style="color:{color if techs else '#8b949e'};font-weight:700;font-size:12px;margin-bottom:4px">{tactic}</div>
          {count}
          <div style="margin-top:6px">{tech_list}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>ATT&CK Heatmap — {target}</title>
<style>body{{background:#0d1117;color:#c9d1d9;font-family:system-ui;padding:24px}}
h1{{color:#ff2d78;margin-bottom:4px}}h2{{color:#8b949e;font-size:14px;font-weight:400;margin-bottom:24px}}
</style></head><body>
<h1>⚔ MITRE ATT&CK Heatmap</h1>
<h2>Target: {target}</h2>
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px">
{tactic_cells}
</div>
<p style="color:#8b949e;font-size:12px;margin-top:24px">Generated by omega-cli v1.8.0</p>
</body></html>"""


def run(target: str, report_dir: str = "", export: str = "", heatmap: bool = False):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"⚔  MITRE ATT&CK Mapper — {target}", style="bold cyan"))

    reports = _load_reports(target, report_dir=report_dir)
    if not reports:
        console.print("[yellow]⚠ No omega reports found — run some recon modules first.[/yellow]")
        return

    console.print(f"[cyan]Analyzing {len(reports)} reports...[/cyan]\n")

    # Map findings → techniques
    technique_hits: dict[str, dict] = {}  # tid → {name, tactic, modules, count}
    tactic_techniques: dict[str, list] = {t: [] for t in TACTIC_ORDER}

    for report in reports:
        finding_keys = _extract_finding_keys(report)
        for fk in finding_keys:
            for tid, name, tactic in FINDING_TO_ATTACK.get(fk, []):
                if tid not in technique_hits:
                    technique_hits[tid] = {"tid": tid, "name": name, "tactic": tactic, "modules": [], "finding_keys": []}
                if report["module"] not in technique_hits[tid]["modules"]:
                    technique_hits[tid]["modules"].append(report["module"])
                if fk not in technique_hits[tid]["finding_keys"]:
                    technique_hits[tid]["finding_keys"].append(fk)
                if (tid, name) not in tactic_techniques.get(tactic, []):
                    tactic_techniques.setdefault(tactic, []).append((tid, name))

    if not technique_hits:
        console.print("[dim]No ATT&CK techniques mapped from current reports.[/dim]")
        console.print("[dim]Try running more omega modules (vuln2, exfil, breach, corscheck, etc.)[/dim]")
        return

    # Display by tactic
    t = Table(title=f"⚔ ATT&CK Techniques Mapped ({len(technique_hits)})", box=box.SIMPLE if box else None)
    t.add_column("Tactic",    style="bold",   min_width=22)
    t.add_column("ID",        style="cyan",   min_width=12)
    t.add_column("Technique", min_width=35)
    t.add_column("Source Modules", style="dim")

    for tactic in TACTIC_ORDER:
        tec_list = [v for v in technique_hits.values() if v["tactic"] == tactic]
        for tec in tec_list:
            color = TACTIC_COLORS.get(tactic, "white")
            t.add_row(
                f"[{color}]{tactic}[/{color}]",
                tec["tid"],
                tec["name"],
                ", ".join(tec["modules"]),
            )
    console.print(t)

    console.print(f"\n[bold]Coverage:[/bold] {len(technique_hits)} techniques across "
                  f"{len(set(v['tactic'] for v in technique_hits.values()))} tactics")

    # ATT&CK Navigator link
    tids = list(technique_hits.keys())
    console.print(f"\n[bold cyan]ATT&CK Navigator:[/bold cyan]")
    console.print(f"  https://mitre-attack.github.io/attack-navigator/")
    console.print(f"  Techniques: {', '.join(tids[:10])}{'...' if len(tids)>10 else ''}")

    # Heatmap HTML
    if heatmap:
        html = _generate_heatmap_html(tactic_techniques, target)
        out_dir = Path.home() / ".omega" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w.-]", "_", target)
        hmap_path = out_dir / f"attackmap_{safe}.html"
        hmap_path.write_text(html)
        console.print(f"[green]Heatmap → {hmap_path}[/green]")

    results = {
        "target": target,
        "techniques": list(technique_hits.values()),
        "tactic_count": len(set(v["tactic"] for v in technique_hits.values())),
        "technique_count": len(technique_hits),
    }
    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", target)
    out_path = Path(export) if export else out_dir / f"attackmap_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
