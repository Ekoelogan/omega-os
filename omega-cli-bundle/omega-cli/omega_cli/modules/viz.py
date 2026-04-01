"""omega viz — Attack surface visualizer: Rich tree + ASCII graph of all recon findings."""
from __future__ import annotations
import json
import math
import os
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table
from rich.columns import Columns
from rich.text import Text

console = Console()


def _load_findings(target: str, json_file: str) -> dict:
    if json_file and Path(json_file).exists():
        return json.loads(Path(json_file).read_text())
    import glob as gl
    patterns = [f"omega_auto_{target}_*.json", f"dossier_{target}_*.json", f"*{target}*.json"]
    files = []
    for pat in patterns:
        files += gl.glob(pat) + gl.glob(os.path.expanduser(f"~/{pat}"))
    if files:
        latest = max(files, key=os.path.getmtime)
        console.print(f"[dim]Loading:[/dim] {latest}")
        return json.loads(Path(latest).read_text())
    return {}


def _risk_color(item: str) -> str:
    item_lower = item.lower()
    if any(k in item_lower for k in ("breach", "password", "secret", "critical", "c2", "malware")):
        return "#ff2d78"
    if any(k in item_lower for k in ("vuln", "cve", "cors", "open", "exposed", "phish")):
        return "#ffaa00"
    if any(k in item_lower for k in ("ok", "✓", "secure", "closed")):
        return "green"
    return "cyan"


def _build_tree(target: str, findings: dict) -> Tree:
    root = Tree(f"[bold #ff2d78]⚡[/bold #ff2d78] [bold cyan]{target}[/bold cyan]  "
                f"[dim]attack surface[/dim]")

    # DNS / IPs
    dns = findings.get("DNS", findings.get("dns", {}))
    if dns:
        dns_b = root.add("[bold]🌐 DNS / Network[/bold]")
        for rtype, records in dns.items():
            if isinstance(records, list):
                sub = dns_b.add(f"[dim]{rtype}[/dim]")
                for r in records[:4]:
                    sub.add(f"[cyan]{r}[/cyan]")

    # Subdomains
    subs = findings.get("Subdomains", findings.get("subdomains", {}))
    if subs:
        sub_b = root.add(f"[bold]🔭 Subdomains[/bold]  [dim]({len(subs)} found)[/dim]")
        items = list(subs.items()) if isinstance(subs, dict) else [(s, "") for s in subs]
        for domain, ip in items[:10]:
            sub_b.add(f"[cyan]{domain}[/cyan]  [dim]{ip}[/dim]")
        if len(items) > 10:
            sub_b.add(f"[dim]… {len(items)-10} more[/dim]")

    # SSL
    ssl = findings.get("SSL", findings.get("ssl", {}))
    if ssl and not ssl.get("error"):
        ssl_b = root.add("[bold]🔒 SSL / TLS[/bold]")
        issuer = ssl.get("issuer", {})
        if isinstance(issuer, dict):
            ssl_b.add(f"[dim]Issuer:[/dim] {issuer.get('organizationName','?')}")
        ssl_b.add(f"[dim]Expires:[/dim] {ssl.get('not_after','?')}")
        ssl_b.add(f"[dim]Cipher:[/dim] {ssl.get('cipher','?')}")

    # Headers / Security posture
    headers = findings.get("Headers", findings.get("headers", {}))
    if headers:
        sec = headers.get("security_headers", {})
        if sec:
            hdr_b = root.add("[bold]🛡  Security Headers[/bold]")
            for h, v in list(sec.items())[:7]:
                sym   = "✓" if v and v != "MISSING" else "✗"
                color = "green" if sym == "✓" else "red"
                hdr_b.add(f"[{color}]{sym}[/{color}]  [dim]{h}[/dim]")

    # Technology
    tech = findings.get("Technology", findings.get("tech", {}))
    if tech and not tech.get("error"):
        detected = tech.get("detected", [])
        if detected:
            tech_b = root.add(f"[bold]⚙  Technology Stack[/bold]")
            for t in detected[:8]:
                tech_b.add(f"[cyan]{t}[/cyan]")

    # Ports
    ports = findings.get("Ports", findings.get("ports", {}))
    if ports:
        open_ports = ports.get("open", [])
        if open_ports:
            port_b = root.add(f"[bold]🔓 Open Ports[/bold]  "
                              f"[dim]({len(open_ports)} open)[/dim]")
            for p in open_ports:
                service = {21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",
                           110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
                           3306:"MySQL",3389:"RDP",5432:"PgSQL",
                           6379:"Redis",8080:"HTTP-alt",8443:"HTTPS-alt"}.get(p, "unknown")
                color = "#ff2d78" if p in (445, 3389, 6379, 27017) else "cyan"
                port_b.add(f"[{color}]{p}[/{color}]/tcp  [dim]{service}[/dim]")

    # Email / People
    emails = findings.get("Email Harvest", findings.get("emails", {}))
    if emails:
        em_list = emails.get("emails", []) if isinstance(emails, dict) else emails
        if em_list:
            em_b = root.add(f"[bold]📧 Email Addresses[/bold]  [dim]({len(em_list)})[/dim]")
            for e in em_list[:6]:
                em_b.add(f"[cyan]{e}[/cyan]")

    # Cloud / Buckets
    cloud = findings.get("Cloud", findings.get("cloud", {}))
    if cloud:
        buckets = cloud.get("buckets", [])
        if buckets:
            cl_b = root.add(f"[bold]☁  Cloud Assets[/bold]")
            for b in buckets[:5]:
                status = b.get("status", "")
                color  = "#ff2d78" if status == 200 else "#ffaa00"
                cl_b.add(f"[{color}]{b.get('url','?')}[/{color}]  [dim]HTTP {status}[/dim]")

    # ASN
    asn = findings.get("ASN", {})
    if asn and not asn.get("error"):
        asn_b = root.add("[bold]📡 ASN / Hosting[/bold]")
        asn_b.add(f"[dim]ASN:[/dim] {asn.get('asn','?')}")
        asn_b.add(f"[dim]Org:[/dim] {asn.get('asn_description','?')}")
        asn_b.add(f"[dim]Network:[/dim] {asn.get('network','?')}")

    return root


def _ascii_graph(target: str, subdomains: list[str], ips: list[str]) -> str:
    """Render a simple ASCII star-topology graph."""
    lines = []
    center = target[:20]
    width  = 60
    pad    = (width - len(center)) // 2
    lines.append(" " * pad + f"[{center}]")
    lines.append(" " * (pad + len(center) // 2) + "|")

    all_nodes = ips[:4] + subdomains[:6]
    if not all_nodes:
        return ""

    mid = len(all_nodes) // 2
    for i, node in enumerate(all_nodes):
        if i < mid:
            lines.append(f"  ├─ {node}")
        elif i == mid:
            lines.append(f"  ├─ {node}")
        else:
            lines.append(f"  └─ {node}" if i == len(all_nodes) - 1 else f"  ├─ {node}")
    return "\n".join(lines)


def run(target: str, json_file: str = "", format: str = "tree") -> None:
    console.print(Panel(
        f"[bold #ff2d78]📊  Attack Surface Visualizer[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    findings = _load_findings(target, json_file)

    if not findings:
        console.print("[yellow]No findings JSON found.[/yellow] "
                      f"Run [bold]omega auto {target}[/bold] or [bold]omega dossier {target}[/bold] first.")
        # Still render an empty tree with just the target
        findings = {}

    if format == "tree" or format == "both":
        console.print()
        tree = _build_tree(target, findings)
        console.print(tree)

    if format in ("ascii", "both"):
        subs = list(findings.get("Subdomains", {}).keys())[:6]
        ips  = findings.get("DNS", {}).get("A", [])[:4]
        graph = _ascii_graph(target, subs, ips)
        if graph:
            console.print(Panel(graph, title="[bold]Network Topology[/bold]",
                                border_style="#ff2d78"))

    # Stats summary
    populated = {k: v for k, v in findings.items()
                 if v and not (isinstance(v, dict) and list(v.keys()) == ["error"])}
    if populated:
        console.print(f"\n[dim]{len(populated)} data sources visualized[/dim]")
        console.print("[dim]Export full report:[/dim] [bold]omega executive " + target + "[/bold]")
