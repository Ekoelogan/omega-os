"""omega hunt — Threat hunting playbook: correlate omega findings with MITRE ATT&CK TTPs."""
from __future__ import annotations
import glob
import json
import os
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel

console = Console()

# MITRE ATT&CK TTP mapping — keyword → (TTP ID, Tactic, Technique)
TTP_MAP: list[tuple[list[str], str, str, str]] = [
    # Recon
    (["subdomain", "subdomain_count"],          "T1590.002", "Reconnaissance",      "DNS Enumeration"),
    (["wayback", "wayback_urls"],               "T1593.002", "Reconnaissance",      "Search Open Websites/Domains"),
    (["git", "github", "repos"],                "T1593.003", "Reconnaissance",      "Code Repositories"),
    (["email", "emails", "harvest"],            "T1589.002", "Reconnaissance",      "Email Addresses"),
    (["shodan", "banner", "port"],              "T1046",     "Discovery",           "Network Service Scanning"),
    (["whois", "registrar"],                    "T1590.001", "Reconnaissance",      "Domain Properties"),
    # Resource Dev
    (["phish", "phishing"],                     "T1566",     "Initial Access",      "Phishing"),
    (["typo", "typosquat"],                     "T1583.001", "Resource Development","Acquire Domain"),
    (["breach", "password", "leak"],            "T1589.001", "Reconnaissance",      "Credentials"),
    (["cloud", "s3", "bucket", "azure"],        "T1530",     "Collection",          "Data from Cloud Storage"),
    # Execution / C2
    (["c2", "beacon", "cobalt", "sliver"],      "T1071",     "Command and Control", "Application Layer Protocol"),
    (["cors", "cors_issues"],                   "T1189",     "Initial Access",      "Drive-by Compromise"),
    (["vuln", "cve", "vulnerability"],          "T1203",     "Execution",           "Exploitation for Client Execution"),
    # Exfil
    (["fuzz", "paths", "endpoints"],            "T1083",     "Discovery",           "File and Directory Discovery"),
    (["dark", "onion"],                         "T1090.003", "Command and Control", "Multi-hop Proxy"),
    (["social", "reddit", "paste"],             "T1217",     "Discovery",           "Browser Bookmark Discovery"),
    (["crypto", "bitcoin", "btc"],              "T1531",     "Impact",              "Account Access Removal"),
]


def _load_findings(target: str, json_file: str) -> dict:
    """Load omega auto recon JSON for target."""
    if json_file and Path(json_file).exists():
        return json.loads(Path(json_file).read_text())

    # Auto-discover latest recon file
    patterns = [
        f"omega_auto_{target}_*.json",
        f"*{target}*.json",
        f"recon_{target}*.json",
    ]
    for pat in patterns:
        matches = glob.glob(pat) + glob.glob(os.path.expanduser(f"~/{pat}"))
        if matches:
            latest = max(matches, key=os.path.getmtime)
            console.print(f"[dim]Loading:[/dim] {latest}")
            return json.loads(Path(latest).read_text())
    return {}


def _flatten_keys(d: dict, prefix: str = "") -> set[str]:
    """Recursively collect all keys from nested dict."""
    keys = set()
    for k, v in d.items():
        full = f"{prefix}.{k}" if prefix else k
        keys.add(k.lower())
        if isinstance(v, dict):
            keys |= _flatten_keys(v, full)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            keys |= _flatten_keys(v[0], full)
    return keys


def _match_ttps(keys: set[str], raw_text: str) -> list[tuple[str, str, str, list[str]]]:
    """Match findings keys against TTP map."""
    hits: list[tuple[str, str, str, list[str]]] = []
    for kw_list, ttp_id, tactic, technique in TTP_MAP:
        matched = [kw for kw in kw_list if kw in keys or kw in raw_text.lower()]
        if matched:
            hits.append((ttp_id, tactic, technique, matched))
    return hits


def _risk_score(hits: list) -> int:
    """Simple risk score based on TTP count and tactic distribution."""
    tactics = {h[1] for h in hits}
    score   = min(len(hits) * 8 + len(tactics) * 5, 100)
    return score


def run(target: str, json_file: str = "", playbook: str = "all") -> None:
    console.print(Panel(
        f"[bold #ff2d78]🎯  Threat Hunt Playbook[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    findings = _load_findings(target, json_file)

    if not findings:
        console.print("[yellow]No findings JSON found.[/yellow] Run [bold]omega auto " + target +
                      "[/bold] first, or pass --json-file PATH.")
        console.print("\n[dim]Running structural analysis on target name alone…[/dim]")

    raw_text = json.dumps(findings)
    keys     = _flatten_keys(findings) if findings else set()

    # Add target name itself as a hint
    keys.add(target.lower())
    for part in re.split(r"[.\-_]", target.lower()):
        keys.add(part)

    hits = _match_ttps(keys, raw_text)

    if not hits:
        console.print("[green]✓  No MITRE ATT&CK TTPs matched from findings.[/green]")
        return

    # TTP table
    tbl = Table(title=f"MITRE ATT&CK Mapping — {len(hits)} TTPs", show_lines=True)
    tbl.add_column("TTP ID",    style="bold #ff2d78", width=12)
    tbl.add_column("Tactic",    style="bold white",   max_width=22)
    tbl.add_column("Technique", style="cyan",         max_width=30)
    tbl.add_column("Evidence",  style="dim",          max_width=25)
    for ttp_id, tactic, technique, evidence in sorted(hits, key=lambda x: x[1]):
        tbl.add_row(ttp_id, tactic, technique, ", ".join(evidence[:3]))
    console.print(tbl)

    # Tactic breakdown tree
    tree = Tree("[bold]Tactic Coverage[/bold]")
    by_tactic: dict[str, list] = {}
    for ttp_id, tactic, technique, _ in hits:
        by_tactic.setdefault(tactic, []).append((ttp_id, technique))
    for tactic, techniques in sorted(by_tactic.items()):
        branch = tree.add(f"[bold #ff2d78]{tactic}[/bold #ff2d78]")
        for ttp_id, tech in techniques:
            branch.add(f"[dim]{ttp_id}[/dim]  {tech}")
    console.print(tree)

    # Risk score
    risk = _risk_score(hits)
    color = "#ff2d78" if risk >= 70 else ("#ffaa00" if risk >= 40 else "green")
    console.print(f"\n[bold]Threat Risk Score: [{color}]{risk}/100[/{color}][/bold]  "
                  f"({len(hits)} TTPs across {len(by_tactic)} tactics)")

    console.print(f"\n[dim]MITRE ATT&CK Navigator:[/dim]")
    console.print(f"  https://attack.mitre.org/")
    console.print(f"  https://mitre-attack.github.io/attack-navigator/")
