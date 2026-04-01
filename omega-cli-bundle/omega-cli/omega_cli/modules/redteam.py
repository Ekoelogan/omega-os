"""omega redteam — Red team automation: map findings to exploits, suggest attack paths."""
from __future__ import annotations
import json
import re
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()

# CVE → Metasploit module mapping (well-known exploits)
CVE_TO_MSF: dict[str, dict] = {
    "CVE-2021-44228": {"module": "exploit/multi/misc/log4shell_header_injection",
                       "name": "Log4Shell", "severity": "CRITICAL"},
    "CVE-2021-34527": {"module": "exploit/windows/smb/ms17_010_eternalblue",
                       "name": "PrintNightmare", "severity": "CRITICAL"},
    "CVE-2017-0144":  {"module": "exploit/windows/smb/ms17_010_eternalblue",
                       "name": "EternalBlue", "severity": "CRITICAL"},
    "CVE-2021-26855": {"module": "exploit/windows/http/exchange_proxylogon_rce",
                       "name": "ProxyLogon", "severity": "CRITICAL"},
    "CVE-2022-22965": {"module": "exploit/multi/http/spring4shell",
                       "name": "Spring4Shell", "severity": "CRITICAL"},
    "CVE-2019-0708":  {"module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                       "name": "BlueKeep RDP", "severity": "CRITICAL"},
    "CVE-2021-21985": {"module": "exploit/linux/http/vmware_vcenter_static_creds",
                       "name": "vCenter Auth Bypass", "severity": "CRITICAL"},
    "CVE-2022-1388":  {"module": "exploit/linux/http/f5_big_ip_cve_2022_1388",
                       "name": "F5 BIG-IP RCE", "severity": "CRITICAL"},
}

# Service → common attack vectors
SERVICE_ATTACKS: dict[int, list[dict]] = {
    21:    [{"name": "FTP Anonymous Login",     "msf": "auxiliary/scanner/ftp/anonymous",        "risk": "HIGH"}],
    22:    [{"name": "SSH Brute Force",          "msf": "auxiliary/scanner/ssh/ssh_login",         "risk": "MEDIUM"},
            {"name": "SSH User Enum",            "msf": "auxiliary/scanner/ssh/ssh_enumusers",     "risk": "LOW"}],
    23:    [{"name": "Telnet Brute Force",       "msf": "auxiliary/scanner/telnet/telnet_login",   "risk": "HIGH"}],
    25:    [{"name": "SMTP User Enum",           "msf": "auxiliary/scanner/smtp/smtp_enum",        "risk": "MEDIUM"}],
    80:    [{"name": "HTTP Directory Scan",      "msf": "auxiliary/scanner/http/dir_scanner",      "risk": "LOW"},
            {"name": "HTTP Verb Tamper",          "msf": "auxiliary/scanner/http/verb_auth_bypass", "risk": "MEDIUM"}],
    443:   [{"name": "SSL/TLS Version Scan",     "msf": "auxiliary/scanner/ssl/openssl_heartbleed","risk": "MEDIUM"},
            {"name": "HTTPS Directory Scan",     "msf": "auxiliary/scanner/http/dir_scanner",      "risk": "LOW"}],
    445:   [{"name": "SMB MS17-010 (EternalBlue)","msf": "exploit/windows/smb/ms17_010_eternalblue","risk": "CRITICAL"},
            {"name": "SMB Relay",                "msf": "exploit/windows/smb/smb_relay",           "risk": "HIGH"},
            {"name": "SMB Share Enum",           "msf": "auxiliary/scanner/smb/smb_enumshares",    "risk": "MEDIUM"}],
    3306:  [{"name": "MySQL Brute Force",        "msf": "auxiliary/scanner/mysql/mysql_login",     "risk": "HIGH"},
            {"name": "MySQL Anonymous Login",    "msf": "auxiliary/scanner/mysql/mysql_authbypass_hashdump","risk":"HIGH"}],
    3389:  [{"name": "RDP BlueKeep",             "msf": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce","risk":"CRITICAL"},
            {"name": "RDP Brute Force",          "msf": "auxiliary/scanner/rdp/rdp_scanner",       "risk": "HIGH"}],
    5432:  [{"name": "PostgreSQL Brute Force",   "msf": "auxiliary/scanner/postgres/postgres_login","risk":"HIGH"}],
    6379:  [{"name": "Redis No-Auth (RCE)",      "msf": "exploit/linux/redis/redis_replication_code_exec","risk":"CRITICAL"}],
    8080:  [{"name": "Tomcat Manager Upload",    "msf": "exploit/multi/http/tomcat_mgr_upload",    "risk": "HIGH"}],
    8443:  [{"name": "HTTPS Alt Port Scan",      "msf": "auxiliary/scanner/http/dir_scanner",      "risk": "LOW"}],
    27017: [{"name": "MongoDB No-Auth",          "msf": "auxiliary/scanner/mongodb/mongodb_login", "risk": "CRITICAL"}],
    9200:  [{"name": "Elasticsearch No-Auth",    "msf": "auxiliary/scanner/http/elasticsearch",    "risk": "HIGH"}],
}

# Technology → attack vectors
TECH_ATTACKS: dict[str, list[dict]] = {
    "WordPress":  [{"name": "WP User Enum",     "msf": "auxiliary/scanner/http/wordpress_login_enum","risk":"MEDIUM"},
                   {"name": "WP xmlrpc Brute",  "msf": "auxiliary/scanner/http/wordpress_xmlrpc_login","risk":"HIGH"}],
    "Joomla":     [{"name": "Joomla Auth Bypass","msf": "exploit/multi/http/joomla_http_header_rce","risk":"HIGH"}],
    "Drupal":     [{"name": "Drupalgeddon2",     "msf": "exploit/unix/webapp/drupal_drupalgeddon2","risk":"CRITICAL"}],
    "Apache":     [{"name": "Apache Log4Shell",  "msf": "exploit/multi/misc/log4shell_header_injection","risk":"CRITICAL"},
                   {"name": "Apache Dir Traversal","msf": "auxiliary/scanner/http/apache_optionsbleed","risk":"MEDIUM"}],
    "Tomcat":     [{"name": "Tomcat Manager RCE","msf": "exploit/multi/http/tomcat_mgr_upload",   "risk":"HIGH"}],
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _load_findings(target: str, json_file: str) -> dict:
    import glob, os
    if json_file and Path(json_file).exists():
        return json.loads(Path(json_file).read_text())
    for pat in [f"omega_auto_{target}_*.json", f"dossier_{target}_*.json"]:
        files = glob.glob(pat) + glob.glob(os.path.expanduser(f"~/{pat}"))
        if files:
            latest = max(files, key=os.path.getmtime)
            return json.loads(Path(latest).read_text())
    return {}


def _extract_cves(findings: dict) -> list[str]:
    text = json.dumps(findings)
    return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)))


def _extract_open_ports(findings: dict) -> list[int]:
    ports = findings.get("Ports", findings.get("ports", {}))
    if isinstance(ports, dict):
        return [int(p) for p in ports.get("open", [])]
    return []


def _extract_tech(findings: dict) -> list[str]:
    tech = findings.get("Technology", findings.get("tech", {}))
    if isinstance(tech, dict):
        return tech.get("detected", [])
    return []


def run(target: str, json_file: str = "", generate_commands: bool = False) -> None:
    console.print(Panel(
        f"[bold #ff2d78]🔴  Red Team Surface[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    findings = _load_findings(target, json_file)
    if not findings:
        console.print("[yellow]No findings JSON found.[/yellow] "
                      f"Run [bold]omega auto {target}[/bold] first.")
        console.print("\n[dim]Generating generic attack surface based on target name…[/dim]")

    attack_paths: list[dict] = []

    # CVE-based exploits
    cves = _extract_cves(findings)
    if cves:
        console.print(f"\n[bold]🐛 CVE Exploit Mapping ({len(cves)} CVEs):[/bold]")
        for cve in cves:
            cve_up = cve.upper()
            if cve_up in CVE_TO_MSF:
                m = CVE_TO_MSF[cve_up]
                attack_paths.append({"source": cve_up, **m})
                color = "#ff2d78" if m["severity"] == "CRITICAL" else "#ffaa00"
                console.print(f"  [{color}]{m['severity']}[/{color}]  {cve_up} → [bold]{m['name']}[/bold]")
                console.print(f"  [dim]    msf> use {m['module']}[/dim]")

    # Port-based attacks
    open_ports = _extract_open_ports(findings)
    if open_ports:
        console.print(f"\n[bold]🔓 Port-Based Attacks ({len(open_ports)} open ports):[/bold]")
        port_attacks: list[dict] = []
        for port in open_ports:
            for atk in SERVICE_ATTACKS.get(port, []):
                port_attacks.append({"port": port, **atk})
                attack_paths.append({"source": f"port:{port}", **atk})

        port_attacks.sort(key=lambda x: RISK_ORDER.get(x["risk"], 99))
        tbl = Table(show_lines=True)
        tbl.add_column("Port",   justify="right", width=6)
        tbl.add_column("Risk",   width=9)
        tbl.add_column("Attack Vector",         style="bold white",   max_width=28)
        tbl.add_column("Metasploit Module",     style="dim",          max_width=45)
        for a in port_attacks[:15]:
            color = "#ff2d78" if a["risk"] == "CRITICAL" else ("#ffaa00" if a["risk"] == "HIGH" else "cyan")
            tbl.add_row(str(a["port"]),
                        f"[bold {color}]{a['risk']}[/bold {color}]",
                        a["name"], a["msf"])
        console.print(tbl)

    # Technology-based attacks
    tech_list = _extract_tech(findings)
    if tech_list:
        console.print(f"\n[bold]⚙  Technology Attack Vectors:[/bold]")
        for tech in tech_list:
            for canonical, attacks in TECH_ATTACKS.items():
                if canonical.lower() in tech.lower():
                    for atk in attacks:
                        attack_paths.append({"source": f"tech:{tech}", **atk})
                        color = "#ff2d78" if atk["risk"] in ("CRITICAL","HIGH") else "#ffaa00"
                        console.print(f"  [{color}]{atk['risk']}[/{color}]  {tech} → [bold]{atk['name']}[/bold]")
                        console.print(f"  [dim]    msf> use {atk['msf']}[/dim]")

    # Attack path tree
    if attack_paths:
        console.print(f"\n[bold]🗺  Attack Path Summary:[/bold]")
        tree = Tree(f"[bold cyan]{target}[/bold cyan]")
        by_risk: dict[str, list] = {}
        for a in attack_paths:
            by_risk.setdefault(a.get("risk","MEDIUM"), []).append(a)
        for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = by_risk.get(risk, [])
            if items:
                color  = "#ff2d78" if risk=="CRITICAL" else ("#ffaa00" if risk=="HIGH" else "cyan")
                branch = tree.add(f"[bold {color}]{risk}[/bold {color}]  ({len(items)})")
                for a in items[:5]:
                    branch.add(f"[dim]{a.get('source','?')}[/dim] → {a.get('name','?')}")
        console.print(tree)

        total   = len(attack_paths)
        critical = sum(1 for a in attack_paths if a.get("risk") == "CRITICAL")
        high    = sum(1 for a in attack_paths if a.get("risk") == "HIGH")
        console.print(f"\n[bold]Total attack vectors:[/bold] {total}  "
                      f"[bold #ff2d78]Critical: {critical}[/bold #ff2d78]  "
                      f"[bold #ffaa00]High: {high}[/bold #ffaa00]")

    if generate_commands and attack_paths:
        console.print(f"\n[bold]📋 Metasploit RC Script:[/bold]")
        console.print("[dim]# Save as attack.rc and run: msfconsole -r attack.rc[/dim]")
        seen = set()
        for a in attack_paths[:8]:
            mod = a.get("msf","")
            if mod and mod not in seen:
                seen.add(mod)
                console.print(f"use {mod}")
                console.print(f"set RHOSTS {target}")
                console.print("run\n")

    if not attack_paths:
        console.print("\n[green]✓  No known attack vectors identified from findings.[/green]")
        console.print("[dim]Run [bold]omega auto " + target + "[/bold] for a full surface scan first.[/dim]")

    console.print("\n[dim bold red]⚠  For authorized penetration testing only.[/dim bold red]")
