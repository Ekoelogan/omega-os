"""omega intel — Threat intelligence aggregator: OTX, AbuseIPDB, Greynoise."""
from __future__ import annotations
import ipaddress
import re
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

OTX_BASE      = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"
GREYNOISE_API = "https://api.greynoise.io/v3/community/{ip}"


def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def _otx_lookup(ioc: str, otx_key: str = "") -> None:
    """Query AlienVault OTX for pulse / reputation data."""
    headers = {}
    if otx_key:
        headers["X-OTX-API-KEY"] = otx_key

    if _is_ip(ioc):
        ioc_type = "IPv4"
    elif re.match(r"^[0-9a-fA-F]{32,64}$", ioc):
        ioc_type = "file"
        section  = "analysis"
    else:
        ioc_type = "domain"

    # Map type → OTX endpoint sections
    if ioc_type == "IPv4":
        sections = ["general", "reputation", "geo", "malware", "url_list"]
    elif ioc_type == "domain":
        sections = ["general", "geo", "malware", "url_list", "passive_dns"]
    else:
        sections = ["analysis"]

    console.print(f"\n[bold]🔬 AlienVault OTX:[/bold] {ioc}")
    for section in sections[:2]:  # limit to keep output tidy
        url = f"{OTX_BASE}/indicators/{ioc_type}/{ioc}/{section}"
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 400:
                continue
            r.raise_for_status()
            data = r.json()
        except Exception as exc:
            console.print(f"  [yellow]OTX {section} error:[/yellow] {exc}")
            continue

        if section == "general":
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            rep         = data.get("reputation", 0)
            country     = data.get("country_name", data.get("country_code", ""))
            tbl = Table(show_header=False, box=None, padding=(0, 2))
            tbl.add_column("Key",   style="bold #ff2d78")
            tbl.add_column("Value", style="white")
            if country:
                tbl.add_row("Country",  country)
            tbl.add_row("OTX Pulses",   str(pulse_count))
            tbl.add_row("Reputation",   str(rep) + (" ⚠" if rep and rep < 0 else ""))
            if pulse_count > 0:
                pulses = data.get("pulse_info", {}).get("pulses", [])[:3]
                for p in pulses:
                    tbl.add_row("  Pulse", p.get("name", "")[:50])
            console.print(tbl)

        elif section == "reputation" and data.get("reputation"):
            rep = data["reputation"]
            acts = rep.get("activities", [])
            if acts:
                console.print(f"  [bold red]Threat activities:[/bold red] {', '.join(a.get('name','') for a in acts[:5])}")


def _abuseipdb_lookup(ip: str, api_key: str = "") -> None:
    """Query AbuseIPDB for abuse confidence score."""
    if not api_key:
        console.print(f"\n[dim]AbuseIPDB:[/dim] no API key (set with [bold]omega config set abuseipdb_api_key KEY[/bold])")
        return
    console.print(f"\n[bold]🚨 AbuseIPDB:[/bold] {ip}")
    try:
        r = requests.get(
            ABUSEIPDB_API,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column("Key",   style="bold #ff2d78")
        tbl.add_column("Value", style="white")
        score = d.get("abuseConfidenceScore", 0)
        color = "#ff2d78" if score > 50 else ("#ffaa00" if score > 10 else "green")
        tbl.add_row("Confidence Score", f"[bold {color}]{score}%[/bold {color}]")
        tbl.add_row("Total Reports",    str(d.get("totalReports", 0)))
        tbl.add_row("Distinct Users",   str(d.get("numDistinctUsers", 0)))
        tbl.add_row("Last Reported",    d.get("lastReportedAt") or "never")
        tbl.add_row("ISP",              d.get("isp", "—"))
        tbl.add_row("Usage Type",       d.get("usageType", "—"))
        tbl.add_row("Tor Node",         "Yes" if d.get("isTor") else "No")
        console.print(tbl)
    except Exception as exc:
        console.print(f"  [yellow]AbuseIPDB error:[/yellow] {exc}")


def _greynoise_lookup(ip: str, api_key: str = "") -> None:
    """Query GreyNoise community API."""
    console.print(f"\n[bold]🌩  GreyNoise:[/bold] {ip}")
    headers = {"key": api_key} if api_key else {}
    try:
        r = requests.get(GREYNOISE_API.format(ip=ip), headers=headers, timeout=10)
        if r.status_code == 404:
            console.print(f"  [dim]Not seen in GreyNoise scan data.[/dim]")
            return
        r.raise_for_status()
        d = r.json()
        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column("Key",   style="bold #ff2d78")
        tbl.add_column("Value", style="white")
        noise = d.get("noise", False)
        riot  = d.get("riot",  False)
        classification = d.get("classification", "unknown")
        color = "#ff2d78" if classification == "malicious" else ("green" if riot else "#ffaa00")
        tbl.add_row("Classification", f"[bold {color}]{classification}[/bold {color}]")
        tbl.add_row("Internet Noise", "Yes — mass scanning" if noise else "No")
        tbl.add_row("RIOT (legit)",   "Yes — known good actor" if riot else "No")
        tbl.add_row("Name",           d.get("name", "—"))
        tbl.add_row("Message",        d.get("message", "—"))
        tbl.add_row("Last seen",      d.get("last_seen", "—"))
        console.print(tbl)
    except Exception as exc:
        console.print(f"  [yellow]GreyNoise error:[/yellow] {exc}")


def run(target: str, otx_key: str = "", abuseipdb_key: str = "",
        greynoise_key: str = "") -> None:
    console.print(Panel(
        f"[bold #ff2d78]🛡  Threat Intelligence[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    _otx_lookup(target, otx_key=otx_key)

    if _is_ip(target):
        _abuseipdb_lookup(target, api_key=abuseipdb_key)
        _greynoise_lookup(target, api_key=greynoise_key)
    else:
        console.print(f"\n[dim]AbuseIPDB + GreyNoise only available for IP addresses.[/dim]")
        console.print(f"[dim]Try: [bold]omega dns {target}[/bold] to resolve IPs first.[/dim]")

    console.print("\n[dim]Also check:[/dim]")
    console.print(f"  https://otx.alienvault.com/indicator/domain/{target}")
    if _is_ip(target):
        console.print(f"  https://www.abuseipdb.com/check/{target}")
        console.print(f"  https://viz.greynoise.io/ip/{target}")
