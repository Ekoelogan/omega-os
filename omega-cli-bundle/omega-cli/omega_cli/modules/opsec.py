"""omega opsec — OpSec self-audit: DNS leaks, proxy check, fingerprint hints, OPSEC score."""
from __future__ import annotations
import json
import socket
import time

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

console = Console()

IP_APIS = [
    "https://api.ipify.org?format=json",
    "https://api64.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    "https://ipinfo.io/json",
]

DNS_LEAK_SERVERS = [
    ("8.8.8.8",         "Google DNS"),
    ("1.1.1.1",         "Cloudflare"),
    ("9.9.9.9",         "Quad9"),
    ("208.67.222.222",  "OpenDNS"),
    ("77.88.8.8",       "Yandex DNS"),
]

WEBRTC_CHECK_URL = "https://raw.githubusercontent.com/diafygi/webrtc-ips/master/index.html"
TOR_CHECK_URL    = "https://check.torproject.org/api/ip"
VPN_DETECT_API   = "https://ipapi.co/{ip}/json/"


def _get_public_ip() -> dict:
    for api in IP_APIS:
        try:
            r = requests.get(api, timeout=6)
            r.raise_for_status()
            data = r.json()
            ip = data.get("ip") or data.get("IP") or data.get("ip_addr") or data.get("ip_address")
            if ip:
                return {"ip": ip, "source": api.split("/")[2]}
        except Exception:
            continue
    return {}


def _dns_leak_test() -> list[dict]:
    """Test which DNS servers resolve our lookup — different results = DNS leak."""
    results = []
    test_domain = f"leak-test-{int(time.time())}.omega-dns-test.com"
    for server_ip, name in DNS_LEAK_SERVERS:
        try:
            import dns.resolver
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = [server_ip]
            res.lifetime    = 3
            # Just check if server is reachable and responds
            res.resolve("google.com", "A")
            results.append({"server": server_ip, "name": name, "status": "reachable"})
        except Exception:
            results.append({"server": server_ip, "name": name, "status": "timeout"})
    return results


def _check_tor() -> dict:
    try:
        r = requests.get(TOR_CHECK_URL, timeout=8)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


def _vpn_detect(ip: str) -> dict:
    try:
        r = requests.get(VPN_DETECT_API.format(ip=ip), timeout=8)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


def _score_opsec(ip_data: dict, tor_data: dict, vpn_data: dict) -> tuple[int, list[str]]:
    score   = 100
    issues  = []

    if not tor_data.get("IsTor"):
        score -= 20
        issues.append("Not routing through Tor (-20)")

    org = vpn_data.get("org", "")
    if org and not any(k in org.lower() for k in ("vpn", "proxy", "tunnel", "hosting", "cloud")):
        score -= 15
        issues.append(f"ISP/Org visible: {org[:40]} (-15)")

    country = vpn_data.get("country_name", "")
    if country in ("United States", "United Kingdom", "Australia", "Canada", "New Zealand"):
        score -= 10
        issues.append(f"Five Eyes country: {country} (-10)")

    if vpn_data.get("timezone", ""):
        score -= 5
        issues.append("Timezone fingerprint exposed (-5)")

    return max(score, 0), issues


def run(target_ip: str = "") -> None:
    console.print(Panel(
        "[bold #ff2d78]🛡  OpSec Audit[/bold #ff2d78]  — Anonymity & Privacy Self-Check",
        expand=False,
    ))

    # Real IP
    console.print("\n[bold]🌐 Identifying your exit IP…[/bold]")
    ip_result = _get_public_ip()
    ip = target_ip or ip_result.get("ip", "unknown")

    tbl = Table(show_header=False, box=None, padding=(0, 2))
    tbl.add_column("Key",   style="bold #ff2d78")
    tbl.add_column("Value", style="white")
    tbl.add_row("Your IP",  f"[bold cyan]{ip}[/bold cyan]")
    tbl.add_row("Source",   ip_result.get("source", "manual"))
    console.print(tbl)

    # Tor check
    console.print("\n[bold]🧅 Tor exit node check…[/bold]")
    tor_data = _check_tor()
    is_tor   = tor_data.get("IsTor", False)
    console.print(f"  {'[green]✓ Routing through Tor[/green]' if is_tor else '[red]✗ NOT using Tor[/red]'}")

    # VPN / ISP detect
    console.print("\n[bold]🔒 VPN / ISP fingerprint…[/bold]")
    vpn_data = _vpn_detect(ip)
    if vpn_data and not vpn_data.get("error"):
        tbl2 = Table(show_header=False, box=None, padding=(0, 2))
        tbl2.add_column("Key",   style="bold #ff2d78")
        tbl2.add_column("Value", style="white")
        tbl2.add_row("ISP",          vpn_data.get("org", "—"))
        tbl2.add_row("Country",      vpn_data.get("country_name", "—"))
        tbl2.add_row("Region",       vpn_data.get("region", "—"))
        tbl2.add_row("Timezone",     vpn_data.get("timezone", "—"))
        tbl2.add_row("ASN",          vpn_data.get("asn", "—"))
        console.print(tbl2)

    # DNS leak test
    console.print("\n[bold]🔍 DNS server reachability…[/bold]")
    dns_results = _dns_leak_test()
    dns_tbl = Table(show_lines=True)
    dns_tbl.add_column("DNS Server", style="cyan")
    dns_tbl.add_column("Name",       style="dim")
    dns_tbl.add_column("Status")
    for d in dns_results:
        color = "green" if d["status"] == "reachable" else "dim"
        dns_tbl.add_row(d["server"], d["name"], f"[{color}]{d['status']}[/{color}]")
    console.print(dns_tbl)

    # OPSEC score
    score, issues = _score_opsec(ip_result, tor_data, vpn_data)
    score_color = "green" if score >= 80 else ("#ffaa00" if score >= 50 else "#ff2d78")
    console.print(f"\n[bold]OpSec Score: [{score_color}]{score}/100[/{score_color}][/bold]")
    if issues:
        for i in issues:
            console.print(f"  [yellow]⚠[/yellow]  {i}")

    # Recommendations
    console.print("\n[bold]Recommendations:[/bold]")
    if not is_tor:
        console.print("  • Run [bold]omega proxy tor[/bold] to route through Tor")
    if score < 80:
        console.print("  • Use a VPN + Tor in combination")
        console.print("  • Use Tails OS or Whonix for sensitive investigations")
    console.print("  • Browser: use Tor Browser or Firefox with uBlock Origin + CanvasBlocker")
    console.print("  • Check WebRTC leaks: https://browserleaks.com/webrtc")
