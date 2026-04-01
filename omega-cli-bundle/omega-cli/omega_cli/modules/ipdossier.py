"""ipdossier.py — Deep IP dossier: PTR, ASN, BGP peers, abuse contacts, multi-blacklist."""
from __future__ import annotations
import json, re, socket, ipaddress
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
  OMEGA-CLI v1.7.0 — OSINT & Passive Recon Toolkit
"""

UA = "Mozilla/5.0 (compatible; OmegaCLI/1.7.0)"

# DNSBL blacklists
DNSBL = [
    "zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net",
    "b.barracudacentral.org", "dnsbl-1.uceprotect.net",
    "cbl.abuseat.org", "drone.abuse.ch", "spam.dnsbl.sorbs.net",
]


def _get(url: str, timeout: int = 8) -> Optional[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _resolve_host(target: str) -> str:
    """Resolve hostname to IP if needed."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return target


def _ptr_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def _dnsbl_check(ip: str) -> list[dict]:
    """Check IP against multiple DNSBLs."""
    results = []
    try:
        parts = ip.split(".")
        rev = ".".join(reversed(parts))
    except Exception:
        return results

    for bl in DNSBL:
        query = f"{rev}.{bl}"
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(query)
            results.append({"blacklist": bl, "listed": True})
        except socket.gaierror:
            results.append({"blacklist": bl, "listed": False})
        except Exception:
            results.append({"blacklist": bl, "listed": None})
    return results


def _ipapi(ip: str) -> dict:
    data = _get(f"https://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query")
    return data or {}


def _ipinfo(ip: str) -> dict:
    data = _get(f"https://ipinfo.io/{ip}/json")
    return data or {}


def _bgp_he(ip: str) -> dict:
    """BGP info from bgp.he.net (HTML parse)."""
    req = urllib.request.Request(
        f"https://bgp.he.net/ip/{ip}",
        headers={"User-Agent": UA}
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            html = r.read(200_000).decode("utf-8", errors="replace")
        asn = re.search(r"AS(\d+)", html)
        prefix = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", html)
        peers_raw = re.findall(r"AS(\d+)[^<]*<[^>]*>([^<]{2,60})</", html)
        return {
            "asn": f"AS{asn.group(1)}" if asn else "N/A",
            "prefix": prefix.group(1) if prefix else "N/A",
            "peers_sample": [{"asn": f"AS{a}", "name": n.strip()} for a, n in peers_raw[:5]],
        }
    except Exception:
        return {}


def _abuseipdb(ip: str, api_key: str) -> dict:
    if not api_key:
        return {}
    req = urllib.request.Request(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": api_key, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode()).get("data", {})
    except Exception:
        return {}


def _shodan_internetdb(ip: str) -> dict:
    data = _get(f"https://internetdb.shodan.io/{ip}")
    return data or {}


def run(target: str, api_key: str = "", export: str = ""):
    ip = _resolve_host(target)
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"🌐  IP Dossier — {target}  [{ip}]", style="bold cyan"))

    results = {"target": target, "ip": ip}

    # PTR
    ptr = _ptr_lookup(ip)
    results["ptr"] = ptr
    console.print(f"[cyan]PTR:[/cyan] {ptr}")

    # Geolocation (ip-api)
    console.print("\n[bold]Geolocation & ASN[/bold]")
    geo = _ipapi(ip)
    results["geo"] = geo
    if geo.get("status") == "success":
        t = Table(box=box.SIMPLE if box else None, show_header=False)
        t.add_column("Field", style="cyan")
        t.add_column("Value")
        for field in ["country","city","region","zip","lat","lon","timezone","isp","org","as","asname"]:
            val = geo.get(field, "")
            if val:
                t.add_row(field.title(), str(val))
        flags = []
        if geo.get("proxy"):  flags.append("⚠ PROXY")
        if geo.get("hosting"): flags.append("⚠ HOSTING/DC")
        if geo.get("mobile"):  flags.append("📱 MOBILE")
        if flags:
            t.add_row("Flags", " ".join(flags))
        console.print(t)

    # ipinfo
    info = _ipinfo(ip)
    results["ipinfo"] = info
    if info.get("org"):
        console.print(f"[dim]ipinfo org: {info.get('org')}[/dim]")

    # Shodan InternetDB
    console.print("\n[bold]Shodan InternetDB[/bold]")
    sdb = _shodan_internetdb(ip)
    results["shodan_internetdb"] = sdb
    if sdb and not sdb.get("detail"):
        console.print(f"  Open ports: [green]{', '.join(str(p) for p in sdb.get('ports', []))}[/green]")
        console.print(f"  Hostnames:  {', '.join(sdb.get('hostnames', []))}")
        vulns = sdb.get("vulns", [])
        if vulns:
            console.print(f"  [red]Vulns:[/red] {', '.join(vulns[:10])}")
        tags = sdb.get("tags", [])
        if tags:
            console.print(f"  Tags: {', '.join(tags)}")
    else:
        console.print("  [dim]No Shodan data[/dim]")

    # BGP
    console.print("\n[bold]BGP Info (bgp.he.net)[/bold]")
    bgp = _bgp_he(ip)
    results["bgp"] = bgp
    if bgp:
        console.print(f"  ASN: [cyan]{bgp.get('asn')}[/cyan]  Prefix: {bgp.get('prefix')}")
        if bgp.get("peers_sample"):
            console.print("  BGP Peers (sample):")
            for p in bgp["peers_sample"]:
                console.print(f"    [dim]{p['asn']}[/dim] {p['name']}")

    # DNSBL
    console.print("\n[bold]Blacklist Check (8 DNSBLs)[/bold]")
    bl_results = _dnsbl_check(ip)
    results["dnsbl"] = bl_results
    listed = [r for r in bl_results if r["listed"] is True]
    clean  = [r for r in bl_results if r["listed"] is False]
    console.print(f"  [red]Listed: {len(listed)}[/red]  [green]Clean: {len(clean)}[/green]  Unknown: {len(bl_results)-len(listed)-len(clean)}")
    for r in listed:
        console.print(f"  [red]⛔ {r['blacklist']}[/red]")

    # AbuseIPDB
    if api_key:
        console.print("\n[bold]AbuseIPDB[/bold]")
        abuse = _abuseipdb(ip, api_key)
        results["abuseipdb"] = abuse
        if abuse:
            console.print(f"  Score: [{'red' if abuse.get('abuseConfidenceScore', 0) > 50 else 'green'}]{abuse.get('abuseConfidenceScore')}%[/]")
            console.print(f"  Reports: {abuse.get('totalReports')}  Domain: {abuse.get('domain')}")
            console.print(f"  Country: {abuse.get('countryCode')}  ISP: {abuse.get('isp')}")

    # Summary risk
    risk_score = 0
    if listed: risk_score += len(listed) * 20
    if geo.get("proxy"): risk_score += 30
    if geo.get("hosting"): risk_score += 10
    vulns = sdb.get("vulns", []) if isinstance(sdb, dict) else []
    if vulns: risk_score += len(vulns) * 5
    risk_score = min(100, risk_score)
    level = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 20 else "LOW"
    color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}[level]
    console.print(f"\n[bold]Risk Score:[/bold] [{color}]{risk_score}/100 ({level})[/{color}]")
    results["risk_score"] = risk_score
    results["risk_level"] = level

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", target)
    out_path = Path(export) if export else out_dir / f"ipdossier_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
