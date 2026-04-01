"""omega network — Network topology mapper: traceroute, BGP, CDN/WAF fingerprint, hosting."""
from __future__ import annotations
import socket
import struct
import time
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()

CDN_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":    ["cloudflare", "cf-ray", "cf-cache"],
    "Fastly":        ["fastly", "x-fastly", "x-served-by"],
    "Akamai":        ["akamai", "x-akamai"],
    "AWS CloudFront":["cloudfront", "x-amz-cf"],
    "Sucuri":        ["sucuri", "x-sucuri"],
    "BunnyCDN":      ["bunnycdn"],
    "KeyCDN":        ["keycdn"],
    "Varnish":       ["via: 1.1 varnish", "x-varnish"],
    "Nginx":         ["nginx"],
    "Apache":        ["apache"],
}

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare WAF":      ["cloudflare", "__cfduid", "cf-ray"],
    "AWS WAF":             ["awswaf", "x-amzn-requestid"],
    "Sucuri WAF":          ["sucuri", "x-sucuri-id"],
    "ModSecurity":         ["mod_security", "modsecurity"],
    "Barracuda":           ["barra"],
    "F5 BIG-IP":           ["bigipserver", "f5"],
    "Imperva/Incapsula":   ["incap_ses", "visid_incap", "incapsula"],
    "Akamai Kona":         ["akamai"],
}

HOSTING_ASN_MAP: dict[str, str] = {
    "AS13335": "Cloudflare",
    "AS14618": "Amazon AWS",
    "AS16509": "Amazon AWS",
    "AS8075":  "Microsoft Azure",
    "AS15169": "Google Cloud",
    "AS24940": "Hetzner",
    "AS14061": "DigitalOcean",
    "AS63949": "Linode/Akamai",
    "AS20473": "Vultr",
    "AS46606": "Unified Layer/HostGator",
}


def _resolve(target: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(target, None)
        return list(dict.fromkeys(info[4][0] for info in infos))
    except Exception:
        return []


def _traceroute(target: str, max_hops: int = 15) -> list[dict]:
    """Pure Python ICMP traceroute (requires no external tools)."""
    import select
    hops = []
    ip = _resolve(target)
    dest_ip = ip[0] if ip else target

    for ttl in range(1, max_hops + 1):
        try:
            # UDP probe on high port
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                       socket.IPPROTO_ICMP)
            recv_sock.settimeout(2)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            t0 = time.time()
            send_sock.sendto(b"omega-trace", (dest_ip, 33434 + ttl))

            try:
                data, addr = recv_sock.recvfrom(1024)
                rtt = (time.time() - t0) * 1000
                hop_ip  = addr[0]
                # Try reverse DNS
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except Exception:
                    hostname = ""
                hops.append({"ttl": ttl, "ip": hop_ip, "hostname": hostname,
                              "rtt_ms": round(rtt, 1)})
                if hop_ip == dest_ip:
                    break
            except socket.timeout:
                hops.append({"ttl": ttl, "ip": "*", "hostname": "", "rtt_ms": None})
            finally:
                send_sock.close()
                recv_sock.close()
        except PermissionError:
            hops.append({"ttl": ttl, "ip": "?", "hostname": "requires root",
                          "rtt_ms": None})
            break
        except Exception:
            break
    return hops


def _cdn_waf_detect(target: str) -> dict:
    detected_cdn = []
    detected_waf = []
    try:
        r = requests.get(f"https://{target}", timeout=8, verify=False,
                         headers={"User-Agent": "omega-cli/1.1.0"})
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        header_str    = " ".join(f"{k} {v}" for k, v in headers_lower.items())

        for cdn, sigs in CDN_SIGNATURES.items():
            if any(s in header_str for s in sigs):
                detected_cdn.append(cdn)
        for waf, sigs in WAF_SIGNATURES.items():
            if any(s in header_str for s in sigs):
                detected_waf.append(waf)

        # Cookie-based WAF detection
        for cookie in r.cookies:
            cname = cookie.name.lower()
            if "incap" in cname or "visid" in cname:
                detected_waf.append("Imperva/Incapsula")
            elif "__cfduid" in cname or "cf_" in cname:
                if "Cloudflare WAF" not in detected_waf:
                    detected_waf.append("Cloudflare WAF")
    except Exception:
        pass
    return {"cdn": list(set(detected_cdn)), "waf": list(set(detected_waf))}


def _bgp_info(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        r.raise_for_status()
        d = r.json()
        asn = d.get("org", "").split(" ")[0]
        return {
            "ip":       ip,
            "asn":      asn,
            "org":      d.get("org", ""),
            "country":  d.get("country", ""),
            "region":   d.get("region", ""),
            "city":     d.get("city", ""),
            "hosting":  HOSTING_ASN_MAP.get(asn, "Unknown / Custom"),
        }
    except Exception as e:
        return {"error": str(e)}


def _dns_propagation(target: str) -> dict:
    """Check DNS across multiple global resolvers."""
    resolvers = {
        "Google (8.8.8.8)":      "8.8.8.8",
        "Cloudflare (1.1.1.1)":  "1.1.1.1",
        "Quad9 (9.9.9.9)":       "9.9.9.9",
        "OpenDNS":                "208.67.222.222",
    }
    results = {}
    import dns.resolver
    for name, server in resolvers.items():
        try:
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = [server]
            res.lifetime    = 3
            ans = res.resolve(target, "A")
            results[name] = [str(r) for r in ans]
        except Exception:
            results[name] = ["timeout/error"]
    return results


def run(target: str, no_trace: bool = False) -> None:
    console.print(Panel(
        f"[bold #ff2d78]🌐  Network Topology[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    # IP resolution
    ips = _resolve(target)
    console.print(f"\n[bold]📍 IP Addresses:[/bold]")
    for ip in ips:
        console.print(f"  [cyan]{ip}[/cyan]")

    # BGP / ASN / Hosting
    if ips:
        console.print(f"\n[bold]🏢 BGP / Hosting:[/bold]")
        for ip in ips[:2]:
            bgp = _bgp_info(ip)
            tbl = Table(show_header=False, box=None, padding=(0, 2))
            tbl.add_column("Key",   style="bold #ff2d78")
            tbl.add_column("Value", style="white")
            for k, v in bgp.items():
                if v and str(v) != "Unknown / Custom":
                    tbl.add_row(k, str(v))
            console.print(tbl)

    # CDN / WAF
    console.print(f"\n[bold]🛡  CDN / WAF Detection:[/bold]")
    shields = _cdn_waf_detect(target)
    cdn = shields.get("cdn", [])
    waf = shields.get("waf", [])
    console.print(f"  CDN: {', '.join(cdn) if cdn else '[dim]none detected[/dim]'}")
    console.print(f"  WAF: {', '.join(waf) if waf else '[dim]none detected[/dim]'}")

    # DNS propagation
    console.print(f"\n[bold]🌍 DNS Propagation:[/bold]")
    prop = _dns_propagation(target)
    prop_tbl = Table(show_lines=True)
    prop_tbl.add_column("Resolver",  style="dim")
    prop_tbl.add_column("A Records", style="cyan")
    for resolver, records in prop.items():
        prop_tbl.add_row(resolver, ", ".join(records[:3]))
    console.print(prop_tbl)

    # Check propagation consistency
    unique_sets = {frozenset(v) for v in prop.values() if v != ["timeout/error"]}
    if len(unique_sets) > 1:
        console.print("[yellow]⚠  DNS inconsistency detected — different resolvers return different IPs.[/yellow]")
    else:
        console.print("[green]✓  DNS propagation consistent across all resolvers.[/green]")

    # Traceroute
    if not no_trace and ips:
        console.print(f"\n[bold]🔀 Traceroute → {ips[0]}:[/bold]")
        hops = _traceroute(target)
        if hops and hops[0].get("ip") != "?":
            hop_tbl = Table(show_lines=False)
            hop_tbl.add_column("TTL",      justify="right", width=4)
            hop_tbl.add_column("IP",       style="cyan",    max_width=16)
            hop_tbl.add_column("Hostname", style="dim",     max_width=35)
            hop_tbl.add_column("RTT (ms)", justify="right", max_width=10)
            for h in hops:
                rtt = str(h["rtt_ms"]) if h["rtt_ms"] else "*"
                hop_tbl.add_row(str(h["ttl"]), h["ip"], h["hostname"], rtt)
            console.print(hop_tbl)
        else:
            console.print("[dim]Traceroute requires root/cap_net_raw — run with sudo for full trace.[/dim]")
            console.print("[dim]Alternative: traceroute " + target + "[/dim]")
