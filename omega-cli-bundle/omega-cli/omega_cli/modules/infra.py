"""omega infra — Infrastructure archaeology: IP history, WHOIS history, CDN pivots, cloud mapping."""
from __future__ import annotations
import json, re, socket
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.tree import Tree

console = Console()
TIMEOUT = 10

CDN_SIGNATURES = {
    "Cloudflare":   ["cloudflare", "cf-ray", "cf-cache-status"],
    "Fastly":       ["fastly", "x-fastly-request-id", "x-served-by"],
    "Akamai":       ["akamai", "x-akamai", "x-check-cacheable"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "Azure CDN":    ["azure", "x-azure-ref", "x-msedge-ref"],
    "Imperva/Incapsula": ["incapsula", "x-iinfo", "_incap_"],
    "Sucuri":       ["sucuri", "x-sucuri-id"],
    "BunnyCDN":     ["bunnycdn", "x-bunny-server"],
    "KeyCDN":       ["keycdn", "x-pull"],
    "StackPath":    ["stackpath", "x-sp-"],
}

WAF_SIGNATURES = {
    "Cloudflare WAF":   ["cloudflare", "__cfduid", "cf-ray"],
    "AWS WAF":          ["awswaf", "x-amzn-requestid"],
    "ModSecurity":      ["mod_security", "modsecurity"],
    "Barracuda":        ["barracuda_", "barra_counter_session"],
    "F5 BIG-IP":        ["bigip", "bigipserver", "f5-"],
    "Fortinet":         ["fortigate", "fortiwafsid"],
    "Imperva":          ["x-iinfo", "visid_incap"],
}


def _resolve_ip(host: str) -> list[str]:
    try:
        return list({r[4][0] for r in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _ip_history(host: str) -> list[dict]:
    """SecurityTrails-style IP history via HackerTarget."""
    results = []
    try:
        r = httpx.get(f"https://api.hackertarget.com/dnslookup/?q={host}", timeout=TIMEOUT)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("error"):
                    parts = line.split()
                    if len(parts) >= 2:
                        results.append({"record": parts[0], "type": parts[-2] if len(parts) > 2 else "?",
                                        "value": parts[-1]})
    except Exception:
        pass

    # Also try ViewDNS IP history endpoint
    try:
        r2 = httpx.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={host}",
            timeout=TIMEOUT
        )
        if r2.status_code == 200 and "error" not in r2.text.lower():
            for domain in r2.text.splitlines()[:20]:
                domain = domain.strip()
                if domain:
                    results.append({"shared_host": domain})
    except Exception:
        pass
    return results


def _cdn_waf_detect(host: str) -> dict:
    detected_cdn = []
    detected_waf = []
    headers_found: dict = {}
    try:
        r = httpx.get(f"https://{host}", timeout=TIMEOUT, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0"})
        resp_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        headers_found = dict(r.headers)
        for cdn, sigs in CDN_SIGNATURES.items():
            for sig in sigs:
                if any(sig in v for v in resp_headers.values()) or any(sig in k for k in resp_headers):
                    detected_cdn.append(cdn)
                    break
        for waf, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if any(sig in v for v in resp_headers.values()) or any(sig in k for k in resp_headers):
                    detected_waf.append(waf)
                    break
    except Exception:
        pass
    return {"cdns": list(set(detected_cdn)), "wafs": list(set(detected_waf)), "headers": headers_found}


def _asn_info(ip: str) -> dict:
    try:
        r = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            return {
                "ip": ip,
                "asn": d.get("asn"),
                "org": d.get("org"),
                "country": d.get("country_name"),
                "city": d.get("city"),
                "isp": d.get("org"),
                "network": d.get("network"),
            }
    except Exception:
        pass
    return {"ip": ip}


def _whois_history(domain: str) -> dict:
    """Fetch current WHOIS data (history requires paid APIs)."""
    try:
        r = httpx.get(f"https://api.hackertarget.com/whois/?q={domain}", timeout=TIMEOUT)
        if r.status_code == 200 and "error" not in r.text[:50].lower():
            text = r.text
            result: dict[str, Any] = {"raw": text[:2000]}
            for line in text.splitlines():
                ll = line.lower()
                if "registrar:" in ll:
                    result["registrar"] = line.split(":", 1)[1].strip()
                elif "creation date:" in ll or "created:" in ll:
                    result["created"] = line.split(":", 1)[1].strip()
                elif "expiry date:" in ll or "expiration date:" in ll:
                    result["expires"] = line.split(":", 1)[1].strip()
                elif "name server:" in ll or "nserver:" in ll:
                    result.setdefault("nameservers", []).append(line.split(":", 1)[1].strip())
                elif "registrant" in ll and "email" in ll:
                    result["registrant_email"] = line.split(":", 1)[1].strip()
            return result
    except Exception:
        pass
    return {}


def _subdomain_pivot(domain: str) -> list[str]:
    """Quick subdomain pivot via HackerTarget."""
    try:
        r = httpx.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=TIMEOUT)
        if r.status_code == 200 and "error" not in r.text[:30].lower():
            subs = []
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts:
                    subs.append(parts[0].strip())
            return subs[:20]
    except Exception:
        pass
    return []


def _cloud_provider(ip: str, org: str) -> str:
    """Guess cloud provider from ASN/org string."""
    org_lower = (org or "").lower()
    if "amazon" in org_lower or "aws" in org_lower:
        return "AWS"
    if "google" in org_lower:
        return "GCP"
    if "microsoft" in org_lower or "azure" in org_lower:
        return "Azure"
    if "digitalocean" in org_lower:
        return "DigitalOcean"
    if "linode" in org_lower or "akamai" in org_lower:
        return "Linode/Akamai"
    if "vultr" in org_lower:
        return "Vultr"
    if "hetzner" in org_lower:
        return "Hetzner"
    if "ovh" in org_lower:
        return "OVHcloud"
    return "Unknown"


def run(target: str, no_cdn: bool = False, deep: bool = False):
    console.print(Panel(
        f"[bold #ff2d78]🏗  Infrastructure Archaeology[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    domain = target if not is_ip else ""
    findings: dict[str, Any] = {"target": target}

    tree = Tree(f"[bold #ff2d78]⛏  {target}[/bold #ff2d78]")

    # IP resolution
    ips = [target] if is_ip else _resolve_ip(target)
    findings["ips"] = ips
    ip_branch = tree.add("[bold cyan]IP Addresses[/bold cyan]")
    for ip in ips:
        rdns = _rdns(ip)
        ip_branch.add(f"[green]{ip}[/green]" + (f" ← [dim]{rdns}[/dim]" if rdns else ""))

    # ASN info for each IP
    asn_data = []
    asn_branch = tree.add("[bold cyan]ASN / Hosting[/bold cyan]")
    for ip in ips[:3]:
        with console.status(f"[dim]ASN lookup: {ip}…[/dim]"):
            asn = _asn_info(ip)
        asn_data.append(asn)
        provider = _cloud_provider(ip, asn.get("org", ""))
        asn_branch.add(
            f"[green]{ip}[/green] → [yellow]{asn.get('asn', '?')}[/yellow] "
            f"{asn.get('org', '?')} [dim]({asn.get('country', '?')})[/dim] "
            f"[cyan]{provider}[/cyan]"
        )
    findings["asn"] = asn_data

    # CDN / WAF
    if not no_cdn:
        with console.status("[dim]CDN/WAF fingerprinting…[/dim]"):
            cdn_waf = _cdn_waf_detect(target)
        findings["cdn_waf"] = cdn_waf
        layer_branch = tree.add("[bold cyan]CDN / WAF[/bold cyan]")
        if cdn_waf["cdns"]:
            for c in cdn_waf["cdns"]:
                layer_branch.add(f"[magenta]CDN:[/magenta] {c}")
        if cdn_waf["wafs"]:
            for w in cdn_waf["wafs"]:
                layer_branch.add(f"[red]WAF:[/red] {w}")
        if not cdn_waf["cdns"] and not cdn_waf["wafs"]:
            layer_branch.add("[dim]No CDN/WAF detected[/dim]")

    # WHOIS history
    if domain:
        with console.status("[dim]WHOIS history…[/dim]"):
            whois = _whois_history(domain)
        findings["whois"] = whois
        whois_branch = tree.add("[bold cyan]WHOIS[/bold cyan]")
        if whois:
            whois_branch.add(f"Registrar: {whois.get('registrar', '?')}")
            whois_branch.add(f"Created:   {whois.get('created', '?')}")
            whois_branch.add(f"Expires:   {whois.get('expires', '?')}")
            for ns in (whois.get("nameservers") or [])[:4]:
                whois_branch.add(f"[dim]NS: {ns}[/dim]")

    # IP/DNS history
    with console.status("[dim]DNS/IP history…[/dim]"):
        dns_hist = _ip_history(target)
    findings["dns_history"] = dns_hist
    dns_branch = tree.add("[bold cyan]DNS / Shared Hosting[/bold cyan]")
    seen_shared = [h.get("shared_host") for h in dns_hist if h.get("shared_host")]
    seen_dns = [h for h in dns_hist if "record" in h]
    for rec in seen_dns[:8]:
        dns_branch.add(f"[dim]{rec.get('type','?')}[/dim] → [green]{rec.get('value','?')}[/green]")
    if seen_shared:
        shared_branch = dns_branch.add(f"[yellow]Shared hosting ({len(seen_shared)} domain(s))[/yellow]")
        for d in seen_shared[:10]:
            shared_branch.add(f"[dim]{d}[/dim]")

    # Subdomain pivot
    if domain and deep:
        with console.status("[dim]Subdomain pivot…[/dim]"):
            subs = _subdomain_pivot(domain)
        findings["subdomains"] = subs
        if subs:
            sub_branch = tree.add(f"[bold cyan]Subdomains ({len(subs)})[/bold cyan]")
            for s in subs[:15]:
                sub_branch.add(f"[green]{s}[/green]")

    console.print(tree)

    # Summary table
    t = Table("Property", "Value", box=box.MINIMAL_HEAVY_HEAD, show_header=False)
    t.add_row("[bold]IPs[/bold]",         ", ".join(ips[:5]))
    if asn_data:
        t.add_row("[bold]ASN[/bold]",     asn_data[0].get("asn", "?"))
        t.add_row("[bold]Hosting[/bold]", _cloud_provider(ips[0] if ips else "", asn_data[0].get("org", "")))
        t.add_row("[bold]Country[/bold]", asn_data[0].get("country", "?"))
    if not no_cdn and "cdn_waf" in findings:
        t.add_row("[bold]CDN[/bold]",     ", ".join(findings["cdn_waf"]["cdns"]) or "None")
        t.add_row("[bold]WAF[/bold]",     ", ".join(findings["cdn_waf"]["wafs"]) or "None")
    console.print(t)

    import os, datetime
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"infra_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
