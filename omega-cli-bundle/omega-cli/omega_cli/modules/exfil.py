"""omega exfil — Exfiltration & C2 pattern detection:
DNS tunnel detection (subdomain entropy), DGA detection, beaconing patterns."""
from __future__ import annotations
import json, os, re, math, datetime, collections
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
TIMEOUT = 8

# Known DGA families' domain length patterns
DGA_PATTERNS = [
    re.compile(r"^[a-z0-9]{16,}$"),           # long random alpha
    re.compile(r"^[a-z]{8,}\d{4,}[a-z]{2,}$"),# alpha+digits+alpha
]

# Known legit CDN/cloud high-entropy domains to whitelist
ENTROPY_WHITELIST = {
    "cloudfront.net", "amazonaws.com", "akamaihd.net", "fastly.net",
    "cloudflare.com", "azureedge.net", "googleusercontent.com",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = collections.Counter(s.lower())
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values() if c > 0)


def _is_dga_candidate(domain: str) -> tuple[bool, str]:
    """Return (is_suspicious, reason)."""
    parts = domain.split(".")
    if len(parts) < 2:
        return False, ""
    label = parts[0]
    tld = ".".join(parts[-2:])

    if tld in ENTROPY_WHITELIST:
        return False, ""

    entropy = _shannon_entropy(label)
    length = len(label)

    reasons = []
    if entropy > 3.8 and length > 10:
        reasons.append(f"high entropy ({entropy:.2f})")
    if length > 20:
        reasons.append(f"long label ({length} chars)")
    for pat in DGA_PATTERNS:
        if pat.match(label):
            reasons.append("DGA pattern match")
            break
    # Consonant ratio: DGA domains tend to have few vowels
    vowels = sum(1 for c in label if c in "aeiou")
    if length > 6 and vowels / length < 0.15:
        reasons.append(f"low vowel ratio ({vowels}/{length})")

    return bool(reasons), ", ".join(reasons)


def _check_dns_tunnel_indicators(domain: str) -> list[str]:
    """Check live DNS for tunnel indicators: long TXT records, unusual subdomains."""
    indicators = []
    try:
        import dns.resolver
        # TXT records with base64-like content suggest tunneling
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=4)
            for rdata in answers:
                for txt in rdata.strings:
                    txt_str = txt.decode(errors="ignore")
                    if len(txt_str) > 50:
                        indicators.append(f"Long TXT record ({len(txt_str)} chars): {txt_str[:60]}…")
        except Exception:
            pass
        # Many NS/MX records can indicate tunneling setup
        try:
            ns = dns.resolver.resolve(domain, "NS", lifetime=4)
            ns_list = [str(r) for r in ns]
            if len(ns_list) > 5:
                indicators.append(f"Unusually many NS records ({len(ns_list)})")
        except Exception:
            pass
    except ImportError:
        pass
    return indicators


def _fetch_passive_dns(domain: str) -> list[str]:
    """Get passive DNS subdomains from HackerTarget."""
    try:
        r = httpx.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=TIMEOUT,
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            lines = r.text.strip().splitlines()
            return [line.split(",")[0] for line in lines[:100] if "," in line]
    except Exception:
        pass
    return []


def _analyse_subdomains(subdomains: list[str]) -> list[dict]:
    suspicious = []
    for fqdn in subdomains:
        label = fqdn.split(".")[0]
        is_susp, reason = _is_dga_candidate(fqdn)
        entropy = _shannon_entropy(label)
        if is_susp or len(label) > 30:
            suspicious.append({
                "fqdn": fqdn,
                "label_length": len(label),
                "entropy": round(entropy, 3),
                "reason": reason or f"label length {len(label)}",
            })
    return sorted(suspicious, key=lambda x: -x["entropy"])


def _check_ioc_feeds(domain: str) -> list[dict]:
    """Check domain against free threat feeds."""
    hits = []
    try:
        r = httpx.get(
            f"https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "is_host":
                urls = data.get("urls", [])[:5]
                for u in urls:
                    hits.append({
                        "source": "URLhaus",
                        "url": u.get("url", "?"),
                        "threat": u.get("threat", "?"),
                        "status": u.get("url_status", "?"),
                    })
    except Exception:
        pass
    return hits


def _beaconing_check(ip: str) -> dict:
    """Check for C2 beaconing indicators via Shodan InternetDB."""
    result: dict[str, Any] = {}
    try:
        r = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            result["ports"] = data.get("ports", [])
            result["vulns"] = data.get("vulns", [])
            result["tags"] = data.get("tags", [])
            if any(t in data.get("tags", []) for t in ["c2", "malware", "bot"]):
                result["c2_flag"] = True
    except Exception:
        pass
    return result


def run(target: str, live: bool = True, subdomain_check: bool = True):
    console.print(Panel(
        f"[bold #ff2d78]🕵  Exfiltration & C2 Detection[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    findings: dict[str, Any] = {"target": target, "suspicious_domains": [], "tunnel_indicators": [], "c2_flags": []}

    if is_ip:
        with console.status("[cyan]Checking C2 indicators…"):
            beacon = _beaconing_check(target)
        findings["internetdb"] = beacon

        ports = beacon.get("ports", [])
        tags = beacon.get("tags", [])
        vulns = beacon.get("vulns", [])

        console.print(f"[bold]Open ports:[/bold] {ports}")
        console.print(f"[bold]Tags:[/bold]       {tags or 'none'}")
        if vulns:
            console.print(f"[bold red]Vulns:[/bold red]      {vulns[:5]}")

        # Known C2 ports
        c2_ports = [p for p in ports if p in [4444,8443,8080,50050,31337,1337,6667,6697,1080,3128]]
        if c2_ports:
            console.print(f"\n[bold red]⚠  Suspicious ports (C2 candidates): {c2_ports}[/bold red]")
            findings["c2_flags"].extend([f"Port {p}" for p in c2_ports])

        if beacon.get("c2_flag"):
            console.print("[bold red]⚠  Tagged as C2/malware in Shodan[/bold red]")
            findings["c2_flags"].append("Shodan C2 tag")

        if not c2_ports and not beacon.get("c2_flag"):
            console.print("[green]✓  No obvious C2 indicators found[/green]")

    else:
        # Domain-based exfil detection
        subdomains: list[str] = []
        if subdomain_check:
            with console.status("[cyan]Fetching passive DNS subdomains…"):
                subdomains = _fetch_passive_dns(target)
            console.print(f"[dim]Found {len(subdomains)} subdomains from passive DNS[/dim]")

        if subdomains:
            suspicious = _analyse_subdomains(subdomains)
            findings["suspicious_domains"] = suspicious

            if suspicious:
                t = Table("FQDN", "Length", "Entropy", "Reason",
                          title=f"[bold red]⚠  {len(suspicious)} Suspicious Subdomain(s)[/bold red]",
                          box=box.SIMPLE_HEAD, header_style="bold red")
                for s in suspicious[:20]:
                    color = "#ff0000" if s["entropy"] > 3.8 else "#ffd700"
                    t.add_row(
                        f"[{color}]{s['fqdn'][:60]}[/{color}]",
                        str(s["label_length"]),
                        f"{s['entropy']:.3f}",
                        s["reason"],
                    )
                console.print(t)
            else:
                console.print("[green]✓  No high-entropy or DGA-like subdomains detected[/green]")

        # Live DNS tunnel check
        if live:
            with console.status("[cyan]Checking DNS tunnel indicators…"):
                indicators = _check_dns_tunnel_indicators(target)
            findings["tunnel_indicators"] = indicators
            if indicators:
                console.print(f"\n[bold red]⚠  DNS Tunnel Indicators:[/bold red]")
                for ind in indicators:
                    console.print(f"  [red]•[/red] {ind}")
            else:
                console.print("[green]✓  No DNS tunnel indicators in TXT/NS records[/green]")

        # IOC feed check
        with console.status("[cyan]Checking URLhaus threat feeds…"):
            ioc_hits = _check_ioc_feeds(target)
        if ioc_hits:
            console.print(f"\n[bold red]⚠  {len(ioc_hits)} URLhaus Hit(s):[/bold red]")
            for hit in ioc_hits:
                console.print(f"  [red]•[/red] [{hit['status']}] {hit['url'][:70]} — {hit['threat']}")
            findings["urlhaus_hits"] = ioc_hits
        else:
            console.print("[green]✓  Not found in URLhaus threat feed[/green]")

        # Entropy analysis of target domain itself
        is_susp, reason = _is_dga_candidate(target)
        findings["target_dga"] = {"suspicious": is_susp, "reason": reason}
        if is_susp:
            console.print(f"\n[bold red]⚠  Target domain itself looks DGA-generated: {reason}[/bold red]")
        else:
            ent = _shannon_entropy(target.split(".")[0])
            console.print(f"[dim]Target label entropy: {ent:.3f} (below DGA threshold)[/dim]")

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out = os.path.join(out_dir, f"exfil_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
