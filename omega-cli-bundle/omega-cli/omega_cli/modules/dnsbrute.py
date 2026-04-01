"""dnsbrute.py — Active DNS bruteforce: wordlist subdomain enum, wildcard detection, zone transfer."""
from __future__ import annotations
import json, re, socket, concurrent.futures
from pathlib import Path
from typing import Optional

try:
    import dns.resolver, dns.zone, dns.query, dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

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

# Built-in wordlist (~300 common subdomains)
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
    "admin", "portal", "dashboard", "panel", "login", "auth", "sso",
    "api", "api2", "apiv2", "v1", "v2", "v3", "rest", "graphql",
    "dev", "develop", "development", "staging", "stage", "stg", "uat",
    "test", "testing", "qa", "preprod", "pre-prod", "sandbox", "demo",
    "prod", "production", "live", "beta", "alpha",
    "static", "cdn", "assets", "media", "img", "images", "files",
    "upload", "uploads", "download", "downloads", "storage", "s3",
    "shop", "store", "commerce", "checkout", "pay", "payments", "billing",
    "support", "help", "helpdesk", "ticket", "tickets", "status",
    "blog", "news", "forum", "community", "wiki", "docs", "documentation",
    "git", "gitlab", "github", "svn", "repo", "code", "ci", "jenkins",
    "monitor", "monitoring", "metrics", "grafana", "kibana", "elastic",
    "vpn", "remote", "rdp", "ssh", "fw", "firewall", "proxy", "mx",
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "autodiscover", "autoconfig", "exchange", "owa",
    "mobile", "m", "app", "apps", "ios", "android",
    "internal", "intranet", "corp", "corporate",
    "backup", "bak", "old", "legacy", "archive",
    "sql", "db", "database", "mysql", "postgres", "mongo", "redis",
    "secure", "ssl", "tls", "vpn2", "remote2",
    "office", "crm", "erp", "jira", "confluence", "slack",
    "search", "elastic", "solr", "analytics", "tracking",
    "health", "healthz", "ping", "ops",
    "cloud", "aws", "azure", "gcp",
    "k8s", "kubernetes", "docker", "registry",
    "mail2", "smtp2", "relay", "mx1", "mx2",
    "video", "stream", "media2", "rtmp",
    "chat", "im", "xmpp",
    "phpmyadmin", "adminer", "cpanel", "plesk", "whm",
    "webdav", "dav", "caldav", "carddav",
    "metrics", "prometheus", "alertmanager",
    "vault", "secrets", "config", "configs",
    "logstash", "fluentd", "splunk",
    "customer", "clients", "partners", "vendors",
    "hr", "finance", "accounting", "legal",
    "marketing", "sales", "crm2",
    "read", "write", "rw", "ro",
    "uat2", "qa2", "test2", "dev2",
    "node", "worker", "server", "servers",
    "mail3", "email2", "noreply", "no-reply", "bounce",
    "wiki2", "kb", "knowledge",
    "vpn3", "gateway", "gw",
    "printer", "printers", "scan",
    "ntp", "time", "clock",
    "update", "updates", "patch", "patches",
    "error", "errors", "log", "logs",
    "report", "reports", "export",
    "hook", "hooks", "webhook", "webhooks",
    "cron", "jobs", "queue", "worker2",
    "staging2", "stage2",
    "origin", "edge", "cache",
    "a", "b", "c", "d", "e", "f", "g", "h",
    "1", "2", "3", "host", "host2",
    "new", "new2", "old2",
]


def _resolve(fqdn: str, rtype: str = "A", lifetime: float = 3.0) -> list[str]:
    if not HAS_DNS:
        try:
            return [socket.gethostbyname(fqdn)]
        except Exception:
            return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    try:
        answers = resolver.resolve(fqdn, rtype)
        return [str(r) for r in answers]
    except Exception:
        return []


def _check_wildcard(domain: str) -> Optional[str]:
    """Detect wildcard DNS by resolving a random subdomain."""
    import random, string
    random_sub = "".join(random.choices(string.ascii_lowercase, k=12)) + "." + domain
    results = _resolve(random_sub)
    return results[0] if results else None


def _zone_transfer(domain: str) -> list[str]:
    """Attempt DNS zone transfer (AXFR) against all NS servers."""
    if not HAS_DNS:
        return []
    records = []
    ns_records = _resolve(domain, "NS")
    for ns in ns_records[:3]:
        ns = ns.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            for name in z.nodes:
                records.append(f"{name}.{domain}")
        except Exception:
            pass
    return records


def _brute_worker(sub: str, domain: str, wildcard_ip: Optional[str]) -> Optional[dict]:
    fqdn = f"{sub}.{domain}"
    ips = _resolve(fqdn)
    if not ips:
        return None
    # Filter wildcard
    if wildcard_ip and all(ip == wildcard_ip for ip in ips):
        return None
    cnames = _resolve(fqdn, "CNAME")
    return {"subdomain": fqdn, "ips": ips, "cnames": cnames}


def run(domain: str, wordlist_file: str = "", threads: int = 50,
        zone_xfr: bool = True, export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"💥  DNS Bruteforce — {domain}", style="bold cyan"))

    results = {
        "domain": domain,
        "found": [],
        "zone_transfer": [],
        "wildcard": None,
    }

    # Zone transfer attempt
    if zone_xfr:
        console.print("[bold]Zone Transfer (AXFR) attempt...[/bold]")
        zt = _zone_transfer(domain)
        results["zone_transfer"] = zt
        if zt:
            console.print(f"  [red bold]⚠ ZONE TRANSFER SUCCEEDED! {len(zt)} records leaked[/red bold]")
            for r in zt[:10]:
                console.print(f"    [red]{r}[/red]")
        else:
            console.print("  [green]Zone transfer blocked (expected)[/green]")

    # Wildcard check
    console.print("\n[bold]Wildcard DNS check...[/bold]")
    wildcard_ip = _check_wildcard(domain)
    results["wildcard"] = wildcard_ip
    if wildcard_ip:
        console.print(f"  [yellow]⚠ Wildcard detected → {wildcard_ip} (filtering results)[/yellow]")
    else:
        console.print("  [green]No wildcard[/green]")

    # Build wordlist
    if wordlist_file and Path(wordlist_file).exists():
        words = Path(wordlist_file).read_text().splitlines()
        words = [w.strip() for w in words if w.strip()]
        console.print(f"\n[bold]Bruteforcing {len(words)} words from {wordlist_file}...[/bold]")
    else:
        words = BUILTIN_WORDLIST
        console.print(f"\n[bold]Bruteforcing {len(words)} built-in subdomains ({threads} threads)...[/bold]")

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_brute_worker, sub, domain, wildcard_ip): sub for sub in words}
        done_count = 0
        for future in concurrent.futures.as_completed(futures):
            done_count += 1
            result = future.result()
            if result:
                found.append(result)
                console.print(f"  [green]✓[/green] {result['subdomain']:50s} → {', '.join(result['ips'][:3])}")

    results["found"] = found
    console.print(f"\n[bold]Found {len(found)} subdomains[/bold] (from {len(words)} attempts)")

    if found:
        t = Table(title="DNS Bruteforce Results", box=box.SIMPLE if box else None)
        t.add_column("Subdomain", style="green")
        t.add_column("IPs",       style="cyan")
        t.add_column("CNAMEs",    style="dim")
        for r in found:
            t.add_row(r["subdomain"], ", ".join(r["ips"][:3]), ", ".join(r["cnames"][:2]))
        console.print(t)

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", domain)
    out_path = Path(export) if export else out_dir / f"dnsbrute_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
