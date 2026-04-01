"""Full recon sweep — runs all modules against a target (sequential/verbose)."""
from rich.console import Console
from rich.rule import Rule
from . import (whois_lookup, dns_lookup, crtsh, subdomain, ipinfo, headers,
               ssl_check, portscan, dorks, techfp, wayback, crawl, jscan,
               buckets, threatintel, spoofcheck, reverseip, cvemap)

console = Console()


def run(target: str, report: bool = False, output_dir: str = None):
    """Run all OSINT modules sequentially with full verbose output."""
    console.print(f"\n[bold magenta]{'='*60}[/bold magenta]")
    console.print(f"[bold magenta]  OMEGA RECON — {target}[/bold magenta]")
    console.print(f"[bold magenta]{'='*60}[/bold magenta]\n")

    modules = [
        ("WHOIS",               lambda: whois_lookup.run(target)),
        ("DNS",                 lambda: dns_lookup.run(target)),
        ("CERT TRANSPARENCY",   lambda: crtsh.run(target)),
        ("SUBDOMAINS (brute)",  lambda: subdomain.run(target)),
        ("HTTP HEADERS",        lambda: headers.run(target)),
        ("SSL CERTIFICATE",     lambda: ssl_check.run(target)),
        ("TECH FINGERPRINT",    lambda: techfp.run(target)),
        ("CVE MAP",             lambda: cvemap.run(tech_detections=techfp.run(target))),
        ("PORT SCAN",           lambda: portscan.run(target)),
        ("EMAIL SPOOF AUDIT",   lambda: spoofcheck.run(target)),
        ("REVERSE IP",          lambda: reverseip.run(target)),
        ("WAYBACK MACHINE",     lambda: wayback.run(target)),
        ("ROBOTS / SITEMAP",    lambda: crawl.run(target)),
        ("JS ANALYZER",         lambda: jscan.run(target)),
        ("CLOUD BUCKETS",       lambda: buckets.run(target)),
        ("THREAT INTEL",        lambda: threatintel.run(target)),
        ("GOOGLE DORKS",        lambda: dorks.run(target)),
    ]

    for name, fn in modules:
        console.print(Rule(f"[bold cyan]{name}[/bold cyan]"))
        try:
            fn()
        except Exception as e:
            console.print(f"[red]Module error:[/red] {e}")
        console.print()

    console.print(Rule("[bold magenta]RECON COMPLETE[/bold magenta]"))

    if report:
        from omega_cli import reporter
        console.print("\n[bold]Generating report...[/bold]")
        try:
            html_path, json_path = reporter.generate(target, {}, output_dir=output_dir)
            console.print(f"[green]HTML:[/green] {html_path}")
            console.print(f"[green]JSON:[/green] {json_path}")
        except Exception as e:
            console.print(f"[red]Report error:[/red] {e}")
