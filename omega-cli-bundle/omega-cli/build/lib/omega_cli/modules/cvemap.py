"""CVE mapper — map detected technologies to known vulnerabilities."""
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Known high-impact CVEs mapped to tech keywords for offline lookup
# Format: (tech_keyword, CVE_ID, CVSS, description, affected_versions)
OFFLINE_CVE_DB = [
    # WordPress
    ("wordpress", "CVE-2023-2745", 8.1, "WP Core path traversal", "< 6.2.1"),
    ("wordpress", "CVE-2022-21663", 6.6, "WP Core SQL injection via WPDB", "< 5.8.3"),
    ("wordpress", "CVE-2021-44223", 9.8, "WP Core nav block XSS/RCE chain", "< 5.8"),
    # Drupal
    ("drupal", "CVE-2022-25271", 9.8, "Drupal core RCE (Drupalgeddon4)", "< 9.3.12"),
    ("drupal", "CVE-2018-7600", 9.8, "Drupalgeddon2 — RCE without auth", "< 7.58 / 8.x < 8.3.9"),
    # Joomla
    ("joomla", "CVE-2023-23752", 5.3, "Joomla unauthorized API access", "4.0.0 - 4.2.7"),
    ("joomla", "CVE-2015-8562", 9.8, "Joomla PHP object injection RCE", "< 3.4.6"),
    # PHP
    ("php", "CVE-2023-3823", 8.6, "PHP XML external entity injection", "< 8.0.30"),
    ("php", "CVE-2022-31625", 9.8, "PHP Postgres use-after-free RCE", "< 8.1.8"),
    ("php", "CVE-2021-21705", 5.3, "PHP FILTER_VALIDATE_URL SSRF", "< 7.3.29"),
    # Apache
    ("apache", "CVE-2021-41773", 9.8, "Apache path traversal/RCE (2.4.49)", "2.4.49"),
    ("apache", "CVE-2021-42013", 9.8, "Apache path traversal/RCE (2.4.50)", "2.4.50"),
    ("apache", "CVE-2022-22721", 9.8, "Apache HTTP Request Smuggling", "< 2.4.52"),
    # nginx
    ("nginx", "CVE-2021-23017", 9.4, "nginx DNS resolver off-by-one RCE", "< 1.20.1"),
    ("nginx", "CVE-2019-20372", 5.3, "nginx HTTP request smuggling", "< 1.17.7"),
    # IIS
    ("iis", "CVE-2022-21907", 9.8, "IIS RCE via HTTP protocol stack", "Windows Server"),
    ("iis", "CVE-2021-31166", 9.8, "IIS HTTP protocol stack RCE", "Windows 10/Server"),
    # jQuery
    ("jquery", "CVE-2020-11023", 6.9, "jQuery XSS via HTML manipulation", "< 3.5.0"),
    ("jquery", "CVE-2020-11022", 6.9, "jQuery XSS via HTML manipulation", "< 3.5.0"),
    ("jquery", "CVE-2019-11358", 6.1, "jQuery prototype pollution", "< 3.4.0"),
    # React
    ("react", "CVE-2018-6341", 6.1, "React XSS via SSR attribute injection", "< 16.0.0"),
    # Next.js
    ("next.js", "CVE-2024-34351", 7.5, "Next.js SSRF via Host header", "< 14.1.1"),
    ("next.js", "CVE-2025-29927", 9.1, "Next.js middleware auth bypass", "< 15.2.3"),
    # ASP.NET
    ("asp.net", "CVE-2023-29470", 9.8, "ASP.NET deserialization RCE", "Multiple"),
    ("asp.net", "CVE-2021-31166", 9.8, "HTTP.sys RCE in IIS/ASP.NET", "Windows"),
    # Shopify (third-party themes)
    ("shopify", "CVE-2022-1901", 5.3, "Shopify subdomain takeover risk", "N/A"),
    # Redis (exposed port)
    ("redis", "CVE-2022-0543", 10.0, "Redis Lua sandbox escape RCE", "Debian packages"),
    ("redis", "CVE-2023-28425", 5.5, "Redis SINTERCARD integer overflow", "< 7.0.10"),
    # Elasticsearch
    ("elasticsearch", "CVE-2023-31419", 7.5, "Elasticsearch StackOverflow DoS", "< 8.9.0"),
    ("elasticsearch", "CVE-2021-22144", 6.5, "Elasticsearch Arbitrary File Read", "< 7.13.3"),
    # MongoDB
    ("mongodb", "CVE-2021-32039", 6.5, "MongoDB server-side request forgery", "< 5.0.3"),
    # Varnish
    ("varnish", "CVE-2022-45060", 7.5, "Varnish HTTP/1 request smuggling", "< 7.3.0"),
    # Log4j (detected via Java headers/X-Powered-By)
    ("java", "CVE-2021-44228", 10.0, "Log4Shell — Log4j RCE (CRITICAL)", "log4j < 2.15.0"),
]


def run(tech_detections: dict = None, target: str = None):
    """Map detected technologies to known CVEs."""
    if target and not tech_detections:
        from omega_cli.modules import techfp
        tech_detections = techfp.run(target)

    if not tech_detections:
        console.print("[yellow]No technology detections to map.[/yellow]")
        return []

    console.print(f"\n[bold cyan][ CVE MAPPER ][/bold cyan]\n")

    detected_names = set()
    for cat, techs in tech_detections.items() if isinstance(tech_detections, dict) else []:
        if isinstance(techs, list):
            for t in techs:
                detected_names.add(t.lower())
        elif isinstance(techs, str):
            detected_names.add(techs.lower())

    matches = []
    for keyword, cve, cvss, desc, affected in OFFLINE_CVE_DB:
        if any(keyword in name for name in detected_names):
            matches.append((keyword, cve, cvss, desc, affected))

    if matches:
        matches.sort(key=lambda x: x[2], reverse=True)
        table = Table(title=f"Potential CVEs ({len(matches)} matches)", show_header=True)
        table.add_column("Tech",     style="yellow")
        table.add_column("CVE",      style="bold cyan")
        table.add_column("CVSS",     style="white")
        table.add_column("Description", style="white", max_width=50)
        table.add_column("Affected",    style="dim",   max_width=25)

        for keyword, cve, cvss, desc, affected in matches:
            score_color = "bold red" if cvss >= 9.0 else ("red" if cvss >= 7.0 else ("yellow" if cvss >= 4.0 else "green"))
            table.add_row(
                keyword.title(), cve,
                f"[{score_color}]{cvss}[/{score_color}]",
                desc, affected
            )
        console.print(table)
        console.print(
            "\n[dim]Note: Match is based on technology name only. "
            "Verify version before assuming exploitability.[/dim]"
        )

        critical = [m for m in matches if m[2] >= 9.0]
        if critical:
            console.print(Panel(
                f"[bold red]⚠  {len(critical)} CRITICAL severity CVE(s) matched![/bold red]\n"
                + "\n".join(f"  • {m[1]} — {m[3]}" for m in critical),
                border_style="red"
            ))
    else:
        console.print("[green]✓ No known CVEs matched for detected technologies[/green]")

    return matches
