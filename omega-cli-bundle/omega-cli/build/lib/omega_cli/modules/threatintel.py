"""Threat intelligence checks — AbuseIPDB, URLhaus, VirusTotal (public)."""
import requests
import os
from rich.console import Console
from rich.table import Table

console = Console()


def _check_urlhaus(target: str) -> dict:
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": target},
            timeout=8,
        )
        return r.json()
    except Exception:
        return {}


def _check_abuseipdb(ip: str) -> dict:
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"error": "No ABUSEIPDB_API_KEY set"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=8,
        )
        return r.json().get("data", {})
    except Exception as e:
        return {"error": str(e)}


def _resolve_to_ip(target: str) -> str:
    import dns.resolver
    try:
        answers = dns.resolver.resolve(target, "A", lifetime=3)
        return str(answers[0])
    except Exception:
        return target


def run(target: str):
    """Check target against threat intelligence feeds."""
    console.print(f"\n[bold cyan][ THREAT INTEL ] {target}[/bold cyan]\n")

    ip = _resolve_to_ip(target) if not target.replace(".", "").isdigit() else target

    # URLhaus check (no API key needed)
    console.print("[bold]URLhaus (malware URL database):[/bold]")
    uh = _check_urlhaus(target)
    uh_table = Table(show_header=False, box=None, padding=(0, 2))
    uh_table.add_column("Field", style="bold yellow")
    uh_table.add_column("Value", style="white")

    uh_status = uh.get("query_status", "unknown")
    if uh_status == "no_results":
        uh_table.add_row("Status", "[green]Clean — not in URLhaus[/green]")
    elif uh_status == "is_host":
        uh_table.add_row("Status", "[red]⚠ FOUND in URLhaus[/red]")
        uh_table.add_row("URLs Count", str(len(uh.get("urls", []))))
        for u in uh.get("urls", [])[:5]:
            uh_table.add_row("  Malware URL", u.get("url", ""))
            uh_table.add_row("  Tags", ", ".join(u.get("tags") or []))
    else:
        uh_table.add_row("Status", str(uh_status))
    console.print(uh_table)
    console.print()

    # AbuseIPDB check
    console.print(f"[bold]AbuseIPDB check for {ip}:[/bold]")
    ab = _check_abuseipdb(ip)
    ab_table = Table(show_header=False, box=None, padding=(0, 2))
    ab_table.add_column("Field", style="bold yellow")
    ab_table.add_column("Value", style="white")

    if "error" in ab:
        ab_table.add_row("Status", f"[yellow]{ab['error']}[/yellow]")
        ab_table.add_row("Tip", "Set ABUSEIPDB_API_KEY env var for full threat data")
    else:
        score = ab.get("abuseConfidenceScore", 0)
        score_color = "red" if score > 50 else ("yellow" if score > 10 else "green")
        ab_table.add_row("Abuse Score", f"[{score_color}]{score}%[/{score_color}]")
        ab_table.add_row("Total Reports", str(ab.get("totalReports", 0)))
        ab_table.add_row("Last Reported", ab.get("lastReportedAt", "Never") or "Never")
        ab_table.add_row("Country", ab.get("countryCode", "N/A"))
        ab_table.add_row("ISP", ab.get("isp", "N/A"))
        ab_table.add_row("Domain", ab.get("domain", "N/A"))
        ab_table.add_row("Tor Exit Node", str(ab.get("isTor", False)))
    console.print(ab_table)
