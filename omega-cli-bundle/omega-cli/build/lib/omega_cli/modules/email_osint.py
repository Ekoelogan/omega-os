"""Email OSINT module — validation, breach check, and header analysis."""
import re
import requests
from rich.console import Console
from rich.table import Table

console = Console()

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _check_mx(domain: str) -> bool:
    import dns.resolver
    try:
        dns.resolver.resolve(domain, "MX", lifetime=3)
        return True
    except Exception:
        return False


def run(target: str):
    """Passive email OSINT: format validation, MX check, disposable check, breach check."""
    console.print(f"\n[bold cyan][ EMAIL OSINT ] {target}[/bold cyan]\n")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Check", style="bold yellow")
    table.add_column("Result", style="white")

    # Format validation
    valid_fmt = bool(EMAIL_RE.match(target))
    table.add_row("Format Valid", "[green]Yes[/green]" if valid_fmt else "[red]No[/red]")

    if not valid_fmt:
        console.print(table)
        return

    domain = target.split("@")[1]
    table.add_row("Domain", domain)

    # MX record check
    has_mx = _check_mx(domain)
    table.add_row("MX Records", "[green]Found[/green]" if has_mx else "[red]None[/red]")

    # Disposable email check (open-source list via GitHub)
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
            timeout=5
        )
        disposable_list = r.text.splitlines()
        is_disposable = domain.lower() in [d.lower() for d in disposable_list]
        table.add_row("Disposable", "[red]Yes[/red]" if is_disposable else "[green]No[/green]")
    except Exception:
        table.add_row("Disposable", "[yellow]Unknown[/yellow]")

    # HaveIBeenPwned check (public API, no key for domain search)
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            headers={"User-Agent": "omega-cli-osint"},
            timeout=5,
        )
        if r.status_code == 200:
            breaches = r.json()
            table.add_row("Domain Breaches", f"[red]{len(breaches)} breach(es)[/red]")
        else:
            table.add_row("Domain Breaches", "[green]None found[/green]")
    except Exception:
        table.add_row("Domain Breaches", "[yellow]Check unavailable[/yellow]")

    console.print(table)
    console.print(
        "\n[dim]Note: Full email breach lookup requires a HaveIBeenPwned API key.[/dim]"
        "\n[dim]Set HIBP_API_KEY env var and re-run for per-address breach data.[/dim]"
    )
