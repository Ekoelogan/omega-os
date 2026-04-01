"""Reverse IP lookup — find domains co-hosted on the same IP."""
import requests
import dns.resolver
from rich.console import Console
from rich.table import Table

console = Console()


def _resolve_ip(target: str) -> str:
    if all(c.isdigit() or c == "." for c in target):
        return target
    try:
        answers = dns.resolver.resolve(target, "A", lifetime=3)
        return str(answers[0])
    except Exception:
        return target


def run(target: str):
    """Find other domains hosted on the same IP via HackerTarget API."""
    console.print(f"\n[bold cyan][ REVERSE IP ] {target}[/bold cyan]\n")

    ip = _resolve_ip(target)
    if ip != target:
        console.print(f"[dim]Resolved {target} → {ip}[/dim]\n")

    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            headers={"User-Agent": "omega-cli"},
            timeout=10,
        )
        lines = [l.strip() for l in r.text.splitlines() if l.strip()]

        if not lines or "error" in lines[0].lower() or "API count exceeded" in r.text:
            console.print(f"[yellow]{r.text.strip()}[/yellow]")
            return []

        table = Table(title=f"{len(lines)} domain(s) on {ip}", show_header=False, box=None, padding=(0, 2))
        table.add_column("Domain", style="green")
        for domain in lines:
            table.add_row(domain)
        console.print(table)

        if len(lines) > 100:
            console.print(f"\n[yellow]⚠ Shared hosting detected ({len(lines)} domains — likely a CDN or bulk host)[/yellow]")

        return lines

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        return []
