"""WHOIS lookup module."""
import whois
from rich.console import Console
from rich.table import Table

console = Console()


def run(target: str):
    """Perform WHOIS lookup on a domain or IP."""
    console.print(f"\n[bold cyan][ WHOIS ] {target}[/bold cyan]\n")
    try:
        w = whois.whois(target)
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow")
        table.add_column("Value", style="white")

        fields = {
            "Domain": w.domain_name,
            "Registrar": w.registrar,
            "Created": w.creation_date,
            "Expires": w.expiration_date,
            "Updated": w.updated_date,
            "Name Servers": w.name_servers,
            "Registrant": w.org or w.name,
            "Emails": w.emails,
            "Country": w.country,
            "DNSSEC": w.dnssec,
            "Status": w.status,
        }

        for field, value in fields.items():
            if value:
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value[:5])
                table.add_row(field, str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
