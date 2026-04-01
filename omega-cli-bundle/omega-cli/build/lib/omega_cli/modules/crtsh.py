"""Certificate Transparency subdomain discovery via crt.sh."""
import requests
from rich.console import Console
from rich.table import Table

console = Console()


def run(target: str):
    """Passively discover subdomains via Certificate Transparency logs (crt.sh)."""
    console.print(f"\n[bold cyan][ CERT TRANSPARENCY ] {target}[/bold cyan]\n")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{target}&output=json",
            headers={"User-Agent": "omega-cli"},
            timeout=15,
        )
        r.raise_for_status()
        entries = r.json()

        seen = set()
        subdomains = []
        for entry in entries:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(target) and name not in seen:
                    seen.add(name)
                    subdomains.append((name, entry.get("issuer_name", ""), entry.get("not_before", "")))

        subdomains.sort(key=lambda x: x[0])

        if subdomains:
            table = Table(title=f"{len(subdomains)} unique subdomains found", show_header=True)
            table.add_column("Subdomain", style="green")
            table.add_column("Issuer", style="dim")
            table.add_column("First Seen", style="dim")
            for name, issuer, first_seen in subdomains:
                cn = issuer.split("CN=")[-1].split(",")[0] if "CN=" in issuer else issuer[:40]
                table.add_row(name, cn, first_seen[:10] if first_seen else "")
            console.print(table)
        else:
            console.print("[yellow]No results from crt.sh.[/yellow]")

        return [s[0] for s in subdomains]

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        return []
