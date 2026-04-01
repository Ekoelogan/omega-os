"""DNS enumeration module."""
import dns.resolver
import dns.reversename
from rich.console import Console
from rich.table import Table

console = Console()

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]


def run(target: str, record_type: str = "ALL"):
    """Perform DNS lookups on a domain."""
    console.print(f"\n[bold cyan][ DNS ] {target}[/bold cyan]\n")

    types = RECORD_TYPES if record_type.upper() == "ALL" else [record_type.upper()]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in types:
        try:
            answers = resolver.resolve(target, rtype)
            table = Table(title=f"{rtype} Records", show_header=False, box=None, padding=(0, 2))
            table.add_column("Value", style="green")
            for rdata in answers:
                table.add_row(str(rdata))
            console.print(table)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass
