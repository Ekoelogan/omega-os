"""SSL/TLS certificate inspection module."""
import ssl
import socket
import datetime
import httpx
from rich.console import Console
from rich.table import Table

console = Console()


def run(target: str):
    """Inspect SSL/TLS certificate for a host."""
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    console.print(f"\n[bold cyan][ SSL CERTIFICATE ] {host}[/bold cyan]\n")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow")
        table.add_column("Value", style="white")

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days
        expiry_color = "green" if days_left > 30 else ("yellow" if days_left > 7 else "red")

        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        table.add_row("Common Name", subject.get("commonName", "N/A"))
        table.add_row("Organization", subject.get("organizationName", "N/A"))
        table.add_row("Issuer CN", issuer.get("commonName", "N/A"))
        table.add_row("Issuer Org", issuer.get("organizationName", "N/A"))
        table.add_row("Valid From", str(not_before.date()))
        table.add_row("Expires", str(not_after.date()))
        table.add_row("Days Left", f"[{expiry_color}]{days_left}[/{expiry_color}]")
        table.add_row("TLS Version", version)
        table.add_row("Cipher Suite", cipher[0] if cipher else "N/A")
        table.add_row("Serial Number", str(cert.get("serialNumber", "N/A")))
        table.add_row("SANs", ", ".join(sans[:10]) if sans else "N/A")

        console.print(table)

    except ssl.SSLCertVerificationError as e:
        console.print(f"[red]SSL Verification Error:[/red] {e}")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
