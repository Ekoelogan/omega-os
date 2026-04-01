"""HTTP headers analysis module."""
import httpx
from rich.console import Console
from rich.table import Table

console = Console()

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer policy",
    "Permissions-Policy": "Permissions policy",
    "X-XSS-Protection": "XSS filter (legacy)",
    "Access-Control-Allow-Origin": "CORS policy",
    "Cache-Control": "Cache control",
    "Set-Cookie": "Cookie flags",
}

LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via", "X-Backend-Server",
]


def run(target: str):
    """Fetch and analyze HTTP response headers."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    console.print(f"\n[bold cyan][ HTTP HEADERS ] {target}[/bold cyan]\n")

    try:
        with httpx.Client(follow_redirects=True, timeout=10,
                          headers={"User-Agent": "Mozilla/5.0 (omega-cli)"}) as client:
            r = client.get(target)

        # General info
        info = Table(title="Response Info", show_header=False, box=None, padding=(0, 2))
        info.add_column("Field", style="bold yellow")
        info.add_column("Value", style="white")
        info.add_row("URL", str(r.url))
        info.add_row("Status", f"{r.status_code}")
        info.add_row("HTTP Version", str(r.http_version))
        console.print(info)
        console.print()

        # All headers
        all_h = Table(title="All Headers", show_header=True, box=None, padding=(0, 2))
        all_h.add_column("Header", style="cyan")
        all_h.add_column("Value", style="white")
        for k, v in r.headers.items():
            all_h.add_row(k, v[:120])
        console.print(all_h)
        console.print()

        # Security header audit
        sec = Table(title="Security Header Audit", show_header=True)
        sec.add_column("Header", style="cyan")
        sec.add_column("Purpose", style="yellow")
        sec.add_column("Present", style="white")
        for header, purpose in SECURITY_HEADERS.items():
            present = header.lower() in [h.lower() for h in r.headers]
            icon = "[green]✓ Yes[/green]" if present else "[red]✗ Missing[/red]"
            sec.add_row(header, purpose, icon)
        console.print(sec)
        console.print()

        # Info leak check
        leaks = [(h, r.headers.get(h)) for h in LEAKY_HEADERS if r.headers.get(h)]
        if leaks:
            leak_t = Table(title="[red]⚠ Potential Info Leaks[/red]", show_header=False, box=None, padding=(0, 2))
            leak_t.add_column("Header", style="bold red")
            leak_t.add_column("Value", style="white")
            for h, v in leaks:
                leak_t.add_row(h, v)
            console.print(leak_t)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
