"""Google dorking / search OSINT module."""
import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()

DORK_TEMPLATES = {
    "login_pages":     'site:{target} inurl:login OR inurl:signin OR inurl:admin',
    "exposed_files":   'site:{target} ext:pdf OR ext:xlsx OR ext:docx OR ext:txt',
    "config_files":    'site:{target} ext:env OR ext:config OR ext:xml OR ext:json',
    "subdomains":      'site:*.{target}',
    "emails":          'site:{target} "@{target}"',
    "error_pages":     'site:{target} "error" OR "exception" OR "stack trace"',
    "open_dirs":       'site:{target} intitle:"index of"',
    "github_mentions": 'site:github.com "{target}"',
    "pastebin":        'site:pastebin.com "{target}"',
    "linkedin":        'site:linkedin.com "{target}"',
}


def run(target: str, dork: str = "all"):
    """Generate and display Google dork queries for a target."""
    console.print(f"\n[bold cyan][ GOOGLE DORKS ] {target}[/bold cyan]\n")
    console.print("[dim]These queries can be pasted directly into Google.[/dim]\n")

    templates = DORK_TEMPLATES if dork == "all" else {dork: DORK_TEMPLATES.get(dork, dork)}

    table = Table(show_header=True)
    table.add_column("Category", style="bold yellow")
    table.add_column("Dork Query", style="cyan")
    table.add_column("Google Link", style="blue")

    for name, template in templates.items():
        query = template.replace("{target}", target)
        encoded = query.replace(" ", "+")
        link = f"https://www.google.com/search?q={encoded}"
        table.add_row(name, query, link)

    console.print(table)
