"""Wayback Machine recon — find archived URLs and exposed endpoints."""
import requests
from urllib.parse import urlparse, parse_qs
from rich.console import Console
from rich.table import Table
from collections import defaultdict

console = Console()

INTERESTING_EXTENSIONS = {
    "config": [".env", ".config", ".cfg", ".ini", ".xml", ".yaml", ".yml", ".toml"],
    "data":   [".json", ".csv", ".sql", ".db", ".bak", ".backup", ".dump"],
    "docs":   [".pdf", ".xlsx", ".docx", ".pptx", ".txt"],
    "code":   [".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".sh"],
    "admin":  ["admin", "login", "signin", "dashboard", "panel", "console", "manage"],
}


def run(target: str, limit: int = 500):
    """Query the Wayback Machine CDX API for archived URLs."""
    console.print(f"\n[bold cyan][ WAYBACK MACHINE ] {target}[/bold cyan]\n")

    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{target}/*",
                "output": "json",
                "fl": "original,statuscode,timestamp,mimetype",
                "collapse": "urlkey",
                "limit": limit,
                "filter": "statuscode:200",
            },
            headers={"User-Agent": "omega-cli"},
            timeout=20,
        )
        r.raise_for_status()
        rows = r.json()

        if not rows or len(rows) <= 1:
            console.print("[yellow]No archived URLs found.[/yellow]")
            return

        rows = rows[1:]  # skip header row

        # Categorize findings
        findings = defaultdict(list)
        params_with_values = []
        all_urls = []

        for url, status, ts, mime in rows:
            all_urls.append(url)
            parsed = urlparse(url)
            path = parsed.path.lower()
            qs = parse_qs(parsed.query)

            # check interesting extensions / keywords
            for category, patterns in INTERESTING_EXTENSIONS.items():
                if any(p in path for p in patterns):
                    findings[category].append(url)
                    break

            # URLs with query parameters (potential injection points)
            if qs:
                params_with_values.append((url, list(qs.keys())))

        # Summary table
        summary = Table(title="Wayback Summary", show_header=False, box=None, padding=(0, 2))
        summary.add_column("Metric", style="bold yellow")
        summary.add_column("Value", style="white")
        summary.add_row("Total archived URLs", str(len(all_urls)))
        summary.add_row("URLs with parameters", str(len(params_with_values)))
        for cat, items in findings.items():
            summary.add_row(f"  {cat.title()} files/paths", f"[red]{len(items)}[/red]" if items else "0")
        console.print(summary)
        console.print()

        # Interesting findings
        for category, urls in findings.items():
            if urls:
                t = Table(title=f"[red]⚠ {category.title()} Exposures[/red]", show_header=False,
                          box=None, padding=(0, 1))
                t.add_column("URL", style="cyan")
                for u in urls[:15]:
                    t.add_row(u)
                if len(urls) > 15:
                    t.add_row(f"[dim]... and {len(urls)-15} more[/dim]")
                console.print(t)
                console.print()

        # URLs with parameters
        if params_with_values:
            pt = Table(title="URLs with Parameters (potential attack surface)",
                       show_header=True)
            pt.add_column("URL", style="cyan", max_width=80)
            pt.add_column("Params", style="yellow")
            for u, params in params_with_values[:20]:
                pt.add_row(u, ", ".join(params))
            if len(params_with_values) > 20:
                pt.add_row(f"[dim]... and {len(params_with_values)-20} more[/dim]", "")
            console.print(pt)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
