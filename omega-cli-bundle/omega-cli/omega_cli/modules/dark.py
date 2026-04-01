"""omega dark — Dark web / Tor onion recon via Ahmia and onion probing."""
from __future__ import annotations
import re
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

AHMIA_URL = "https://ahmia.fi/search/"
ONION_RE  = re.compile(r"[a-z2-7]{16,56}\.onion", re.I)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; omega-cli/0.8.0)"
}


def _ahmia_search(query: str, limit: int = 20) -> list[dict]:
    results = []
    try:
        resp = requests.get(
            AHMIA_URL,
            params={"q": query},
            headers=HEADERS,
            timeout=15,
        )
        resp.raise_for_status()
        # Parse plain text results — Ahmia returns HTML
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        for li in soup.select("li.result")[:limit]:
            title_el = li.select_one("h4")
            link_el  = li.select_one("p.onion-site a") or li.select_one("a")
            desc_el  = li.select_one("p.description")
            results.append({
                "title":       title_el.get_text(strip=True) if title_el else "—",
                "url":         link_el["href"] if link_el and link_el.get("href") else "—",
                "description": desc_el.get_text(strip=True)[:80] if desc_el else "—",
            })
    except Exception as exc:
        console.print(f"[yellow]Ahmia error:[/yellow] {exc}")
    return results


def _extract_onions(text: str) -> list[str]:
    return list(dict.fromkeys(ONION_RE.findall(text)))


def run(query: str, limit: int = 20, extract_only: bool = False) -> None:
    console.print(Panel(f"[bold #ff2d78]🌑  Dark Web Recon[/bold #ff2d78]  →  [cyan]{query}[/cyan]",
                        expand=False))

    if extract_only:
        onions = _extract_onions(query)
        if not onions:
            console.print("[yellow]No .onion addresses found in input.[/yellow]")
            return
        console.print(f"[bold]Extracted {len(onions)} .onion addresses:[/bold]")
        for o in onions:
            console.print(f"  [cyan]{o}[/cyan]")
        return

    console.print(f"[dim]Searching Ahmia.fi for:[/dim] [bold]{query}[/bold] …")
    results = _ahmia_search(query, limit=limit)

    if not results:
        console.print("[yellow]No results found (Ahmia may be unreachable without Tor).[/yellow]")
        console.print("[dim]Tip: run [bold]omega proxy tor[/bold] first to route through Tor.[/dim]")
        return

    tbl = Table(title=f"Ahmia results for '{query}'", show_lines=True, expand=True)
    tbl.add_column("Title",       style="bold white", max_width=30)
    tbl.add_column("Onion URL",   style="cyan",       max_width=50)
    tbl.add_column("Description", style="dim",        max_width=50)

    for r in results:
        tbl.add_row(r["title"], r["url"], r["description"])

    console.print(tbl)
    console.print(f"\n[dim]Found {len(results)} results.[/dim]")
    console.print("[dim]Tip: use [bold]omega proxy tor[/bold] to browse discovered .onion links anonymously.[/dim]")
