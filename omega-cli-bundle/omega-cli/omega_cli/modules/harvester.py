"""Email harvester — scrapes emails from web pages, crt.sh, and GitHub."""
import re
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
BLACKLIST = {"example.com", "test.com", "sentry.io", "user@", "email@", "noreply@"}


def _clean(emails: set, domain: str) -> list:
    results = []
    for e in emails:
        e = e.lower().strip(".,;\"'")
        if any(b in e for b in BLACKLIST):
            continue
        if len(e) > 6 and "@" in e:
            results.append(e)
    return sorted(set(results))


def _scrape_url(url: str) -> set:
    emails = set()
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        text = r.text
        emails.update(EMAIL_RE.findall(text))
    except Exception:
        pass
    return emails


def _scrape_web(domain: str) -> set:
    emails = set()
    pages = [
        f"https://{domain}",
        f"https://{domain}/contact",
        f"https://{domain}/about",
        f"https://{domain}/team",
        f"https://www.{domain}",
        f"https://www.{domain}/contact",
    ]
    for url in pages:
        emails.update(_scrape_url(url))
    return emails


def _scrape_crtsh(domain: str) -> set:
    """Extract emails from crt.sh certificate entries."""
    emails = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q={domain}&output=json", timeout=10
        )
        if r.status_code == 200:
            text = r.text
            emails.update(EMAIL_RE.findall(text))
    except Exception:
        pass
    return emails


def _scrape_github(domain: str, token: str = "") -> set:
    """Search GitHub code for email addresses matching the domain."""
    emails = set()
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        r = requests.get(
            "https://api.github.com/search/code",
            params={"q": f"{domain} in:file", "per_page": 30},
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            for item in r.json().get("items", []):
                raw_url = item.get("html_url", "").replace(
                    "github.com", "raw.githubusercontent.com"
                ).replace("/blob/", "/")
                emails.update(_scrape_url(raw_url))
    except Exception:
        pass
    return emails


def _scrape_bing(domain: str) -> set:
    """Use Bing to find email addresses for a domain."""
    emails = set()
    try:
        query = f'"%40{domain}" OR "@{domain}"'
        r = requests.get(
            "https://www.bing.com/search",
            params={"q": query, "count": 50},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
        )
        emails.update(EMAIL_RE.findall(r.text))
    except Exception:
        pass
    return emails


def run(domain: str, github_token: str = "", deep: bool = False):
    """Harvest email addresses for a domain from multiple sources."""
    console.print(Panel(
        f"[bold #ff2d78]📧 Email Harvester[/]\n[dim]Domain:[/] [cyan]{domain}[/]",
        border_style="#ff85b3",
    ))

    all_emails: set = set()
    sources = {}

    console.print("[dim]  Scraping web pages...[/]")
    found = _scrape_web(domain)
    sources["web"] = len(found)
    all_emails.update(found)

    console.print("[dim]  Querying crt.sh...[/]")
    found = _scrape_crtsh(domain)
    sources["crtsh"] = len(found)
    all_emails.update(found)

    if deep:
        console.print("[dim]  Searching Bing...[/]")
        found = _scrape_bing(domain)
        sources["bing"] = len(found)
        all_emails.update(found)

        console.print("[dim]  Searching GitHub...[/]")
        found = _scrape_github(domain, github_token)
        sources["github"] = len(found)
        all_emails.update(found)

    # Filter to only emails matching the target domain (+ all found)
    target_emails = [e for e in all_emails if domain in e]
    other_emails = [e for e in all_emails if domain not in e]

    cleaned = _clean(set(target_emails), domain)
    other_cleaned = _clean(set(other_emails), domain)

    if not cleaned and not other_cleaned:
        console.print("[yellow]No email addresses found.[/]")
        return {"domain": domain, "emails": [], "sources": sources}

    if cleaned:
        tbl = Table(
            title=f"Target Domain Emails ({len(cleaned)})",
            box=box.ROUNDED, border_style="#ff85b3",
        )
        tbl.add_column("#", style="dim", width=4)
        tbl.add_column("Email", style="cyan")
        tbl.add_column("Domain", style="dim")
        for i, e in enumerate(cleaned, 1):
            parts = e.split("@")
            tbl.add_row(str(i), e, parts[1] if len(parts) == 2 else "")
        console.print(tbl)

    if other_cleaned:
        tbl2 = Table(
            title=f"Other Emails Found ({len(other_cleaned)})",
            box=box.SIMPLE, border_style="dim",
        )
        tbl2.add_column("Email", style="dim")
        for e in other_cleaned[:20]:
            tbl2.add_row(e)
        console.print(tbl2)

    console.print(f"\n[bold]Sources:[/] " + "  ".join(f"[cyan]{k}[/]:[yellow]{v}[/]" for k, v in sources.items()))
    return {"domain": domain, "emails": cleaned, "other": other_cleaned, "sources": sources}
