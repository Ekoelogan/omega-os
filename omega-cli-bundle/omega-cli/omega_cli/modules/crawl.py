"""robots.txt and sitemap.xml content discovery."""
import httpx
import re
from xml.etree import ElementTree
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from collections import Counter

console = Console()

SENSITIVE_PATHS = [
    "admin", "login", "signin", "dashboard", "panel", "console",
    "api", "graphql", "swagger", "openapi", "docs", "debug",
    "backup", "old", "test", "staging", "dev", "internal",
    "config", "setup", "install", "update", "cron", ".env",
    "phpmyadmin", "wp-admin", "xmlrpc", "cpanel", "webmail",
]


def _fetch(client: httpx.Client, url: str) -> str | None:
    try:
        r = client.get(url, timeout=8)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


def run(target: str):
    """Parse robots.txt and sitemap.xml for content discovery."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

    console.print(f"\n[bold cyan][ ROBOTS / SITEMAP ] {base}[/bold cyan]\n")

    with httpx.Client(follow_redirects=True, timeout=8,
                      headers={"User-Agent": "Mozilla/5.0 (omega-cli)"}) as client:

        # ── robots.txt ────────────────────────────────────────────────
        robots = _fetch(client, f"{base}/robots.txt")
        if robots:
            disallowed, allowed, sitemaps_found = [], [], []
            for line in robots.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                elif low.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        allowed.append(path)
                elif low.startswith("sitemap:"):
                    sitemaps_found.append(line.split(":", 1)[1].strip())

            console.print(f"[bold]robots.txt[/bold] — {len(disallowed)} disallowed, {len(allowed)} allowed")

            sensitive = [p for p in disallowed if any(s in p.lower() for s in SENSITIVE_PATHS)]
            if sensitive:
                st = Table(title="[red]⚠ Sensitive Disallowed Paths[/red]", show_header=False,
                           box=None, padding=(0, 2))
                st.add_column("Path", style="red")
                for p in sensitive:
                    st.add_row(p)
                console.print(st)

            if disallowed:
                dt = Table(title=f"All Disallowed ({len(disallowed)})", show_header=False,
                           box=None, padding=(0, 2))
                dt.add_column("Path", style="yellow")
                for p in disallowed[:30]:
                    dt.add_row(p)
                if len(disallowed) > 30:
                    dt.add_row(f"[dim]... {len(disallowed)-30} more[/dim]")
                console.print(dt)
        else:
            console.print("[yellow]No robots.txt found[/yellow]")
            sitemaps_found = []

        console.print()

        # ── sitemap.xml ───────────────────────────────────────────────
        sitemap_urls = list(set(sitemaps_found + [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]))
        all_pages = []

        for sitemap_url in sitemap_urls[:5]:
            content = _fetch(client, sitemap_url)
            if not content:
                continue
            try:
                root = ElementTree.fromstring(content)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                locs = [el.text for el in root.iter() if el.tag.endswith("loc") and el.text]
                all_pages.extend(locs)
                console.print(f"[dim]✓ {sitemap_url} ({len(locs)} URLs)[/dim]")
            except Exception:
                # Try regex fallback
                locs = re.findall(r'<loc>([^<]+)</loc>', content)
                all_pages.extend(locs)

        if all_pages:
            console.print(f"\n[bold]Sitemap:[/bold] {len(all_pages)} total URLs\n")
            # Categorize by path depth and interesting patterns
            extensions = Counter(urlparse(u).path.rsplit(".", 1)[-1].lower()
                                 for u in all_pages if "." in urlparse(u).path)
            if extensions:
                ext_t = Table(title="File Types", show_header=True)
                ext_t.add_column("Extension", style="cyan")
                ext_t.add_column("Count", style="white")
                for ext, count in extensions.most_common(10):
                    ext_t.add_row(f".{ext}", str(count))
                console.print(ext_t)

            interesting = [u for u in all_pages
                           if any(s in u.lower() for s in SENSITIVE_PATHS)]
            if interesting:
                it = Table(title="[yellow]Interesting URLs from Sitemap[/yellow]", show_header=False,
                           box=None, padding=(0, 2))
                it.add_column("URL", style="yellow")
                for u in interesting[:15]:
                    it.add_row(u)
                console.print(it)
        else:
            console.print("[yellow]No sitemap found[/yellow]")
