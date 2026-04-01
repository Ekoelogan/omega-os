"""omega spider — Recursive web spider: pages, links, forms, JS endpoints, emails."""
from __future__ import annotations
import asyncio
import re
from collections import defaultdict
from urllib.parse import urljoin, urlparse

try:
    import httpx
    from bs4 import BeautifulSoup
except ImportError:
    httpx = None  # type: ignore
    BeautifulSoup = None  # type: ignore

from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel

console = Console()

EMAIL_RE    = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)
JS_EP_RE    = re.compile(r"""(?:fetch|axios|\.get|\.post|XMLHttpRequest)\s*\(?['"](/[^'"]{2,})['"]""", re.I)
SECRET_RE   = re.compile(
    r"""(?:api[_-]?key|token|secret|password|passwd|auth)\s*[=:]\s*['"]([^'"]{6,})""",
    re.I,
)


class Spider:
    def __init__(self, base: str, max_pages: int = 50, concurrency: int = 8,
                 depth: int = 3):
        self.base        = base.rstrip("/")
        self.origin      = urlparse(base).netloc
        self.max_pages   = max_pages
        self.concurrency = concurrency
        self.depth       = depth
        self.visited:    set[str]           = set()
        self.queue:      list[tuple[str,int]] = [(base, 0)]
        self.pages:      list[dict]         = []
        self.emails:     set[str]           = set()
        self.js_endpoints: set[str]         = set()
        self.forms:      list[dict]         = []
        self.secrets:    list[dict]         = []

    def _same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == self.origin

    async def _fetch(self, client: "httpx.AsyncClient", url: str, depth: int) -> None:
        if url in self.visited or len(self.visited) >= self.max_pages:
            return
        self.visited.add(url)
        try:
            r = await client.get(url, timeout=8, follow_redirects=True)
        except Exception:
            return

        ct = r.headers.get("content-type", "")
        if "html" not in ct and "javascript" not in ct:
            return

        text = r.text
        soup = BeautifulSoup(text, "html.parser") if "html" in ct else None

        links   = []
        page    = {"url": url, "status": r.status_code, "title": "", "links": 0, "forms": 0}

        if soup:
            title_el = soup.find("title")
            page["title"] = title_el.get_text(strip=True)[:60] if title_el else ""
            for a in soup.find_all("a", href=True):
                abs_url = urljoin(url, a["href"]).split("#")[0].split("?")[0]
                if self._same_origin(abs_url) and abs_url not in self.visited:
                    links.append(abs_url)
            page["links"] = len(links)

            # Forms
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", ""))
                method = form.get("method", "GET").upper()
                fields = [i.get("name", "") for i in form.find_all("input") if i.get("name")]
                self.forms.append({"action": action, "method": method, "fields": fields, "page": url})
            page["forms"] = len(soup.find_all("form"))

        # Emails
        for em in EMAIL_RE.findall(text):
            self.emails.add(em.lower())

        # JS endpoints
        for ep in JS_EP_RE.findall(text):
            self.js_endpoints.add(ep)

        # Potential secrets
        for match in SECRET_RE.finditer(text):
            val = match.group(1)
            if len(val) > 8 and not val.startswith("{{"):
                self.secrets.append({"page": url, "key": match.group(0)[:60], "value": val[:20] + "…"})

        self.pages.append(page)

        # Queue child links respecting depth
        if depth < self.depth:
            for lnk in links[:10]:
                if lnk not in self.visited:
                    self.queue.append((lnk, depth + 1))

    async def crawl(self) -> None:
        limits = httpx.Limits(max_connections=self.concurrency)
        headers = {"User-Agent": "Mozilla/5.0 (compatible; omega-spider/0.9.0)"}
        async with httpx.AsyncClient(limits=limits, headers=headers) as client:
            while self.queue and len(self.visited) < self.max_pages:
                batch = []
                while self.queue and len(batch) < self.concurrency:
                    url, depth = self.queue.pop(0)
                    if url not in self.visited:
                        batch.append((url, depth))
                await asyncio.gather(*[self._fetch(client, u, d) for u, d in batch])


def run(target: str, max_pages: int = 50, depth: int = 3, concurrency: int = 8) -> None:
    if not target.startswith("http"):
        target = f"https://{target}"

    console.print(Panel(
        f"[bold #ff2d78]🕷  Web Spider[/bold #ff2d78]  →  [cyan]{target}[/cyan]  "
        f"[dim](max {max_pages} pages, depth {depth})[/dim]",
        expand=False,
    ))

    if not httpx or not BeautifulSoup:
        console.print("[red]Missing deps.[/red] Install: [bold]pipx inject omega-cli httpx beautifulsoup4[/bold]")
        return

    spider = Spider(target, max_pages=max_pages, depth=depth, concurrency=concurrency)

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            raise RuntimeError
        loop.run_until_complete(spider.crawl())
    except RuntimeError:
        asyncio.new_event_loop().run_until_complete(spider.crawl())

    # Pages table
    tbl = Table(title=f"Pages crawled ({len(spider.pages)})", show_lines=True)
    tbl.add_column("URL",    style="cyan",  max_width=55)
    tbl.add_column("Status", justify="right")
    tbl.add_column("Title",  style="dim",   max_width=30)
    tbl.add_column("Links",  justify="right")
    tbl.add_column("Forms",  justify="right")
    for p in spider.pages[:40]:
        color = "green" if p["status"] < 300 else ("#ffaa00" if p["status"] < 400 else "red")
        tbl.add_row(p["url"][-55:], f"[{color}]{p['status']}[/{color}]",
                    p["title"], str(p["links"]), str(p["forms"]))
    console.print(tbl)

    if spider.emails:
        console.print(f"\n[bold]📧 Emails found ({len(spider.emails)}):[/bold]")
        for em in sorted(spider.emails):
            console.print(f"  [cyan]{em}[/cyan]")

    if spider.js_endpoints:
        console.print(f"\n[bold]🔗 JS API Endpoints ({len(spider.js_endpoints)}):[/bold]")
        for ep in sorted(spider.js_endpoints)[:20]:
            console.print(f"  [yellow]{ep}[/yellow]")

    if spider.forms:
        console.print(f"\n[bold]📋 Forms ({len(spider.forms)}):[/bold]")
        for f in spider.forms[:10]:
            console.print(f"  [{f['method']}] {f['action']}  fields: {', '.join(f['fields'][:5])}")

    if spider.secrets:
        console.print(f"\n[bold red]🔑 Potential secrets ({len(spider.secrets)}):[/bold red]")
        for s in spider.secrets[:10]:
            console.print(f"  [red]{s['key']}[/red]  [dim]on {s['page'][-40:]}[/dim]")

    console.print(f"\n[bold]Summary:[/bold] {len(spider.visited)} pages visited, "
                  f"{len(spider.emails)} emails, {len(spider.js_endpoints)} JS endpoints, "
                  f"{len(spider.forms)} forms, {len(spider.secrets)} potential secrets.")
