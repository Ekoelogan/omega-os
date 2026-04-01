"""webcrawl.py — Smart web crawler: forms, JS endpoints, comments, robots/sitemap."""
from __future__ import annotations
import re, json, time, hashlib
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode
from typing import Optional
import urllib.request, urllib.error

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **kw): print(*a)
    console = Console()
    Table = Panel = box = None

BANNER = r"""
██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  OMEGA-CLI v1.7.0 — OSINT & Passive Recon Toolkit
"""

UA = "Mozilla/5.0 (compatible; OmegaCLI/1.7.0; +https://omega-cli.sh)"

_JS_ENDPOINT = re.compile(
    r"""(?:url|href|action|src|fetch|axios\.get|axios\.post|http\.get|http\.post|"path"|'path')\s*[=:(,]\s*["'`](/?(?:api|v\d|graphql|rest|endpoint|query)[^"'`\s]{0,120})["'`]""",
    re.I,
)
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_FORM = re.compile(r"<form[^>]*>(.*?)</form>", re.S | re.I)
_INPUT = re.compile(r"<input[^>]*>", re.I)
_ATTR = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']')
_LINK = re.compile(r'href=["\']([^"\'#?][^"\']*)["\']', re.I)
_JS_FILE = re.compile(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', re.I)
_SECRETS = re.compile(
    r"(?:api[_-]?key|secret|token|password|passwd|auth|bearer|private)[_\s]*[=:]\s*['\"]?([A-Za-z0-9/_\-+]{12,64})['\"]?",
    re.I,
)


def _fetch(url: str, timeout: int = 8) -> Optional[str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ct = r.headers.get("Content-Type", "")
            if "html" in ct or "javascript" in ct or "text" in ct or "json" in ct:
                return r.read(512_000).decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _parse_robots(base: str):
    txt = _fetch(f"{base}/robots.txt")
    paths, sitemaps = [], []
    if txt:
        for line in txt.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                p = line.split(":", 1)[1].strip()
                if p and p != "/":
                    paths.append(p)
            elif line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    return paths, sitemaps


def _parse_sitemap(url: str, limit: int = 50):
    urls = []
    xml = _fetch(url)
    if not xml:
        return urls
    for m in re.finditer(r"<loc>\s*(https?://[^<]+)\s*</loc>", xml):
        urls.append(m.group(1).strip())
        if len(urls) >= limit:
            break
    return urls


def run(target: str, depth: int = 1, max_pages: int = 30,
        show_secrets: bool = True, export: str = ""):
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"🕷  Smart Web Crawler — {target}", style="bold cyan"))

    results = {
        "target": target, "base": base,
        "pages": [], "forms": [], "js_endpoints": [],
        "comments": [], "secrets": [], "js_files": [],
        "robots_paths": [], "sitemap_urls": [],
    }

    # robots + sitemap
    robot_paths, sitemaps = _parse_robots(base)
    results["robots_paths"] = robot_paths
    console.print(f"[cyan]robots.txt[/cyan]: {len(robot_paths)} paths, {len(sitemaps)} sitemaps")
    for sm in sitemaps[:3]:
        su = _parse_sitemap(sm, limit=20)
        results["sitemap_urls"].extend(su)
    if not sitemaps:
        su = _parse_sitemap(f"{base}/sitemap.xml", limit=20)
        results["sitemap_urls"].extend(su)
    console.print(f"[cyan]sitemap[/cyan]: {len(results['sitemap_urls'])} URLs discovered")

    # BFS crawl
    queue = [target] + [urljoin(base, p) for p in robot_paths[:5]] + results["sitemap_urls"][:10]
    seen = set()
    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        url = queue.pop(0)
        if url in seen or not url.startswith(base):
            continue
        seen.add(url)
        html = _fetch(url)
        if not html:
            continue
        pages_crawled += 1
        console.print(f"  [dim]crawled[/dim] {url[:80]}")

        page_info = {"url": url, "links": [], "status": "ok"}

        # links
        for m in _LINK.finditer(html):
            link = urljoin(url, m.group(1))
            if link.startswith(base) and link not in seen:
                queue.append(link)
                page_info["links"].append(link)

        # JS files
        for m in _JS_FILE.finditer(html):
            js_url = urljoin(url, m.group(1))
            if js_url not in results["js_files"]:
                results["js_files"].append(js_url)

        # forms
        for fm in _FORM.finditer(html):
            form_html = fm.group(0)
            action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            inputs = []
            for inp in _INPUT.finditer(form_html):
                attrs = dict(_ATTR.findall(inp.group(0)))
                inputs.append({k: v for k, v in attrs.items() if k in ("name","type","id","placeholder")})
            results["forms"].append({
                "page": url,
                "action": urljoin(url, action.group(1)) if action else url,
                "method": (method.group(1) if method else "GET").upper(),
                "inputs": inputs,
            })

        # HTML comments
        for cm in _HTML_COMMENT.finditer(html):
            c = cm.group(1).strip()
            if len(c) > 10 and not c.startswith("[if"):
                results["comments"].append({"page": url, "comment": c[:200]})

        results["pages"].append(page_info)

    # JS endpoint mining
    all_js_sources = []
    for js_url in results["js_files"][:10]:
        js = _fetch(js_url)
        if js:
            all_js_sources.append((js_url, js))

    # also scan inline scripts
    for page in results["pages"][:5]:
        ph = _fetch(page["url"])
        if ph:
            inline = re.findall(r"<script[^>]*>(.*?)</script>", ph, re.S | re.I)
            for sc in inline:
                all_js_sources.append((page["url"] + "#inline", sc))

    ep_seen = set()
    for src_url, src in all_js_sources:
        for m in _JS_ENDPOINT.finditer(src):
            ep = m.group(1)
            if ep not in ep_seen:
                ep_seen.add(ep)
                results["js_endpoints"].append({"source": src_url, "endpoint": ep})
        if show_secrets:
            for sm in _SECRETS.finditer(src):
                val = sm.group(1)
                if len(set(val)) > 5:
                    results["secrets"].append({"source": src_url, "match": sm.group(0)[:120]})

    # display
    t = Table(title="📄 Pages Crawled", box=box.SIMPLE if box else None)
    t.add_column("URL", style="cyan", no_wrap=False, max_width=80)
    for pg in results["pages"]:
        t.add_row(pg["url"])
    console.print(t)

    if results["forms"]:
        tf = Table(title="📝 Forms Found", box=box.SIMPLE if box else None)
        tf.add_column("Page", style="cyan", max_width=50)
        tf.add_column("Action", style="yellow", max_width=50)
        tf.add_column("Method")
        tf.add_column("Inputs", style="dim")
        for f in results["forms"]:
            names = ", ".join(i.get("name", i.get("id", "?")) for i in f["inputs"])
            tf.add_row(f["page"][:50], f["action"][:50], f["method"], names[:60])
        console.print(tf)

    if results["js_endpoints"]:
        te = Table(title="⚙ JS Endpoints", box=box.SIMPLE if box else None)
        te.add_column("Endpoint", style="green")
        te.add_column("Source", style="dim", max_width=50)
        for ep in results["js_endpoints"][:30]:
            te.add_row(ep["endpoint"], ep["source"][:50])
        console.print(te)

    if results["comments"]:
        console.print(f"\n[yellow]💬 HTML Comments: {len(results['comments'])}[/yellow]")
        for c in results["comments"][:5]:
            console.print(f"  [dim]{c['comment'][:120]}[/dim]")

    if results["secrets"]:
        console.print(f"\n[red bold]🔑 Potential Secrets: {len(results['secrets'])}[/red bold]")
        for s in results["secrets"][:10]:
            console.print(f"  [red]{s['match'][:100]}[/red]")

    console.print(f"\n[bold]Summary:[/bold] {pages_crawled} pages | {len(results['forms'])} forms | "
                  f"{len(results['js_endpoints'])} JS endpoints | {len(results['js_files'])} JS files | "
                  f"{len(results['secrets'])} secrets")

    if export:
        Path(export).write_text(json.dumps(results, indent=2))
        console.print(f"[green]Exported → {export}[/green]")
    else:
        out_dir = Path.home() / ".omega" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w.-]", "_", urlparse(target).netloc or target)
        out = out_dir / f"webcrawl_{safe}.json"
        out.write_text(json.dumps(results, indent=2))
        console.print(f"[dim]Saved → {out}[/dim]")
