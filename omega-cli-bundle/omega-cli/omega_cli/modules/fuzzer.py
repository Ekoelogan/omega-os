"""Smart directory/file fuzzer — uses target-specific and built-in wordlists."""
import asyncio
import aiohttp
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
from rich.live import Live
from rich import box

console = Console()

# Built-in common paths
COMMON_PATHS = [
    # Admin / config
    "admin", "administrator", "admin/", "wp-admin", "panel", "dashboard",
    "login", "signin", "auth", "manage", "management", "control",
    # Config / info
    ".env", ".git/config", ".git/HEAD", "config.php", "config.js",
    "config.yaml", "config.yml", "config.json", "settings.py",
    "wp-config.php", "configuration.php", ".htaccess", "web.config",
    # Backup
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "dump.sql", "site.tar.gz", "www.zip", "old", "bak",
    # API
    "api", "api/v1", "api/v2", "api/v3", "graphql", "rest",
    "swagger", "swagger.json", "openapi.json", "api-docs",
    # Sensitive files
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "phpinfo.php", "info.php", "test.php", "shell.php",
    ".DS_Store", "Thumbs.db", "package.json", "composer.json",
    # Directories
    "uploads", "upload", "files", "static", "assets", "media",
    "images", "img", "css", "js", "vendor", "node_modules",
    "includes", "inc", "lib", "libs", "src",
    # Monitoring / status
    "status", "health", "ping", "metrics", "monitor",
    "actuator", "actuator/health", "actuator/env",
    "debug", "trace", ".well-known/security.txt",
    # CMS
    "wp-json", "xmlrpc.php", "wp-login.php", "wp-content",
    "joomla", "drupal", "typo3", "magento",
    # Git / CI
    ".gitlab-ci.yml", ".travis.yml", "Jenkinsfile", "Makefile",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
]

EXTENSIONS = ["", ".php", ".html", ".txt", ".bak", ".old", ".zip", ".tar.gz", ".json"]


async def _probe(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore) -> dict:
    async with sem:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=6),
                allow_redirects=False,
            ) as r:
                size = int(r.headers.get("Content-Length", 0))
                ctype = r.headers.get("Content-Type", "").split(";")[0]
                return {
                    "url": url,
                    "status": r.status,
                    "size": size,
                    "content_type": ctype,
                    "interesting": r.status in (200, 201, 301, 302, 401, 403),
                }
        except Exception:
            return {"url": url, "status": 0, "interesting": False}


async def _fuzz_async(base_url: str, paths: list, concurrency: int = 20) -> list:
    sem = asyncio.Semaphore(concurrency)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; omega-cli/0.7.0)",
        "Accept": "*/*",
    }
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    results = []

    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        tasks = [_probe(session, f"{base_url.rstrip('/')}/{p.lstrip('/')}", sem) for p in paths]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r.get("interesting")]


def _build_wordlist(target: str, custom_file: str = "", extensions: bool = False) -> list:
    paths = list(COMMON_PATHS)

    # Load custom wordlist
    if custom_file and Path(custom_file).exists():
        extra = Path(custom_file).read_text().splitlines()
        paths.extend([p.strip() for p in extra if p.strip()])

    # Load omega-generated wordlist if it exists
    safe = target.replace(".", "_")
    omega_wl = Path.home() / "omega-reports" / f"wordlist_{safe}.txt"
    if omega_wl.exists():
        custom = omega_wl.read_text().splitlines()
        paths.extend([p.strip() for p in custom[:200] if p.strip()])
        console.print(f"[dim]  Loaded omega wordlist: {len(custom)} extra words[/]")

    if extensions:
        expanded = []
        for p in paths:
            expanded.append(p)
            if "." not in Path(p).suffix:
                for ext in EXTENSIONS[1:]:
                    expanded.append(f"{p}{ext}")
        return list(dict.fromkeys(expanded))

    return list(dict.fromkeys(paths))


def run(target: str, wordlist_file: str = "", extensions: bool = False,
        concurrency: int = 20, codes: str = "200,201,301,302,401,403"):
    """Fuzz directories and files on a web target."""
    if not target.startswith("http"):
        target = f"https://{target}"

    console.print(Panel(
        f"[bold #ff2d78]💥 Directory Fuzzer[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    paths = _build_wordlist(domain, wordlist_file, extensions)
    console.print(f"[dim]  {len(paths)} paths to test  |  concurrency: {concurrency}[/]")

    start = time.time()
    try:
        results = asyncio.run(_fuzz_async(target, paths, concurrency))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(_fuzz_async(target, paths, concurrency))
        loop.close()
    elapsed = time.time() - start

    filter_codes = [int(c) for c in codes.split(",")]
    results = [r for r in results if r["status"] in filter_codes]

    if not results:
        console.print(f"[green]✓[/] Nothing interesting found  ({len(paths)} paths in {elapsed:.1f}s)")
        return []

    # Sort by interestingness: 200 first, then 301/302, then 401/403
    order = {200: 0, 201: 1, 301: 2, 302: 3, 401: 4, 403: 5}
    results.sort(key=lambda r: (order.get(r["status"], 99), r["url"]))

    tbl = Table(
        title=f"[bold #ff2d78]Found ({len(results)}) — {len(paths)} tested in {elapsed:.1f}s[/]",
        box=box.ROUNDED, border_style="#ff85b3",
    )
    tbl.add_column("Status", width=8)
    tbl.add_column("Size", width=10)
    tbl.add_column("Type", width=20)
    tbl.add_column("Path", style="cyan")

    for r in results:
        s = r["status"]
        sc = "green" if s == 200 else "yellow" if s in (301, 302) else "red" if s == 403 else "dim"
        tbl.add_row(
            f"[{sc}]{s}[/]",
            f"{r['size']:,}" if r["size"] else "-",
            r.get("content_type", "")[:20],
            r["url"].replace(target, ""),
        )
    console.print(tbl)
    console.print(f"\n[bold]Rate:[/] [cyan]{len(paths)/elapsed:.0f}[/] req/s")
    return results
