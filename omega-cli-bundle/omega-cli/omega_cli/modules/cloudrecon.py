"""Cloud infrastructure enumeration — Firebase, GCP, Azure, AWS expanded, DigitalOcean."""
import asyncio
import aiohttp
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

console = Console()

# AWS S3 patterns
S3_REGIONS = ["s3", "s3-us-east-1", "s3-us-west-2", "s3-eu-west-1", "s3-ap-southeast-1"]

# Firebase patterns
FIREBASE_PATTERNS = [
    "https://{name}.firebaseio.com/.json",
    "https://{name}-default-rtdb.firebaseio.com/.json",
]

# GCP storage
GCS_URL = "https://storage.googleapis.com/{name}"

# Azure blob
AZURE_URL = "https://{name}.blob.core.windows.net"

# DigitalOcean Spaces
DO_REGIONS = ["nyc3", "ams3", "sgp1", "fra1", "sfo3"]

# Cloud metadata endpoints (for SSRF testing reference)
METADATA_ENDPOINTS = {
    "AWS IMDSv1":  "http://169.254.169.254/latest/meta-data/",
    "AWS IMDSv2":  "http://169.254.169.254/latest/meta-data/ (token required)",
    "GCP":         "http://metadata.google.internal/computeMetadata/v1/",
    "Azure":       "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "DigitalOcean":"http://169.254.169.254/metadata/v1/",
    "Alibaba":     "http://100.100.100.200/latest/meta-data/",
}


async def _check_url_async(session: aiohttp.ClientSession, url: str, name: str, service: str) -> dict:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as r:
            is_open = r.status in (200, 206)
            is_exists = r.status not in (404, 403, 400)
            content_len = r.headers.get("Content-Length", "")
            return {
                "url": url,
                "name": name,
                "service": service,
                "status": r.status,
                "open": is_open,
                "exists": is_exists,
                "size": content_len,
            }
    except Exception:
        return {"url": url, "name": name, "service": service, "status": 0, "open": False, "exists": False}


async def _probe_all(targets: list) -> list:
    connector = aiohttp.TCPConnector(limit=30, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check_url_async(session, t["url"], t["name"], t["service"]) for t in targets]
        return await asyncio.gather(*tasks, return_exceptions=False)


def _generate_targets(name: str) -> list:
    targets = []
    variants = [
        name, f"{name}-dev", f"{name}-prod", f"{name}-staging", f"{name}-backup",
        f"{name}-assets", f"{name}-media", f"{name}-static", f"{name}-files",
        f"{name}-data", f"{name}-images", f"dev-{name}", f"prod-{name}",
        f"{name}-public", f"{name}-private", f"{name}backup", f"{name}assets",
    ]

    for variant in variants:
        # AWS S3
        for region in S3_REGIONS:
            targets.append({"url": f"https://{variant}.{region}.amazonaws.com", "name": variant, "service": "S3"})

        # Firebase RTDB
        targets.append({"url": f"https://{variant}.firebaseio.com/.json", "name": variant, "service": "Firebase RTDB"})
        targets.append({"url": f"https://{variant}-default-rtdb.firebaseio.com/.json", "name": variant, "service": "Firebase RTDB"})

        # Firebase Hosting
        targets.append({"url": f"https://{variant}.web.app", "name": variant, "service": "Firebase Hosting"})
        targets.append({"url": f"https://{variant}.firebaseapp.com", "name": variant, "service": "Firebase Hosting"})

        # GCS
        targets.append({"url": f"https://storage.googleapis.com/{variant}", "name": variant, "service": "GCS"})

        # Azure Blob
        targets.append({"url": f"https://{variant}.blob.core.windows.net", "name": variant, "service": "Azure Blob"})
        targets.append({"url": f"https://{variant}.azurewebsites.net", "name": variant, "service": "Azure Web"})

        # DigitalOcean Spaces
        for region in DO_REGIONS:
            targets.append({"url": f"https://{variant}.{region}.digitaloceanspaces.com", "name": variant, "service": "DO Spaces"})

    return targets


def run(name: str, deep: bool = False):
    """Enumerate cloud assets across AWS, GCP, Azure, Firebase, DigitalOcean."""
    console.print(Panel(
        f"[bold #ff2d78]☁  Cloud Asset Enumeration[/]\n[dim]Name:[/] [cyan]{name}[/]",
        border_style="#ff85b3",
    ))

    targets = _generate_targets(name)
    console.print(f"[dim]  Probing {len(targets)} cloud endpoints (async)...[/]")

    try:
        results = asyncio.run(_probe_all(targets))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(_probe_all(targets))
        loop.close()

    open_buckets = [r for r in results if r.get("open")]
    existing = [r for r in results if r.get("exists") and not r.get("open")]

    if open_buckets:
        tbl = Table(
            title=f"[bold red]🚨 Open / Public Cloud Assets ({len(open_buckets)})[/]",
            box=box.ROUNDED, border_style="red",
        )
        tbl.add_column("Service", style="bold yellow")
        tbl.add_column("Name", style="cyan")
        tbl.add_column("URL")
        tbl.add_column("Status", width=8)
        tbl.add_column("Size")
        for r in open_buckets:
            tbl.add_row(
                r["service"], r["name"], r["url"][:70],
                f"[green]{r['status']}[/]", r.get("size", ""),
            )
        console.print(tbl)

    if existing:
        tbl2 = Table(
            title=f"Existing (Protected) Assets ({len(existing)})",
            box=box.SIMPLE, border_style="dim",
        )
        tbl2.add_column("Service")
        tbl2.add_column("URL", style="dim")
        tbl2.add_column("Status", width=8)
        for r in existing[:20]:
            tbl2.add_row(r["service"], r["url"][:70], str(r["status"]))
        console.print(tbl2)

    # Show metadata SSRF reference
    if deep:
        mtbl = Table(title="Cloud Metadata SSRF Reference", box=box.ROUNDED, border_style="#ff85b3")
        mtbl.add_column("Provider", style="bold")
        mtbl.add_column("Endpoint", style="cyan")
        for provider, endpoint in METADATA_ENDPOINTS.items():
            mtbl.add_row(provider, endpoint)
        console.print(mtbl)

    if not open_buckets and not existing:
        console.print(f"[green]✓[/] No cloud assets found for '{name}'")

    console.print(f"\n[bold]Probed:[/] {len(targets)}  "
                  f"[bold red]Open:[/] {len(open_buckets)}  "
                  f"[yellow]Exists:[/] {len(existing)}")

    return {
        "name": name,
        "open": [r["url"] for r in open_buckets],
        "existing": [r["url"] for r in existing],
    }
