"""Cloud storage bucket finder — S3, GCS, Azure, DigitalOcean Spaces."""
import httpx
import asyncio
from rich.console import Console
from rich.table import Table

console = Console()

# Permutation templates for bucket name guessing
PERMUTATIONS = [
    "{name}", "{name}-backup", "{name}-data", "{name}-files", "{name}-assets",
    "{name}-static", "{name}-media", "{name}-images", "{name}-uploads",
    "{name}-dev", "{name}-staging", "{name}-prod", "{name}-production",
    "{name}-test", "{name}-old", "{name}-new", "{name}-public", "{name}-private",
    "{name}-logs", "{name}-cdn", "{name}-store", "{name}-storage", "{name}-docs",
    "{name}-resources", "{name}-web", "{name}-api", "{name}-archive",
    "backup-{name}", "data-{name}", "files-{name}", "assets-{name}",
    "{name}backup", "{name}data", "{name}files", "{name}assets",
]

# Provider URL templates — {bucket} = bucket name
PROVIDERS = {
    "AWS S3 (us-east-1)":  "https://{bucket}.s3.amazonaws.com/",
    "AWS S3 (us-west-2)":  "https://{bucket}.s3.us-west-2.amazonaws.com/",
    "GCS":                  "https://storage.googleapis.com/{bucket}/",
    "Azure Blob":           "https://{bucket}.blob.core.windows.net/",
    "DO Spaces":            "https://{bucket}.nyc3.digitaloceanspaces.com/",
    "Backblaze B2":         "https://f001.backblazeb2.com/file/{bucket}/",
}

OPEN_INDICATORS = [
    "ListBucketResult", "Contents", "Key", "<EnumerationResults",
    "<?xml", "Blobs", "BlobItems",
]
FORBIDDEN_INDICATORS = ["AccessDenied", "403", "NoSuchBucket", "InvalidBucketName", "404"]


async def _check_bucket(client: httpx.AsyncClient, provider: str, url: str) -> tuple:
    try:
        r = await client.get(url, timeout=5, follow_redirects=False)
        body = r.text[:500]
        if r.status_code == 200 and any(ind in body for ind in OPEN_INDICATORS):
            return provider, url, "OPEN", r.status_code
        elif r.status_code == 403:
            return provider, url, "EXISTS (private)", r.status_code
        elif r.status_code in (301, 302):
            return provider, url, "REDIRECT", r.status_code
        return provider, url, "NOT_FOUND", r.status_code
    except Exception:
        return provider, url, "ERROR", 0


async def _run_async(names: list[str]) -> list:
    limits = httpx.Limits(max_connections=30)
    headers = {"User-Agent": "Mozilla/5.0 (omega-cli)"}
    results = []

    async with httpx.AsyncClient(limits=limits, headers=headers) as client:
        tasks = []
        for name in names:
            for provider, url_tmpl in PROVIDERS.items():
                url = url_tmpl.replace("{bucket}", name)
                tasks.append(_check_bucket(client, provider, url))
        results = await asyncio.gather(*tasks)
    return results


def run(target: str):
    """Search for open or exposed cloud storage buckets."""
    # derive candidate names from domain
    base = target.replace("https://", "").replace("http://", "").split("/")[0]
    parts = base.split(".")
    candidates = set()
    for part in parts:
        if len(part) > 2 and part not in ("com", "org", "net", "io", "co"):
            for tmpl in PERMUTATIONS:
                candidates.add(tmpl.replace("{name}", part))
    # also try the full domain without TLD
    root = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
    for tmpl in PERMUTATIONS:
        candidates.add(tmpl.replace("{name}", root))

    candidates = sorted(candidates)
    console.print(f"\n[bold cyan][ CLOUD BUCKETS ] {target}[/bold cyan]\n")
    console.print(f"[dim]Testing {len(candidates)} name variants across {len(PROVIDERS)} providers...[/dim]\n")

    with console.status("Scanning cloud storage...", spinner="dots"):
        results = asyncio.run(_run_async(candidates))

    open_buckets  = [(p, u, s) for p, u, s, _ in results if s == "OPEN"]
    exist_buckets = [(p, u, s) for p, u, s, _ in results if "EXISTS" in s]

    if open_buckets:
        ot = Table(title=f"[bold red]🪣 OPEN BUCKETS ({len(open_buckets)})[/bold red]")
        ot.add_column("Provider",   style="bold red")
        ot.add_column("URL",        style="cyan")
        ot.add_column("Status",     style="red")
        for p, u, s in open_buckets:
            ot.add_row(p, u, s)
        console.print(ot)
    else:
        console.print("[green]✓ No publicly open buckets found[/green]")

    if exist_buckets:
        console.print()
        et = Table(title=f"[yellow]Private/Existing Buckets ({len(exist_buckets)})[/yellow]")
        et.add_column("Provider", style="yellow")
        et.add_column("URL",      style="dim")
        for p, u, s in exist_buckets[:20]:
            et.add_row(p, u)
        console.print(et)

    console.print(f"\n[dim]Scanned {len(results)} combinations.[/dim]")
    return {"open": open_buckets, "private": exist_buckets}
