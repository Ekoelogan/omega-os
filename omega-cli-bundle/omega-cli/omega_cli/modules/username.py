"""Username OSINT — check a handle across major platforms."""
import httpx
import asyncio
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

PLATFORMS = {
    "GitHub":       "https://github.com/{username}",
    "GitLab":       "https://gitlab.com/{username}",
    "Twitter/X":    "https://x.com/{username}",
    "Instagram":    "https://www.instagram.com/{username}/",
    "TikTok":       "https://www.tiktok.com/@{username}",
    "Reddit":       "https://www.reddit.com/user/{username}",
    "LinkedIn":     "https://www.linkedin.com/in/{username}",
    "YouTube":      "https://www.youtube.com/@{username}",
    "Twitch":       "https://www.twitch.tv/{username}",
    "Pinterest":    "https://www.pinterest.com/{username}/",
    "Mastodon":     "https://mastodon.social/@{username}",
    "HackerNews":   "https://news.ycombinator.com/user?id={username}",
    "Dev.to":       "https://dev.to/{username}",
    "Medium":       "https://medium.com/@{username}",
    "Keybase":      "https://keybase.io/{username}",
    "Docker Hub":   "https://hub.docker.com/u/{username}",
    "npm":          "https://www.npmjs.com/~{username}",
    "PyPI":         "https://pypi.org/user/{username}/",
    "Pastebin":     "https://pastebin.com/u/{username}",
    "Steam":        "https://steamcommunity.com/id/{username}",
    "Spotify":      "https://open.spotify.com/user/{username}",
    "Telegram":     "https://t.me/{username}",
}

NOT_FOUND_INDICATORS = [
    "404", "not found", "page not found", "user not found",
    "doesn't exist", "no longer available", "this account",
]


async def _check(client: httpx.AsyncClient, platform: str, url: str) -> tuple:
    try:
        r = await client.get(url, follow_redirects=True, timeout=8)
        body_lower = r.text.lower()[:2000]
        if r.status_code == 200:
            if any(ind in body_lower for ind in NOT_FOUND_INDICATORS):
                return platform, url, "not_found"
            return platform, url, "found"
        elif r.status_code == 404:
            return platform, url, "not_found"
        else:
            return platform, url, f"status_{r.status_code}"
    except Exception:
        return platform, url, "error"


async def _run_async(username: str):
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    headers = {"User-Agent": "Mozilla/5.0 (omega-cli OSINT)"}
    results = []

    async with httpx.AsyncClient(limits=limits, headers=headers) as client:
        tasks = []
        for platform, url_template in PLATFORMS.items():
            url = url_template.replace("{username}", username)
            tasks.append(_check(client, platform, url))
        results = await asyncio.gather(*tasks)

    return results


def run(username: str):
    """Check username availability/presence across major platforms."""
    console.print(f"\n[bold cyan][ USERNAME OSINT ] @{username}[/bold cyan]\n")

    with console.status(f"Checking {len(PLATFORMS)} platforms...", spinner="dots"):
        results = asyncio.run(_run_async(username))

    found = [(p, u) for p, u, s in results if s == "found"]
    not_found = [(p, u) for p, u, s in results if s == "not_found"]
    errors = [(p, u, s) for p, u, s in results if s not in ("found", "not_found")]

    if found:
        table = Table(title=f"[green]Found on {len(found)} platform(s)[/green]", show_header=True)
        table.add_column("Platform", style="bold green")
        table.add_column("URL", style="cyan")
        for platform, url in found:
            table.add_row(platform, url)
        console.print(table)
    else:
        console.print("[yellow]Username not found on any checked platform.[/yellow]")

    if not_found:
        nf_table = Table(title=f"[dim]Not found on {len(not_found)} platform(s)[/dim]",
                         show_header=False, box=None, padding=(0, 2))
        nf_table.add_column("Platform", style="dim")
        for platform, _ in not_found:
            nf_table.add_row(platform)
        console.print(nf_table)
