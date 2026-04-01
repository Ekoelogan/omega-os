"""omega identity — Cross-platform identity correlation across 50+ platforms."""
from __future__ import annotations
import asyncio, json, re, time
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Platform definitions: (url_template, positive_indicator)
PLATFORMS = {
    # Social
    "Twitter/X":       ("https://twitter.com/{}", 200),
    "Instagram":       ("https://www.instagram.com/{}/", 200),
    "TikTok":          ("https://www.tiktok.com/@{}", 200),
    "Reddit":          ("https://www.reddit.com/user/{}/", 200),
    "Pinterest":       ("https://www.pinterest.com/{}/", 200),
    "Tumblr":          ("https://{}.tumblr.com", 200),
    # Dev
    "GitHub":          ("https://github.com/{}", 200),
    "GitLab":          ("https://gitlab.com/{}", 200),
    "Bitbucket":       ("https://bitbucket.org/{}", 200),
    "npm":             ("https://www.npmjs.com/~{}", 200),
    "PyPI":            ("https://pypi.org/user/{}/", 200),
    "HackerNews":      ("https://news.ycombinator.com/user?id={}", 200),
    "SourceForge":     ("https://sourceforge.net/u/{}/profile/", 200),
    "Replit":          ("https://replit.com/@{}", 200),
    "Codepen":         ("https://codepen.io/{}", 200),
    # Gaming
    "Steam":           ("https://steamcommunity.com/id/{}", 200),
    "Twitch":          ("https://www.twitch.tv/{}", 200),
    "Roblox":          ("https://www.roblox.com/user.aspx?username={}", 200),
    "Chess.com":       ("https://www.chess.com/member/{}", 200),
    # Professional
    "LinkedIn":        ("https://www.linkedin.com/in/{}", 200),
    "AngelList":       ("https://angel.co/u/{}", 200),
    "Behance":         ("https://www.behance.net/{}", 200),
    "Dribbble":        ("https://dribbble.com/{}", 200),
    # Forums
    "Medium":          ("https://medium.com/@{}", 200),
    "Dev.to":          ("https://dev.to/{}", 200),
    "Hashnode":        ("https://hashnode.com/@{}", 200),
    "Keybase":         ("https://keybase.io/{}", 200),
    "Gravatar":        ("https://en.gravatar.com/{}", 200),
    "About.me":        ("https://about.me/{}", 200),
    # Other
    "Patreon":         ("https://www.patreon.com/{}", 200),
    "Ko-fi":           ("https://ko-fi.com/{}", 200),
    "Spotify":         ("https://open.spotify.com/user/{}", 200),
    "SoundCloud":      ("https://soundcloud.com/{}", 200),
    "Vimeo":           ("https://vimeo.com/{}", 200),
    "Flickr":          ("https://www.flickr.com/people/{}/", 200),
    "Blogger":         ("https://{}.blogspot.com", 200),
    "WordPress":       ("https://{}.wordpress.com", 200),
    "Wattpad":         ("https://www.wattpad.com/user/{}", 200),
    "Goodreads":       ("https://www.goodreads.com/{}", 200),
    "DockerHub":       ("https://hub.docker.com/u/{}", 200),
    "Kaggle":          ("https://www.kaggle.com/{}", 200),
    "Leetcode":        ("https://leetcode.com/{}", 200),
    "HackerRank":      ("https://www.hackerrank.com/{}", 200),
    "Codeforces":      ("https://codeforces.com/profile/{}", 200),
    "Mixcloud":        ("https://www.mixcloud.com/{}/", 200),
    "Last.fm":         ("https://www.last.fm/user/{}", 200),
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
}


async def _check_platform(client: httpx.AsyncClient, name: str, url_tmpl: str, handle: str, expected: int) -> dict:
    url = url_tmpl.format(handle)
    try:
        r = await client.get(url, follow_redirects=True, timeout=8)
        found = r.status_code == expected
        # Extra checks for false positives
        if found and r.status_code == 200:
            body = r.text.lower()
            not_found_phrases = ["this page doesn't exist", "user not found", "404", "no user",
                                 "page not found", "doesn't exist", "not available"]
            if any(p in body for p in not_found_phrases):
                found = False
        return {"platform": name, "url": url, "found": found, "status": r.status_code}
    except Exception:
        return {"platform": name, "url": url, "found": False, "status": None}


async def _check_all(handle: str, platforms: dict) -> list[dict]:
    results = []
    limits = httpx.Limits(max_connections=15, max_keepalive_connections=10)
    async with httpx.AsyncClient(headers=HEADERS, limits=limits) as client:
        tasks = [_check_platform(client, name, url, handle, code)
                 for name, (url, code) in platforms.items()]
        results = await asyncio.gather(*tasks)
    return list(results)


def _email_pattern_analysis(email: str) -> dict:
    """Generate likely username patterns from an email address."""
    local = email.split("@")[0]
    domain = email.split("@")[1] if "@" in email else ""
    patterns = set()
    patterns.add(local)
    if "." in local:
        parts = local.split(".")
        patterns.add("".join(parts))
        patterns.add("_".join(parts))
        patterns.add(parts[0])
        if len(parts) > 1:
            patterns.add(parts[0][0] + parts[-1])
            patterns.add(parts[0] + parts[-1][0])
    if re.match(r"\d+$", local[-2:]):
        patterns.add(local[:-2])
    return {"email": email, "domain": domain, "likely_usernames": sorted(patterns)}


def run(target: str, deep: bool = False, email_pivot: bool = False):
    is_email = "@" in target
    console.print(Panel(
        f"[bold #ff2d78]🪪  Identity Correlation[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    findings: dict[str, Any] = {"target": target, "type": "email" if is_email else "username"}

    handles_to_check = [target]

    if is_email:
        pivot = _email_pattern_analysis(target)
        findings["email_analysis"] = pivot
        console.print(f"\n[bold]Email domain:[/bold] {pivot['domain']}")
        console.print("[bold]Likely username patterns:[/bold]")
        for u in pivot["likely_usernames"]:
            console.print(f"  [cyan]•[/cyan] {u}")
        if email_pivot:
            handles_to_check = list(pivot["likely_usernames"])
        else:
            handles_to_check = [pivot["likely_usernames"][0]] if pivot["likely_usernames"] else [target.split("@")[0]]

    handle = handles_to_check[0]
    platforms = PLATFORMS if deep else dict(list(PLATFORMS.items())[:30])

    console.print(f"\n[dim]Checking [bold]{len(platforms)}[/bold] platforms for handle: [cyan]{handle}[/cyan]…[/dim]\n")

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _check_all(handle, platforms))
                results = future.result(timeout=60)
        else:
            results = loop.run_until_complete(_check_all(handle, platforms))
    except RuntimeError:
        results = asyncio.run(_check_all(handle, platforms))

    found = [r for r in results if r["found"]]
    not_found = [r for r in results if not r["found"]]

    findings["found"] = found
    findings["not_found_count"] = len(not_found)
    findings["coverage"] = f"{len(found)}/{len(platforms)}"

    if found:
        t = Table("Platform", "URL", title=f"[bold green]✓  Found on {len(found)} platform(s)[/bold green]",
                  box=box.SIMPLE_HEAD, header_style="bold green")
        for r in sorted(found, key=lambda x: x["platform"]):
            t.add_row(r["platform"], f"[link={r['url']}][cyan]{r['url']}[/cyan][/link]")
        console.print(t)
    else:
        console.print("[yellow]No platform profiles found.[/yellow]")

    # Confidence score
    score = min(100, len(found) * 5)
    color = "green" if score > 50 else "yellow" if score > 20 else "red"
    console.print(f"\n[bold]Identity confidence score:[/bold] [{color}]{score}/100[/{color}]  "
                  f"[dim]({len(found)} profiles across {len(platforms)} checked)[/dim]")

    import os, datetime
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"identity_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"[dim]Saved → {out_file}[/dim]")
