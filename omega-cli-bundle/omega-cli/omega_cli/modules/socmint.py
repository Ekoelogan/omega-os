"""socmint.py — Social media OSINT: cross-platform username search & profile aggregation."""
from __future__ import annotations
import json, re, time
from pathlib import Path
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

UA = "Mozilla/5.0 (compatible; OmegaCLI/1.7.0)"

# Platform URL templates {username}
PLATFORMS = {
    "GitHub":        ("https://github.com/{u}",                    ['"login"', 'class="p-name"']),
    "GitLab":        ("https://gitlab.com/{u}",                    ['class="cover-title"', '"username"']),
    "Twitter/X":     ("https://x.com/{u}",                         ["UserName", '"screen_name"']),
    "Reddit":        ("https://www.reddit.com/user/{u}/about.json", ['"name"', '"created_utc"']),
    "HackerNews":    ("https://hacker-news.firebaseio.com/v0/user/{u}.json", ['"id"']),
    "Dev.to":        ("https://dev.to/api/users/by_username?url={u}", ['"username"']),
    "Keybase":       ("https://keybase.io/{u}",                    ['"them"', '"basics"']),
    "Gravatar":      ("https://en.gravatar.com/{u}.json",          ['"entry"']),
    "SourceHatch":   ("https://sr.ht/~{u}/",                       ["~{u}"]),
    "npmjs":         ("https://www.npmjs.com/~{u}",                ['class="username"']),
    "PyPI":          ("https://pypi.org/user/{u}/",                ['"username"']),
    "DockerHub":     ("https://hub.docker.com/v2/users/{u}/",     ['"username"']),
    "TryHackMe":     ("https://tryhackme.com/p/{u}",               ['"username"', 'class="name"']),
    "HackTheBox":    ("https://app.hackthebox.com/api/v4/user/profile/overview/{u}", ['"id"']),
    "Pastebin":      ("https://pastebin.com/u/{u}",                ['class="username"']),
    "ProductHunt":   ("https://www.producthunt.com/@{u}",         ['"username"', '"name"']),
    "Medium":        ("https://medium.com/@{u}",                   ['"@context"', '"name"']),
    "Mastodon":      ("https://mastodon.social/@{u}",              ['"@context"', '"name"']),
    "Twitch":        ("https://api.twitch.tv/helix/users?login={u}", ['"data"']),
    "Linktree":      ("https://linktr.ee/{u}",                    ['"username"', '"title"']),
    "About.me":      ("https://about.me/{u}",                      ['"username"']),
    "Replit":        ("https://replit.com/@{u}",                   ['"username"']),
    "Codepen":       ("https://codepen.io/{u}",                    ['"user"', '"username"']),
    "SoundCloud":    ("https://soundcloud.com/{u}",                ['"username"', '"kind":"user"']),
    "Instagram":     ("https://www.instagram.com/{u}/",            ['"@type":"ProfilePage"']),
    "Flickr":        ("https://www.flickr.com/people/{u}/",        ['"owner"']),
    "Vimeo":         ("https://vimeo.com/{u}",                    ['"name"']),
}

# Email breach checks (passive, no key required)
EMAIL_BREACH_URLS = [
    ("HaveIBeenPwned", "https://haveibeenpwned.com/unifiedsearch/{email}"),
]


def _probe(url: str, timeout: int = 8) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(50_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _extract_github_info(username: str) -> dict:
    status, body = _probe(f"https://api.github.com/users/{username}")
    if status == 200:
        try:
            d = json.loads(body)
            return {
                "name":         d.get("name"),
                "bio":          d.get("bio"),
                "company":      d.get("company"),
                "location":     d.get("location"),
                "blog":         d.get("blog"),
                "email":        d.get("email"),
                "followers":    d.get("followers"),
                "following":    d.get("following"),
                "public_repos": d.get("public_repos"),
                "created_at":   d.get("created_at"),
                "twitter":      d.get("twitter_username"),
            }
        except Exception:
            pass
    return {}


def _extract_reddit_info(username: str) -> dict:
    status, body = _probe(f"https://www.reddit.com/user/{username}/about.json")
    if status == 200:
        try:
            d = json.loads(body).get("data", {})
            return {
                "name":         d.get("name"),
                "link_karma":   d.get("link_karma"),
                "comment_karma":d.get("comment_karma"),
                "created_utc":  d.get("created_utc"),
                "is_gold":      d.get("is_gold"),
                "verified":     d.get("verified"),
                "subreddits":   d.get("subreddit", {}).get("display_name_prefixed"),
            }
        except Exception:
            pass
    return {}


def _extract_hn_info(username: str) -> dict:
    status, body = _probe(f"https://hacker-news.firebaseio.com/v0/user/{username}.json")
    if status == 200:
        try:
            d = json.loads(body) or {}
            return {
                "id":      d.get("id"),
                "karma":   d.get("karma"),
                "about":   re.sub(r"<[^>]+>", "", d.get("about", ""))[:200],
                "created": d.get("created"),
            }
        except Exception:
            pass
    return {}


def run(username: str, email: str = "", deep: bool = False, export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"👤  Social Media OSINT — @{username}", style="bold cyan"))

    results = {
        "username": username,
        "email":    email,
        "found":    [],
        "not_found":[],
        "profiles": {},
    }

    t = Table(title="Platform Search", box=box.SIMPLE if box else None)
    t.add_column("Platform",  style="cyan", min_width=15)
    t.add_column("Status",    style="bold")
    t.add_column("URL",       style="dim",  max_width=60)
    t.add_column("Notes",     style="dim")

    for platform, (url_template, markers) in PLATFORMS.items():
        url = url_template.replace("{u}", username).replace("{username}", username)
        url = url.replace("{email}", username)
        status_code, body = _probe(url)

        found = False
        notes = ""

        if status_code == 200:
            # Check for markers to reduce false positives
            if markers:
                found = any(m.replace("{u}", username) in body for m in markers)
            else:
                found = True
        elif status_code in (301, 302, 307):
            found = True  # redirect = likely exists

        color  = "green" if found else "dim"
        status = "✅ Found" if found else ("❌ 404" if status_code == 404 else f"[dim]{status_code}[/dim]")

        if found:
            results["found"].append({"platform": platform, "url": url})
            # Deep info for key platforms
            if platform == "GitHub":
                gh = _extract_github_info(username)
                if gh:
                    results["profiles"]["github"] = gh
                    notes = f"repos={gh.get('public_repos')} followers={gh.get('followers')}"
            elif platform == "Reddit":
                rdt = _extract_reddit_info(username)
                if rdt:
                    results["profiles"]["reddit"] = rdt
                    notes = f"karma={rdt.get('link_karma',0)+rdt.get('comment_karma',0)}"
            elif platform == "HackerNews":
                hn = _extract_hn_info(username)
                if hn:
                    results["profiles"]["hackernews"] = hn
                    notes = f"karma={hn.get('karma')}"
        else:
            results["not_found"].append(platform)

        t.add_row(platform, f"[{color}]{status}[/{color}]", url[:60], notes)

    console.print(t)

    # GitHub deep dive
    if results["profiles"].get("github"):
        gh = results["profiles"]["github"]
        console.print(Panel(
            f"Name: {gh.get('name')}\nBio: {gh.get('bio')}\n"
            f"Location: {gh.get('location')}\nCompany: {gh.get('company')}\n"
            f"Blog: {gh.get('blog')}\nEmail: {gh.get('email')}\n"
            f"Twitter: @{gh.get('twitter')}\n"
            f"Repos: {gh.get('public_repos')}  Followers: {gh.get('followers')}  Following: {gh.get('following')}\n"
            f"Joined: {gh.get('created_at')}",
            title="[cyan]GitHub Profile[/cyan]"
        ))

    # Reddit deep dive
    if results["profiles"].get("reddit"):
        r = results["profiles"]["reddit"]
        console.print(f"[cyan]Reddit[/cyan]: karma={r.get('link_karma',0)+r.get('comment_karma',0)}, "
                      f"verified={r.get('verified')}, gold={r.get('is_gold')}")

    # Summary
    console.print(f"\n[bold]Found on {len(results['found'])}/{len(PLATFORMS)} platforms[/bold]")
    if results["found"]:
        console.print("[green]✅ Profiles:[/green] " + ", ".join(p["platform"] for p in results["found"]))

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", username)
    out_path = Path(export) if export else out_dir / f"socmint_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
