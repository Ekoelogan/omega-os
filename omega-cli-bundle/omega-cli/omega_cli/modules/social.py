"""Social media OSINT — Twitter/X, Reddit, Pastebin, GitHub, HackerNews."""
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

console = Console()


def _reddit_search(query: str, limit: int = 20) -> list:
    try:
        r = requests.get(
            "https://www.reddit.com/search.json",
            params={"q": query, "limit": limit, "sort": "new", "type": "link"},
            headers={"User-Agent": "omega-cli/0.7.0"},
            timeout=10,
        )
        if r.status_code == 200:
            posts = r.json().get("data", {}).get("children", [])
            return [p["data"] for p in posts]
    except Exception as e:
        console.print(f"[dim]Reddit error: {e}[/]")
    return []


def _reddit_user(username: str) -> dict:
    try:
        r = requests.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers={"User-Agent": "omega-cli/0.7.0"}, timeout=10,
        )
        if r.status_code == 200:
            return r.json().get("data", {})
    except Exception:
        pass
    return {}


def _pastebin_search(query: str) -> list:
    """Search public Pastebin pastes via Google (no API needed)."""
    results = []
    try:
        r = requests.get(
            "https://www.google.com/search",
            params={"q": f"site:pastebin.com {query}", "num": 20},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
        )
        import re
        # Extract pastebin URLs from results
        urls = re.findall(r"pastebin\.com/[A-Za-z0-9]{8}", r.text)
        results = list(set(f"https://pastebin.com/{u.split('/')[-1]}" for u in urls))
    except Exception:
        pass
    return results[:10]


def _hackernews_search(query: str) -> list:
    try:
        r = requests.get(
            "https://hn.algolia.com/api/v1/search",
            params={"query": query, "hitsPerPage": 15},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json().get("hits", [])
    except Exception:
        pass
    return []


def _github_mentions(query: str, token: str = "") -> list:
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        r = requests.get(
            "https://api.github.com/search/commits",
            params={"q": query, "per_page": 10},
            headers={**headers, "Accept": "application/vnd.github.cloak-preview"},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("items", [])
    except Exception:
        pass
    return []


def _twitter_search(query: str) -> list:
    """Search Twitter/X via Nitter (no API key required)."""
    results = []
    nitter_instances = [
        "https://nitter.net",
        "https://nitter.privacydev.net",
        "https://nitter.poast.org",
    ]
    for instance in nitter_instances:
        try:
            r = requests.get(
                f"{instance}/search",
                params={"q": query, "f": "tweets"},
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=8,
            )
            if r.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "lxml")
                tweets = soup.find_all("div", class_="tweet-content")
                for t in tweets[:10]:
                    results.append({"text": t.get_text()[:200], "source": instance})
                if results:
                    break
        except Exception:
            continue
    return results


def run(target: str, token: str = "", deep: bool = False):
    """Run social media OSINT on a username, domain, or keyword."""
    console.print(Panel(
        f"[bold #ff2d78]📱 Social Media OSINT[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    results = {"target": target}

    # Reddit
    console.print("[dim]  Searching Reddit...[/]")
    reddit_posts = _reddit_search(target)

    if "@" not in target and "." not in target:
        # Username — check Reddit profile
        rd_user = _reddit_user(target)
        if rd_user and "name" in rd_user:
            tree = Tree(f"[bold #ff2d78]Reddit: u/{rd_user['name']}[/]", guide_style="dim #ff85b3")
            tree.add(f"[dim]Karma:[/] [cyan]{rd_user.get('link_karma', 0) + rd_user.get('comment_karma', 0):,}[/]")
            tree.add(f"[dim]Created:[/] {str(rd_user.get('created_utc', ''))[:10]}")
            tree.add(f"[dim]Gold:[/] {rd_user.get('is_gold', False)}")
            tree.add(f"[dim]Verified:[/] {rd_user.get('verified', False)}")
            console.print(tree)
            results["reddit_user"] = rd_user

    if reddit_posts:
        rtbl = Table(title=f"Reddit Mentions ({len(reddit_posts)})", box=box.ROUNDED, border_style="#ff85b3")
        rtbl.add_column("Subreddit", style="cyan", width=18)
        rtbl.add_column("Title")
        rtbl.add_column("Score", width=8)
        rtbl.add_column("Date", width=12)
        for p in reddit_posts[:10]:
            rtbl.add_row(
                f"r/{p.get('subreddit', '')}",
                p.get("title", "")[:70],
                str(p.get("score", "")),
                str(p.get("created_utc", ""))[:10],
            )
        console.print(rtbl)
        results["reddit_posts"] = len(reddit_posts)

    # HackerNews
    console.print("[dim]  Searching HackerNews...[/]")
    hn_hits = _hackernews_search(target)
    if hn_hits:
        htbl = Table(title=f"HackerNews ({len(hn_hits)})", box=box.SIMPLE, border_style="dim")
        htbl.add_column("Title", style="cyan")
        htbl.add_column("Points", width=8)
        htbl.add_column("Date", width=12)
        for h in hn_hits[:8]:
            htbl.add_row(
                h.get("title", h.get("story_title", ""))[:80],
                str(h.get("points", "")),
                h.get("created_at", "")[:10],
            )
        console.print(htbl)
        results["hackernews"] = len(hn_hits)

    # Pastebin
    console.print("[dim]  Searching Pastebin...[/]")
    pb_links = _pastebin_search(target)
    if pb_links:
        ptbl = Table(title=f"[bold red]Pastebin Hits ({len(pb_links)})[/]", box=box.ROUNDED, border_style="red")
        ptbl.add_column("URL", style="cyan")
        for url in pb_links:
            ptbl.add_row(url)
        console.print(ptbl)
        results["pastebin"] = pb_links

    # Twitter/X via Nitter
    console.print("[dim]  Searching Twitter/X (via Nitter)...[/]")
    tweets = _twitter_search(target)
    if tweets:
        ttbl = Table(title=f"Twitter/X Mentions ({len(tweets)})", box=box.ROUNDED, border_style="#ff85b3")
        ttbl.add_column("Tweet", style="cyan")
        for t in tweets[:8]:
            ttbl.add_row(t["text"][:100])
        console.print(ttbl)
        results["twitter"] = len(tweets)
    else:
        console.print("[dim]  No Twitter results (Nitter may be down)[/]")

    # GitHub commits mentioning target
    if deep:
        console.print("[dim]  Searching GitHub commits...[/]")
        gh_commits = _github_mentions(target, token)
        if gh_commits:
            gtbl = Table(title=f"GitHub Commits ({len(gh_commits)})", box=box.SIMPLE)
            gtbl.add_column("Repo", style="cyan")
            gtbl.add_column("Message")
            for c in gh_commits[:8]:
                gtbl.add_row(
                    c.get("repository", {}).get("full_name", "")[:40],
                    c.get("commit", {}).get("message", "")[:80],
                )
            console.print(gtbl)
            results["github_commits"] = len(gh_commits)

    total = sum(v for v in results.values() if isinstance(v, int))
    console.print(f"\n[bold]Total mentions found:[/] [cyan]{total}[/]")
    return results
