"""omega deepweb — Dark web intelligence: ransomware trackers, leak monitors, Tor OSINT."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()
TIMEOUT = 15

# Public ransomware tracker feeds
RANSOMWARE_FEEDS = {
    "RansomWatch": "https://ransomwatch.telemetry.ltd/posts.json",
    "Ransomware.live": "https://api.ransomware.live/v2/recentvictims",
}

# Known ransomware group TOR addresses (via public clearnet proxies)
THREAT_GROUPS = [
    "LockBit", "BlackCat/ALPHV", "Cl0p", "BlackBasta", "Royal",
    "Akira", "Play", "Medusa", "RansomHub", "Hunters",
    "8Base", "NoEscape", "Rhysida", "Cactus", "INC Ransom",
]


def _ransomwatch(query: str = "") -> list[dict]:
    """Fetch ransomwatch.telemetry.ltd public feed."""
    results = []
    try:
        r = httpx.get(RANSOMWARE_FEEDS["RansomWatch"], timeout=TIMEOUT)
        if r.status_code == 200:
            posts = r.json()
            query_lower = query.lower()
            for post in posts:
                victim = str(post.get("post_title") or "").lower()
                group = str(post.get("group_name") or "")
                discovered = post.get("discovered") or ""
                if not query or query_lower in victim or query_lower in group.lower():
                    results.append({
                        "victim": post.get("post_title", "?"),
                        "group": group,
                        "discovered": discovered[:10] if discovered else "?",
                        "url": post.get("post_url", ""),
                        "country": post.get("country", "?"),
                        "activity": post.get("activity", "?"),
                    })
    except Exception:
        pass
    return results[:50]


def _ransomware_live(query: str = "") -> list[dict]:
    """Fetch ransomware.live recent victims."""
    results = []
    try:
        r = httpx.get(RANSOMWARE_FEEDS["Ransomware.live"], timeout=TIMEOUT)
        if r.status_code == 200:
            victims = r.json() if isinstance(r.json(), list) else r.json().get("data", [])
            query_lower = query.lower()
            for v in victims:
                name = str(v.get("victim") or v.get("post_title") or "").lower()
                group = str(v.get("group") or v.get("group_name") or "")
                if not query or query_lower in name or query_lower in group.lower():
                    results.append({
                        "victim": v.get("victim") or v.get("post_title", "?"),
                        "group": group,
                        "discovered": (v.get("discovered") or v.get("published", ""))[:10],
                        "country": v.get("country", "?"),
                        "website": v.get("website", ""),
                    })
    except Exception:
        pass
    return results[:50]


def _ahmia_search(query: str) -> list[dict]:
    """Search Ahmia.fi for .onion content."""
    results = []
    try:
        r = httpx.get(
            "https://ahmia.fi/search/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            # Extract result links and snippets
            body = r.text
            items = re.findall(
                r'<h4[^>]*>.*?<a href="([^"]+)"[^>]*>(.*?)</a>.*?</h4>.*?<p[^>]*>(.*?)</p>',
                body, re.DOTALL
            )
            for href, title, snippet in items[:15]:
                title_clean = re.sub(r'<[^>]+>', '', title).strip()
                snippet_clean = re.sub(r'<[^>]+>', '', snippet).strip()[:120]
                onion_m = re.search(r'([a-z2-7]{16,56}\.onion)', href)
                results.append({
                    "title": title_clean,
                    "snippet": snippet_clean,
                    "onion": onion_m.group(1) if onion_m else None,
                    "url": href[:100],
                })
    except Exception:
        pass
    return results


def _tor2web_check(onion: str) -> dict:
    """Check .onion availability via Tor2Web proxy."""
    result: dict[str, Any] = {"onion": onion}
    onion_clean = onion.replace(".onion", "")
    proxies = [
        f"https://{onion_clean}.onion.ly",
        f"https://{onion_clean}.tor2web.io",
    ]
    for proxy in proxies:
        try:
            r = httpx.get(proxy, timeout=8, follow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"})
            result["status"] = r.status_code
            result["online"] = r.status_code == 200
            result["proxy_used"] = proxy
            if r.status_code == 200:
                title_m = re.search(r'<title>([^<]+)</title>', r.text, re.I)
                result["title"] = title_m.group(1)[:80] if title_m else None
                result["size"] = len(r.content)
            break
        except Exception:
            continue
    return result


def _hacker_forums_search(query: str) -> list[dict]:
    """Search known clear-web hacker forum indexes."""
    results = []
    # IntelligenceX-style public leak aggregator search
    try:
        r = httpx.get(
            "https://leakix.net/search",
            params={"q": query, "scope": "leak", "page": 0},
            headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            leaks = r.json() if isinstance(r.json(), list) else []
            for leak in leaks[:10]:
                results.append({
                    "host": leak.get("ip") or leak.get("host"),
                    "plugin": leak.get("plugin"),
                    "summary": (leak.get("summary") or "")[:100],
                    "severity": leak.get("severity", "?"),
                    "date": (leak.get("time") or "")[:10],
                    "source": "LeakIX",
                })
    except Exception:
        pass
    return results


def _domain_on_ransomware_list(domain: str, victims: list[dict]) -> list[dict]:
    """Check if domain appears in ransomware victim lists."""
    matches = []
    domain_root = re.sub(r"^www\.", "", domain.lower())
    for v in victims:
        victim_name = str(v.get("victim") or "").lower()
        website = str(v.get("website") or "").lower()
        if domain_root in victim_name or domain_root in website:
            matches.append(v)
    return matches


def run(query: str, check_onion: str = "", monitor_domain: str = ""):
    console.print(Panel(
        f"[bold #ff2d78]🕸  Dark Web Intelligence[/bold #ff2d78] — [cyan]{query}[/cyan]",
        box=box.ROUNDED
    ))

    findings: dict[str, Any] = {"query": query}

    # Ransomware victim tracking
    with console.status("[cyan]Fetching ransomware victim feeds…"):
        rw_victims = _ransomwatch(query)
        rl_victims = _ransomware_live(query)

    all_victims = rw_victims + rl_victims
    # Deduplicate
    seen = set()
    unique_victims = []
    for v in all_victims:
        key = (str(v.get("victim", "")), str(v.get("group", "")))
        if key not in seen:
            seen.add(key)
            unique_victims.append(v)

    findings["ransomware_victims"] = unique_victims

    if unique_victims:
        t = Table("Victim", "Group", "Country", "Date",
                  title=f"[bold red]☠  {len(unique_victims)} Ransomware Victim(s)[/bold red]",
                  box=box.SIMPLE_HEAD, header_style="bold red")
        for v in unique_victims[:20]:
            t.add_row(
                (str(v.get("victim") or "?"))[:40],
                str(v.get("group") or "?")[:25],
                str(v.get("country") or "?")[:15],
                str(v.get("discovered") or "?"),
            )
        console.print(t)

        # Group breakdown
        group_counts: dict[str, int] = {}
        for v in unique_victims:
            g = str(v.get("group") or "Unknown")
            group_counts[g] = group_counts.get(g, 0) + 1
        if len(group_counts) > 1:
            console.print("\n[bold]By group:[/bold]")
            for g, cnt in sorted(group_counts.items(), key=lambda x: -x[1])[:8]:
                bar = "█" * min(cnt, 20)
                console.print(f"  [red]{g:<25}[/red] {bar} {cnt}")
    else:
        console.print("[green]✓ No ransomware victims matching query.[/green]")

    # Domain check against ransomware lists
    if monitor_domain:
        domain_hits = _domain_on_ransomware_list(monitor_domain, unique_victims)
        findings["domain_ransomware_hits"] = domain_hits
        if domain_hits:
            console.print(f"\n[bold red]⚠  DOMAIN ALERT: {monitor_domain} appears in {len(domain_hits)} ransomware record(s)![/bold red]")
        else:
            console.print(f"\n[green]✓ {monitor_domain} not found in ransomware victim lists.[/green]")

    # Ahmia dark web search
    with console.status("[cyan]Searching Ahmia dark web index…"):
        ahmia = _ahmia_search(query)
    findings["ahmia"] = ahmia
    if ahmia:
        t2 = Table("Title", "Snippet", ".onion",
                   title=f"[bold magenta]🧅 {len(ahmia)} Dark Web Result(s)[/bold magenta]",
                   box=box.SIMPLE_HEAD, header_style="bold magenta")
        for a in ahmia:
            t2.add_row(
                a.get("title", "?")[:40],
                a.get("snippet", "")[:60],
                a.get("onion") or "—",
            )
        console.print(t2)
    else:
        console.print("\n[dim]No Ahmia results found.[/dim]")

    # Specific .onion check
    if check_onion:
        onion = check_onion if check_onion.endswith(".onion") else check_onion + ".onion"
        with console.status(f"[cyan]Checking {onion} availability…"):
            onion_status = _tor2web_check(onion)
        findings["onion_check"] = onion_status
        status_color = "green" if onion_status.get("online") else "red"
        console.print(f"\n[bold]Onion status:[/bold] [{status_color}]{'ONLINE' if onion_status.get('online') else 'OFFLINE'}[/{status_color}]")
        if onion_status.get("title"):
            console.print(f"  Title: {onion_status['title']}")

    # LeakIX
    with console.status("[cyan]Checking LeakIX…"):
        leakix = _hacker_forums_search(query)
    findings["leakix"] = leakix
    if leakix:
        t3 = Table("Host", "Plugin", "Severity", "Date", "Summary",
                   title=f"[bold yellow]💧 {len(leakix)} LeakIX Record(s)[/bold yellow]",
                   box=box.SIMPLE_HEAD, header_style="bold yellow")
        for l in leakix:
            t3.add_row(
                str(l.get("host") or "?")[:25],
                str(l.get("plugin") or "?")[:20],
                str(l.get("severity") or "?"),
                str(l.get("date") or "?"),
                str(l.get("summary") or "")[:50],
            )
        console.print(t3)

    # Threat group summary
    console.print(f"\n[bold]Known active ransomware groups:[/bold]")
    console.print("  " + "  ".join(f"[dim]{g}[/dim]" for g in THREAT_GROUPS[:8]))

    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", query)
    out_file = os.path.join(out_dir, f"deepweb_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
