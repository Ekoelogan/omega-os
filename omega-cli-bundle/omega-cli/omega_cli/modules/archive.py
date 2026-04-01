"""omega archive — Deep archive mining: Wayback CDX, CommonCrawl, screenshot history, content diffs."""
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


def _wayback_cdx(domain: str, limit: int = 200, collapse: str = "urlkey") -> list[dict]:
    """Fetch URL list from Wayback CDX API."""
    results = []
    try:
        r = httpx.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "limit": limit,
                "fl": "original,timestamp,statuscode,mimetype,length",
                "collapse": collapse,
                "filter": "statuscode:200",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            rows = r.json()
            if rows and len(rows) > 1:
                headers = rows[0]
                for row in rows[1:]:
                    results.append(dict(zip(headers, row)))
    except Exception:
        pass
    return results


def _wayback_snapshots(url: str, limit: int = 20) -> list[dict]:
    """Get snapshot list for a specific URL."""
    results = []
    try:
        r = httpx.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": url,
                "output": "json",
                "limit": limit,
                "fl": "timestamp,statuscode,length,digest",
                "filter": "statuscode:200",
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            rows = r.json()
            if rows and len(rows) > 1:
                headers = rows[0]
                for row in rows[1:]:
                    d = dict(zip(headers, row))
                    d["snapshot_url"] = f"https://web.archive.org/web/{d['timestamp']}/{url}"
                    results.append(d)
    except Exception:
        pass
    return results


def _wayback_availability(url: str) -> dict:
    """Check if URL is available in Wayback Machine."""
    try:
        r = httpx.get(
            "https://archive.org/wayback/available",
            params={"url": url},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("archived_snapshots", {})
    except Exception:
        pass
    return {}


def _commoncrawl_search(domain: str, limit: int = 50) -> list[dict]:
    """Search CommonCrawl index for domain URLs."""
    results = []
    # Use CC index API (latest index)
    indexes = ["CC-MAIN-2024-10", "CC-MAIN-2023-50", "CC-MAIN-2023-40"]
    for idx in indexes[:1]:
        try:
            r = httpx.get(
                f"https://index.commoncrawl.org/{idx}-index",
                params={
                    "url": f"*.{domain}",
                    "output": "json",
                    "limit": limit,
                    "fl": "url,timestamp,status,mime",
                },
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                for line in r.text.strip().splitlines()[:limit]:
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        pass
                if results:
                    break
        except Exception:
            pass
    return results


def _extract_interesting_urls(urls: list[dict]) -> dict[str, list]:
    """Categorize URLs into interesting buckets."""
    cats: dict[str, list] = {
        "admin":    [],
        "api":      [],
        "config":   [],
        "backup":   [],
        "auth":     [],
        "upload":   [],
        "debug":    [],
        "secrets":  [],
        "other":    [],
    }
    patterns = {
        "admin":   re.compile(r"/admin|/administrator|/wp-admin|/cpanel|/phpmyadmin", re.I),
        "api":     re.compile(r"/api/|/v1/|/v2/|/graphql|/swagger|/openapi", re.I),
        "config":  re.compile(r"\.env|\.config|config\.|\.cfg|\.ini|settings\.", re.I),
        "backup":  re.compile(r"\.bak|\.backup|\.sql|\.tar|\.zip|\.gz|~$|\.old|_backup", re.I),
        "auth":    re.compile(r"/login|/signin|/auth|/oauth|/token|/session", re.I),
        "upload":  re.compile(r"/upload|/uploads|/files|/media|/images/", re.I),
        "debug":   re.compile(r"/debug|/test|/dev|/staging|/phpinfo|\.php\?", re.I),
        "secrets": re.compile(r"password|secret|key|token|credential|private", re.I),
    }
    for entry in urls:
        url = entry.get("original") or entry.get("url", "")
        matched = False
        for cat, pat in patterns.items():
            if pat.search(url):
                cats[cat].append(entry)
                matched = True
                break
        if not matched:
            cats["other"].append(entry)
    return cats


def _diff_snapshots(url: str, ts1: str, ts2: str) -> dict:
    """Fetch two snapshots and diff content length/status."""
    result: dict[str, Any] = {"url": url, "ts1": ts1, "ts2": ts2}
    for ts_key, ts in [("snap1", ts1), ("snap2", ts2)]:
        try:
            r = httpx.get(
                f"https://web.archive.org/web/{ts}/{url}",
                timeout=TIMEOUT,
                follow_redirects=True,
            )
            result[ts_key] = {
                "status": r.status_code,
                "length": len(r.content),
                "title": re.search(r'<title>([^<]+)</title>', r.text, re.I).group(1)[:80]
                         if re.search(r'<title>', r.text, re.I) else "?",
            }
        except Exception as e:
            result[ts_key] = {"error": str(e)}
    if result.get("snap1") and result.get("snap2"):
        l1 = result["snap1"].get("length", 0)
        l2 = result["snap2"].get("length", 0)
        result["size_delta"] = l2 - l1
        result["significant_change"] = abs(l2 - l1) > 1000
    return result


def run(
    target: str,
    limit: int = 100,
    diff: bool = False,
    interesting_only: bool = False,
    show_snapshots: bool = False,
):
    console.print(Panel(
        f"[bold #ff2d78]🗄  Deep Archive Mining[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    # Strip protocol for domain extraction
    domain = re.sub(r"^https?://", "", target).split("/")[0].lstrip("www.")
    url = target if target.startswith("http") else f"https://{target}"

    findings: dict[str, Any] = {"target": target, "domain": domain}

    # Wayback availability
    with console.status("[cyan]Checking Wayback Machine availability…"):
        avail = _wayback_availability(url)
    findings["availability"] = avail
    if avail.get("closest"):
        closest = avail["closest"]
        console.print(f"[green]✓ Archived:[/green] {closest.get('url')} "
                      f"[dim]({closest.get('timestamp', '?')[:8]})[/dim]")
    else:
        console.print("[yellow]⚠ No Wayback Machine archive found.[/yellow]")

    # CDX full URL discovery
    with console.status(f"[cyan]CDX search for *.{domain}/* (limit {limit})…"):
        cdx_urls = _wayback_cdx(domain, limit=limit)
    findings["cdx_count"] = len(cdx_urls)
    console.print(f"\n[bold]Wayback CDX:[/bold] [cyan]{len(cdx_urls)}[/cyan] unique URLs archived")

    if cdx_urls:
        # Categorize
        cats = _extract_interesting_urls(cdx_urls)
        interesting_count = sum(len(v) for k, v in cats.items() if k != "other")

        if interesting_count > 0:
            console.print(f"\n[bold yellow]🎯 {interesting_count} Interesting URLs found:[/bold yellow]")
            for cat, entries in cats.items():
                if cat != "other" and entries:
                    console.print(f"\n  [bold]{cat.upper()} ({len(entries)}):[/bold]")
                    for e in entries[:5]:
                        url_str = e.get("original") or e.get("url", "?")
                        ts = e.get("timestamp", "?")[:8]
                        console.print(f"    [cyan]{url_str[:90]}[/cyan] [dim]({ts})[/dim]")

        # All URLs table (if not interesting_only)
        if not interesting_only:
            t = Table("URL", "Timestamp", "Type", "Size",
                      title=f"[bold]📋 {min(len(cdx_urls), 20)} of {len(cdx_urls)} Archived URLs[/bold]",
                      box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
            for entry in cdx_urls[:20]:
                t.add_row(
                    (entry.get("original") or "?")[:70],
                    (entry.get("timestamp") or "?")[:12],
                    entry.get("mimetype", "?")[:25],
                    entry.get("length", "?"),
                )
            console.print(t)

    # Snapshot history for the root URL
    if show_snapshots:
        with console.status("[cyan]Fetching snapshot history…"):
            snaps = _wayback_snapshots(url, limit=20)
        findings["snapshots"] = snaps
        if snaps:
            t2 = Table("Timestamp", "Status", "Size", "Snapshot URL",
                       title=f"[bold]📸 {len(snaps)} Snapshots[/bold]",
                       box=box.SIMPLE_HEAD, header_style="bold cyan")
            for s in snaps:
                t2.add_row(
                    s.get("timestamp", "?"),
                    s.get("statuscode", "?"),
                    s.get("length", "?"),
                    s.get("snapshot_url", "?")[:60],
                )
            console.print(t2)

    # CommonCrawl
    with console.status("[cyan]Querying CommonCrawl index…"):
        cc_urls = _commoncrawl_search(domain, limit=30)
    findings["commoncrawl_count"] = len(cc_urls)
    if cc_urls:
        console.print(f"\n[bold]CommonCrawl:[/bold] [cyan]{len(cc_urls)}[/cyan] URLs indexed")
        # Find any not in Wayback
        wb_set = {e.get("original", "") for e in cdx_urls}
        cc_only = [e for e in cc_urls if e.get("url", "") not in wb_set]
        if cc_only:
            console.print(f"  [yellow]{len(cc_only)} URL(s) in CommonCrawl only (not in Wayback):[/yellow]")
            for e in cc_only[:5]:
                console.print(f"    [dim]{e.get('url', '?')[:80]}[/dim]")
    else:
        console.print("[dim]No CommonCrawl data found (index may not cover this domain).[/dim]")

    # Diff mode
    if diff and len(snaps if show_snapshots else []) >= 2:
        snaps_list = snaps if show_snapshots else []
        console.print(f"\n[bold]Diffing first and last snapshot…[/bold]")
        d = _diff_snapshots(url, snaps_list[-1]["timestamp"], snaps_list[0]["timestamp"])
        findings["diff"] = d
        console.print(f"  Size delta: [{('red' if d.get('significant_change') else 'green')}]{d.get('size_delta', 0):+,}[/] bytes")
        if d.get("snap1", {}).get("title"):
            console.print(f"  Oldest title: [dim]{d['snap1']['title']}[/dim]")
        if d.get("snap2", {}).get("title"):
            console.print(f"  Newest title: [dim]{d['snap2']['title']}[/dim]")

    # Summary
    console.print(f"\n[bold]Archive Summary:[/bold]")
    console.print(f"  Wayback URLs:     {len(cdx_urls)}")
    console.print(f"  CommonCrawl URLs: {len(cc_urls)}")
    if cdx_urls:
        cats = _extract_interesting_urls(cdx_urls)
        interesting = sum(len(v) for k, v in cats.items() if k != "other")
        console.print(f"  Interesting URLs: [{'yellow' if interesting else 'green'}]{interesting}[/]")

    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"archive_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
