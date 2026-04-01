"""pastewatch.py — Pastebin/Gist monitor: search GitHub Gists and paste sites for target mentions."""
from __future__ import annotations
import json, re, time
from pathlib import Path
from typing import Optional
import urllib.request, urllib.error
import urllib.parse

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
  OMEGA-CLI v1.8.0 — OSINT & Passive Recon Toolkit
"""

UA = "Mozilla/5.0 (compatible; OmegaCLI/1.8.0)"

# Patterns that suggest sensitive leakage
SENSITIVE_PATTERNS = re.compile(
    r"(password|passwd|secret|api[_\-]?key|token|credential|private[_\-]?key|"
    r"access[_\-]?key|auth|bearer|BEGIN (RSA|EC|OPENSSH|PGP)|"
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|"
    r"-----BEGIN CERTIFICATE-----|db_password|database_url|jdbc:|mongodb://|redis://)",
    re.I
)


def _get(url: str, headers: Optional[dict] = None, timeout: int = 10) -> Optional[str]:
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(200_000).decode("utf-8", errors="replace")
    except Exception:
        return None


def _search_github_gists(query: str, token: str = "") -> list[dict]:
    """Search GitHub Gists via GitHub code search API."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    q = urllib.parse.quote(f"{query} language:text")
    body = _get(f"https://api.github.com/search/code?q={q}&per_page=20", headers=headers)
    results = []
    if not body:
        return results
    try:
        data = json.loads(body)
        for item in data.get("items", []):
            if "gist.github.com" in item.get("html_url", "") or item.get("repository", {}).get("fork") is False:
                results.append({
                    "source": "GitHub Gist",
                    "url":    item.get("html_url", ""),
                    "name":   item.get("name", ""),
                    "repo":   item.get("repository", {}).get("full_name", ""),
                })
        # Also plain GitHub code results
        for item in data.get("items", [])[:10]:
            results.append({
                "source": "GitHub Code",
                "url":    item.get("html_url", ""),
                "name":   item.get("name", ""),
                "repo":   item.get("repository", {}).get("full_name", ""),
            })
    except Exception:
        pass
    return results


def _search_github_commits(query: str, token: str = "") -> list[dict]:
    """Search GitHub commit messages for target mentions."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    q = urllib.parse.quote(query)
    body = _get(f"https://api.github.com/search/commits?q={q}&per_page=10", headers=headers)
    results = []
    if not body:
        return results
    try:
        data = json.loads(body)
        for item in data.get("items", []):
            results.append({
                "source":  "GitHub Commit",
                "url":     item.get("html_url", ""),
                "message": item.get("commit", {}).get("message", "")[:200],
                "author":  item.get("commit", {}).get("author", {}).get("name", ""),
                "date":    item.get("commit", {}).get("author", {}).get("date", ""),
                "repo":    item.get("repository", {}).get("full_name", ""),
            })
    except Exception:
        pass
    return results


def _search_psbdmp(query: str) -> list[dict]:
    """Search psbdmp.cc — public Pastebin dump search (no key needed)."""
    q = urllib.parse.quote(query)
    body = _get(f"https://psbdmp.cc/api/search/{q}")
    results = []
    if not body:
        return results
    try:
        data = json.loads(body)
        for item in (data.get("data") or [])[:10]:
            pid = item.get("id", "")
            results.append({
                "source": "Pastebin (psbdmp)",
                "url":    f"https://pastebin.com/{pid}",
                "id":     pid,
                "tags":   ", ".join(item.get("tags", [])),
                "date":   item.get("time", ""),
            })
    except Exception:
        pass
    return results


def _search_grep_app(query: str) -> list[dict]:
    """Search grep.app — searches across public GitHub repos."""
    q = urllib.parse.quote(query)
    body = _get(f"https://grep.app/api/search?q={q}&case=false&limit=10")
    results = []
    if not body:
        return results
    try:
        data = json.loads(body)
        for hit in (data.get("hits", {}).get("hits", []))[:10]:
            src = hit.get("_source", {})
            results.append({
                "source": "grep.app (GitHub)",
                "url":    f"https://github.com/{src.get('repo', {}).get('raw', '')}/blob/{src.get('branch', {}).get('raw', 'main')}/{src.get('path', {}).get('raw', '')}",
                "repo":   src.get("repo", {}).get("raw", ""),
                "path":   src.get("path", {}).get("raw", ""),
                "line":   (src.get("content", {}).get("snippet", ""))[:200],
            })
    except Exception:
        pass
    return results


def _fetch_and_check(url: str, target: str) -> Optional[str]:
    """Fetch a paste and check if it contains sensitive patterns + target mention."""
    body = _get(url)
    if not body:
        return None
    has_target = target.lower() in body.lower()
    has_sensitive = bool(SENSITIVE_PATTERNS.search(body))
    if has_target and has_sensitive:
        # Extract a context snippet
        idx = body.lower().find(target.lower())
        return body[max(0, idx-100):idx+200].strip()
    return None


def run(target: str, github_token: str = "", deep: bool = False, export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"📋  Paste Watcher — {target}", style="bold cyan"))

    results = {
        "target": target,
        "hits": [],
        "sensitive_matches": [],
    }

    all_hits = []

    # GitHub Gists + Code Search
    console.print("[bold]GitHub Gist / Code search...[/bold]")
    gh_hits = _search_github_gists(target, token=github_token)
    all_hits.extend(gh_hits)
    console.print(f"  GitHub code/gist: [cyan]{len(gh_hits)} hits[/cyan]")

    # GitHub Commits
    console.print("[bold]GitHub commit search...[/bold]")
    commit_hits = _search_github_commits(target, token=github_token)
    all_hits.extend(commit_hits)
    console.print(f"  GitHub commits: [cyan]{len(commit_hits)} hits[/cyan]")

    # Pastebin via psbdmp
    console.print("[bold]Pastebin search (psbdmp)...[/bold]")
    pb_hits = _search_psbdmp(target)
    all_hits.extend(pb_hits)
    console.print(f"  Pastebin: [cyan]{len(pb_hits)} hits[/cyan]")

    # grep.app
    console.print("[bold]grep.app (public repos)...[/bold]")
    grep_hits = _search_grep_app(target)
    all_hits.extend(grep_hits)
    console.print(f"  grep.app: [cyan]{len(grep_hits)} hits[/cyan]")

    results["hits"] = all_hits

    if all_hits:
        t = Table(title=f"📋 Paste/Code Mentions ({len(all_hits)})", box=box.SIMPLE if box else None)
        t.add_column("Source",  style="cyan", min_width=20)
        t.add_column("URL",     style="dim",  max_width=60)
        t.add_column("Details", style="dim",  max_width=40)

        for hit in all_hits[:30]:
            details = hit.get("message") or hit.get("line") or hit.get("tags") or hit.get("repo") or ""
            t.add_row(hit["source"], hit["url"][:60], str(details)[:40])
        console.print(t)

        # Deep check for secrets
        if deep:
            console.print("\n[bold]Checking for sensitive content (deep)...[/bold]")
            for hit in all_hits[:10]:
                url = hit.get("url", "")
                if not url:
                    continue
                snippet = _fetch_and_check(url, target)
                if snippet:
                    results["sensitive_matches"].append({"url": url, "snippet": snippet[:300]})
                    console.print(f"  [red bold]⚠ SENSITIVE: {url}[/red bold]")
                    console.print(f"  [dim]{snippet[:150]}[/dim]")
                time.sleep(0.5)
    else:
        console.print("[green]✅ No paste/code mentions found[/green]")

    console.print(f"\n[bold]Summary:[/bold] {len(all_hits)} total hits | "
                  f"{len(results['sensitive_matches'])} with potential secrets")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", target)
    out_path = Path(export) if export else out_dir / f"pastewatch_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
