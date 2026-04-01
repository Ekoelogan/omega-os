"""omega creds — Credential exposure: GitHub secret scan + paste-site search + keyword lookup."""
from __future__ import annotations
import re
import time
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

GITHUB_SEARCH = "https://api.github.com/search/code"
PASTEBIN_SEARCH = "https://psbdmp.ws/api/v3/search/{keyword}"
DEHASHED_API    = "https://api.dehashed.com/search"

# Regex patterns for secret detection in GitHub code results
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Key":      re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    "Private Key":  re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----"),
    "Password":     re.compile(r"""(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{6,})""", re.I),
    "API Token":    re.compile(r"""(?:api[_-]?key|token|secret)\s*[=:]\s*['"]([^'"]{8,})""", re.I),
    "DB Conn":      re.compile(r"(?:mysql|postgres|mongodb)://[^\s\"']{10,}", re.I),
    "Slack Token":  re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}", re.I),
    "GH Token":     re.compile(r"gh[pousr]_[A-Za-z0-9]{36}", re.I),
}

DORK_TEMPLATES = [
    '"{target}" password',
    '"{target}" api_key',
    '"{target}" secret',
    '"{target}" credentials',
    '"{target}" .env',
    '"{target}" config.yml password',
]


def _github_search(keyword: str, token: str = "") -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    findings: list[dict] = []
    for tpl in DORK_TEMPLATES[:3]:  # respect rate limit
        q = tpl.format(target=keyword)
        try:
            r = requests.get(GITHUB_SEARCH,
                             params={"q": q, "per_page": 10},
                             headers=headers, timeout=12)
            if r.status_code == 403:
                console.print("[yellow]GitHub rate limit hit. Set token with: omega config set github_token TOKEN[/yellow]")
                break
            r.raise_for_status()
            items = r.json().get("items", [])
            for item in items:
                # Check raw content for secrets
                raw_url = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com")\
                              .replace("/blob/", "/")
                raw_content = ""
                try:
                    rc = requests.get(raw_url, headers=headers, timeout=8)
                    if rc.ok:
                        raw_content = rc.text[:4000]
                except Exception:
                    pass

                detected = []
                for sname, spat in SECRET_PATTERNS.items():
                    if spat.search(raw_content):
                        detected.append(sname)

                findings.append({
                    "repo":     item.get("repository", {}).get("full_name", "—"),
                    "file":     item.get("name", "—"),
                    "url":      item.get("html_url", "—"),
                    "secrets":  detected,
                })
            time.sleep(0.4)  # be nice to GitHub API
        except Exception as exc:
            console.print(f"[yellow]GitHub search error:[/yellow] {exc}")
    return findings


def _pastebin_search(keyword: str) -> list[dict]:
    """Search psbdmp (Pastebin dump search) for keyword."""
    findings = []
    try:
        url = PASTEBIN_SEARCH.format(keyword=requests.utils.quote(keyword))
        r = requests.get(url, timeout=10, headers={"User-Agent": "omega-cli/0.9.0"})
        r.raise_for_status()
        data = r.json()
        for item in data.get("data", [])[:10]:
            findings.append({
                "id":   item.get("id", ""),
                "url":  f"https://pastebin.com/{item.get('id','')}",
                "date": item.get("time", ""),
                "tags": item.get("tags", ""),
            })
    except Exception as exc:
        console.print(f"[yellow]Pastebin search error:[/yellow] {exc}")
    return findings


def run(target: str, token: str = "", no_github: bool = False,
        no_paste: bool = False) -> None:
    console.print(Panel(
        f"[bold #ff2d78]🔐  Credential Exposure[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    # GitHub code search
    if not no_github:
        console.print("\n[bold]🐙 GitHub Secret Scan:[/bold]")
        findings = _github_search(target, token=token)
        if findings:
            tbl = Table(show_lines=True)
            tbl.add_column("Repository",  style="cyan",       max_width=30)
            tbl.add_column("File",        style="white",      max_width=20)
            tbl.add_column("Secrets",     style="bold #ff2d78", max_width=30)
            tbl.add_column("URL",         style="dim",        max_width=40)
            for f in findings:
                secs = ", ".join(f["secrets"]) if f["secrets"] else "[dim]none detected[/dim]"
                tbl.add_row(f["repo"], f["file"], secs, f["url"][-38:])
            console.print(tbl)
            console.print(f"[dim]{len(findings)} GitHub results scanned.[/dim]")
        else:
            console.print("[green]✓  No GitHub results found.[/green]")

    # Pastebin
    if not no_paste:
        console.print("\n[bold]📋 Pastebin Exposure:[/bold]")
        pastes = _pastebin_search(target)
        if pastes:
            tbl = Table(show_lines=True)
            tbl.add_column("Paste URL",   style="cyan")
            tbl.add_column("Date",        style="dim")
            tbl.add_column("Tags",        style="dim")
            for p in pastes:
                tbl.add_row(p["url"], str(p["date"]), str(p["tags"])[:30])
            console.print(tbl)
            console.print(f"[bold red]⚠  {len(pastes)} paste(s) found for '{target}'[/bold red]")
        else:
            console.print("[green]✓  No pastes found.[/green]")

    # Manual follow-up links
    console.print(f"\n[dim]Further manual checks:[/dim]")
    console.print(f"  https://github.com/search?q={requests.utils.quote(target)}&type=code")
    console.print(f"  https://haveibeenpwned.com/DomainSearch — domain breach check")
    console.print(f"  https://dehashed.com/search?query={requests.utils.quote(target)}")
    console.print(f"  https://intelx.io/?s={requests.utils.quote(target)}")
