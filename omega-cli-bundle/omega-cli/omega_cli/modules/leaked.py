"""omega leaked — Leaked data aggregator: pastes, breach repos, pivot chains."""
from __future__ import annotations
import json, re, hashlib
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()
TIMEOUT = 10


def _sha1(value: str) -> str:
    return hashlib.sha1(value.encode()).hexdigest().upper()


def _md5(value: str) -> str:
    return hashlib.md5(value.encode()).hexdigest()


def _hibp_email(email: str, api_key: str = "") -> list[dict]:
    """Have I Been Pwned — email breach lookup."""
    headers = {"User-Agent": "omega-cli-osint", "hibp-api-key": api_key}
    try:
        r = httpx.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers, timeout=TIMEOUT,
            params={"truncateResponse": "false"}
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return []
    except Exception:
        pass
    return []


def _hibp_password(password: str) -> dict:
    """k-anonymity password check via HIBP range API."""
    sha = _sha1(password)
    prefix, suffix = sha[:5], sha[5:]
    try:
        r = httpx.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=TIMEOUT)
        if r.status_code == 200:
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return {"pwned": True, "count": int(count), "hash": sha}
            return {"pwned": False, "count": 0, "hash": sha}
    except Exception:
        pass
    return {"pwned": False, "count": 0, "hash": sha}


def _pastebin_search(query: str) -> list[dict]:
    """Search Pastebin Google dork via scraping metadata."""
    results = []
    try:
        r = httpx.get(
            "https://psbdmp.ws/api/v3/search",
            params={"q": query},
            timeout=TIMEOUT,
            headers={"User-Agent": "omega-cli"}
        )
        if r.status_code == 200:
            data = r.json()
            for item in (data.get("data") or [])[:10]:
                results.append({
                    "id": item.get("id"),
                    "title": item.get("title", "Untitled"),
                    "time": item.get("time"),
                    "url": f"https://pastebin.com/{item.get('id')}",
                })
    except Exception:
        pass
    return results


def _github_secret_search(query: str, token: str = "") -> list[dict]:
    """Search GitHub for leaked credentials matching query."""
    results = []
    headers: dict = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    search_terms = [
        f'"{query}" password',
        f'"{query}" secret',
        f'"{query}" api_key',
        f'"{query}" token',
    ]
    seen_urls = set()
    for term in search_terms[:2]:
        try:
            r = httpx.get(
                "https://api.github.com/search/code",
                headers=headers,
                params={"q": term, "per_page": 5},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                for item in r.json().get("items", [])[:5]:
                    url = item.get("html_url", "")
                    if url not in seen_urls:
                        seen_urls.add(url)
                        results.append({
                            "repo": item.get("repository", {}).get("full_name"),
                            "file": item.get("name"),
                            "url": url,
                            "term": term,
                        })
        except Exception:
            pass
    return results


def _intelx_search(query: str, api_key: str = "") -> list[dict]:
    """IntelligenceX search (if key provided)."""
    if not api_key:
        return []
    results = []
    try:
        r = httpx.post(
            "https://2.intelx.io/phonebook/search",
            headers={"x-key": api_key},
            json={"term": query, "maxresults": 20, "media": 0, "target": 0, "timeout": 5},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            for s in (data.get("selectors") or [])[:15]:
                results.append({
                    "value": s.get("selectvalue"),
                    "type": s.get("selectortype"),
                })
    except Exception:
        pass
    return results


def _dehashed_search(query: str, email: str = "", api_key: str = "") -> list[dict]:
    """Dehashed API search (if creds provided)."""
    if not api_key or not email:
        return []
    results = []
    try:
        r = httpx.get(
            "https://api.dehashed.com/search",
            auth=(email, api_key),
            params={"query": query, "size": 10},
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            for entry in (r.json().get("entries") or [])[:10]:
                results.append({
                    "email": entry.get("email"),
                    "username": entry.get("username"),
                    "password": entry.get("password", "[redacted]"),
                    "database": entry.get("database_name"),
                    "ip": entry.get("ip_address"),
                })
    except Exception:
        pass
    return results


def _classify_target(target: str) -> str:
    if re.match(r"^[a-fA-F0-9]{32}$", target):
        return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", target):
        return "sha1"
    if "@" in target:
        return "email"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    return "username"


def run(
    target: str,
    check_password: bool = False,
    hibp_key: str = "",
    github_token: str = "",
    intelx_key: str = "",
    dehashed_email: str = "",
    dehashed_key: str = "",
):
    target_type = _classify_target(target)
    console.print(Panel(
        f"[bold #ff2d78]💧  Leaked Data Search[/bold #ff2d78] — [cyan]{target}[/cyan] [dim]({target_type})[/dim]",
        box=box.ROUNDED
    ))

    findings: dict[str, Any] = {"target": target, "type": target_type}

    # HIBP breach check (email)
    if target_type == "email":
        with console.status("[cyan]Checking Have I Been Pwned…"):
            breaches = _hibp_email(target, hibp_key)
        findings["hibp_breaches"] = breaches
        if breaches:
            t = Table("Breach", "Domain", "Date", "Pwn Count",
                      title=f"[bold red]💥  {len(breaches)} HIBP Breach(es)[/bold red]",
                      box=box.SIMPLE_HEAD, header_style="bold red")
            for b in sorted(breaches, key=lambda x: x.get("BreachDate", ""), reverse=True):
                t.add_row(
                    b.get("Name", "?"),
                    b.get("Domain", "?"),
                    b.get("BreachDate", "?"),
                    f"{b.get('PwnCount', 0):,}",
                )
            console.print(t)
        else:
            console.print("[green]✓  No HIBP breaches found.[/green]")

    # Password check
    if check_password:
        with console.status("[cyan]Checking password exposure (k-anonymity)…"):
            pw_result = _hibp_password(target)
        findings["password_pwned"] = pw_result
        if pw_result["pwned"]:
            console.print(f"[bold red]⚠  Password PWNED — seen {pw_result['count']:,} times in breaches![/bold red]")
        else:
            console.print("[green]✓  Password not found in known breach databases.[/green]")

    # Pastebin search
    with console.status("[cyan]Searching paste databases…"):
        pastes = _pastebin_search(target)
    findings["pastes"] = pastes
    if pastes:
        t2 = Table("Paste ID", "Title", "URL",
                   title=f"[bold yellow]📋  {len(pastes)} Paste(s) Found[/bold yellow]",
                   box=box.SIMPLE_HEAD, header_style="bold yellow")
        for p in pastes:
            t2.add_row(p.get("id", "?"), p.get("title", "?")[:50], p.get("url", "?"))
        console.print(t2)
    else:
        console.print("[dim]No pastes found via public aggregator.[/dim]")

    # GitHub secret search
    with console.status("[cyan]Searching GitHub for exposed credentials…"):
        gh_results = _github_secret_search(target, github_token)
    findings["github_leaks"] = gh_results
    if gh_results:
        t3 = Table("Repo", "File", "URL",
                   title=f"[bold red]🐙  {len(gh_results)} GitHub Leak(s)[/bold red]",
                   box=box.SIMPLE_HEAD, header_style="bold red")
        for g in gh_results:
            t3.add_row(g.get("repo", "?"), g.get("file", "?"), g.get("url", "?")[:80])
        console.print(t3)
    else:
        console.print("[dim]No GitHub leaks found.[/dim]")

    # IntelX
    if intelx_key:
        with console.status("[cyan]Querying IntelligenceX…"):
            ix = _intelx_search(target, intelx_key)
        findings["intelx"] = ix
        if ix:
            console.print(f"[bold]IntelX — {len(ix)} selector(s):[/bold]")
            for s in ix[:10]:
                console.print(f"  [cyan]{s.get('type', '?')}[/cyan]: {s.get('value', '?')}")

    # Dehashed
    if dehashed_key and dehashed_email:
        with console.status("[cyan]Querying Dehashed…"):
            dh = _dehashed_search(target, dehashed_email, dehashed_key)
        findings["dehashed"] = dh
        if dh:
            t4 = Table("Email", "Username", "Password", "Database",
                       title=f"[bold red]🔓  {len(dh)} Dehashed Record(s)[/bold red]",
                       box=box.SIMPLE_HEAD, header_style="bold red")
            for d in dh:
                t4.add_row(d.get("email", "?"), d.get("username", "?"),
                           d.get("password", "[redacted]"), d.get("database", "?"))
            console.print(t4)

    # Summary
    total_hits = (len(findings.get("hibp_breaches", [])) +
                  len(pastes) + len(gh_results) +
                  len(findings.get("intelx", [])) +
                  len(findings.get("dehashed", [])))
    risk = "CRITICAL" if total_hits > 5 else "HIGH" if total_hits > 2 else "MEDIUM" if total_hits > 0 else "LOW"
    color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[risk]
    console.print(f"\n[bold]Total exposure hits:[/bold] [{color}]{total_hits}[/{color}]  "
                  f"[bold]Risk:[/bold] [{color}]{risk}[/{color}]")

    import os, datetime
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"leaked_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"[dim]Saved → {out_file}[/dim]")
