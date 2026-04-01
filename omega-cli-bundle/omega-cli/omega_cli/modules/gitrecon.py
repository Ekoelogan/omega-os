"""GitHub OSINT — repos, exposed secrets, dorks, org recon."""
import re
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

console = Console()

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})", "API Key"),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})", "Secret Key"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})", "Password"),
    (r"(?i)(access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{16,})", "Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "Private Key"),
    (r"(?i)(discord[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{50,})", "Discord Token"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
    (r"(?i)(mongodb(\+srv)?://[^\s'\"<>]+)", "MongoDB URI"),
    (r"(?i)(postgres|postgresql)://[^\s'\"<>]+", "Postgres URI"),
]


def _github_headers(token: str = "") -> dict:
    h = {"Accept": "application/vnd.github.v3+json"}
    if token:
        h["Authorization"] = f"token {token}"
    return h


def _search_code(query: str, token: str = "") -> list:
    try:
        r = requests.get(
            "https://api.github.com/search/code",
            params={"q": query, "per_page": 30},
            headers=_github_headers(token), timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("items", [])
        elif r.status_code == 403:
            console.print("[yellow]GitHub rate limit — set token:[/] [cyan]omega config set github_token TOKEN[/]")
    except Exception as e:
        console.print(f"[red]GitHub search error:[/] {e}")
    return []


def _get_org(org: str, token: str = "") -> dict:
    r = requests.get(
        f"https://api.github.com/orgs/{org}",
        headers=_github_headers(token), timeout=10,
    )
    return r.json() if r.status_code == 200 else {}


def _get_repos(org: str, token: str = "") -> list:
    repos = []
    page = 1
    while len(repos) < 100:
        r = requests.get(
            f"https://api.github.com/orgs/{org}/repos",
            params={"per_page": 100, "page": page, "sort": "updated"},
            headers=_github_headers(token), timeout=15,
        )
        if r.status_code != 200 or not r.json():
            break
        repos.extend(r.json())
        page += 1
        if len(r.json()) < 100:
            break
    return repos


def _scan_file_for_secrets(raw_url: str) -> list:
    found = []
    try:
        r = requests.get(raw_url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        content = r.text[:50000]
        for pattern, label in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            for m in matches:
                val = m if isinstance(m, str) else (m[-1] if m else "")
                if len(val) > 4:
                    found.append({"type": label, "value": val[:80], "url": raw_url})
    except Exception:
        pass
    return found


def run(target: str, token: str = "", deep: bool = False):
    """Run GitHub OSINT on an org, user, or domain."""
    console.print(Panel(
        f"[bold #ff2d78]🐙 GitHub OSINT[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    results = {"target": target, "repos": [], "secrets": [], "dork_hits": []}

    # Org/user profile
    console.print("[dim]  Fetching org/user profile...[/]")
    org_data = _get_org(target, token)
    if not org_data:
        r = requests.get(f"https://api.github.com/users/{target}",
                         headers=_github_headers(token), timeout=10)
        org_data = r.json() if r.status_code == 200 else {}

    if org_data and "login" in org_data:
        tree = Tree(f"[bold #ff2d78]{org_data.get('login','')}[/]  [dim]{org_data.get('type','')}[/]",
                    guide_style="dim #ff85b3")
        tree.add(f"[dim]Name:[/]       {org_data.get('name','')}")
        tree.add(f"[dim]Bio:[/]        {str(org_data.get('bio',''))[:80]}")
        tree.add(f"[dim]Location:[/]   {org_data.get('location','')}")
        tree.add(f"[dim]Email:[/]      [cyan]{org_data.get('email','') or 'not public'}[/]")
        tree.add(f"[dim]Public repos:[/] [yellow]{org_data.get('public_repos',0)}[/]")
        tree.add(f"[dim]Followers:[/]  {org_data.get('followers',0)}")
        tree.add(f"[dim]Created:[/]    {str(org_data.get('created_at',''))[:10]}")
        console.print(tree)

    # Repo listing
    console.print("[dim]  Fetching repositories...[/]")
    repos = _get_repos(target, token)
    if not repos:
        r = requests.get(f"https://api.github.com/users/{target}/repos",
                         params={"per_page": 100, "sort": "updated"},
                         headers=_github_headers(token), timeout=15)
        repos = r.json() if r.status_code == 200 else []

    if repos and isinstance(repos, list) and repos and "full_name" in repos[0]:
        results["repos"] = [r["full_name"] for r in repos]
        tbl = Table(
            title=f"Repositories ({len(repos)})",
            box=box.ROUNDED, border_style="#ff85b3",
        )
        tbl.add_column("Repo", style="cyan")
        tbl.add_column("⭐", width=6)
        tbl.add_column("Lang", width=12)
        tbl.add_column("Updated", width=12)
        tbl.add_column("Description")
        for repo in repos[:20]:
            tbl.add_row(
                repo.get("name", ""),
                str(repo.get("stargazers_count", 0)),
                repo.get("language", "") or "",
                str(repo.get("updated_at", ""))[:10],
                (repo.get("description") or "")[:60],
            )
        if len(repos) > 20:
            tbl.add_row(f"[dim]+{len(repos)-20} more[/]", "", "", "", "")
        console.print(tbl)

    # Dork searches for secrets
    dorks = [
        f'org:{target} password',
        f'org:{target} secret',
        f'org:{target} api_key',
        f'org:{target} token',
        f'org:{target} AWS_ACCESS_KEY',
        f'org:{target} .env',
        f'org:{target} private_key',
    ]

    console.print("[dim]  Searching for exposed secrets (dorks)...[/]")
    secret_hits = []
    for dork in dorks:
        items = _search_code(dork, token)
        for item in items:
            raw = item.get("html_url", "").replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")
            if deep and raw:
                secrets = _scan_file_for_secrets(raw)
                for s in secrets:
                    secret_hits.append(s)
                    results["secrets"].append(s)
            else:
                results["dork_hits"].append({
                    "dork": dork,
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "file": item.get("name", ""),
                    "url": item.get("html_url", ""),
                })

    if results["dork_hits"]:
        dtbl = Table(
            title=f"[bold red]⚠  Potential Secret Exposures ({len(results['dork_hits'])})[/]",
            box=box.ROUNDED, border_style="red",
        )
        dtbl.add_column("Repo", style="cyan")
        dtbl.add_column("File", style="yellow")
        dtbl.add_column("Dork Match")
        dtbl.add_column("URL", style="dim")
        for hit in results["dork_hits"][:20]:
            dtbl.add_row(
                hit["repo"], hit["file"],
                hit["dork"].split()[-1],
                hit["url"][:80],
            )
        console.print(dtbl)
        if not deep:
            console.print("[dim]  Tip: add --deep to scan file contents for actual secret values[/]")

    if secret_hits:
        stbl = Table(
            title=f"[bold red]🚨 Confirmed Secrets ({len(secret_hits)})[/]",
            box=box.ROUNDED, border_style="red",
        )
        stbl.add_column("Type", style="bold red")
        stbl.add_column("Value (truncated)", style="yellow")
        stbl.add_column("File", style="dim")
        for s in secret_hits[:20]:
            stbl.add_row(s["type"], s["value"], s["url"].split("/")[-1])
        console.print(stbl)

    console.print(f"\n[bold]Summary:[/] [cyan]{len(repos)}[/] repos  "
                  f"[red]{len(results['dork_hits'])}[/] dork hits  "
                  f"[bold red]{len(results['secrets'])}[/] confirmed secrets")
    return results
