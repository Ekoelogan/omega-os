"""Subdomain enumeration module (passive, wordlist-based)."""
import threading
import dns.resolver
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote", "blog",
    "dev", "staging", "test", "api", "cdn", "static", "assets", "img", "images",
    "media", "upload", "admin", "portal", "vpn", "ns1", "ns2", "mx", "shop",
    "store", "app", "dashboard", "login", "auth", "sso", "id", "support",
    "help", "docs", "status", "monitor", "git", "gitlab", "github", "jira",
    "confluence", "wiki", "chat", "slack", "m", "mobile", "news", "beta",
    "demo", "sandbox", "db", "database", "backup", "old", "new", "legacy",
    "secure", "ssl", "intranet", "extranet", "corp", "internal", "external",
    "hub", "cloud", "data", "analytics", "metrics", "logs", "reporting",
    "ci", "cd", "jenkins", "build", "deploy", "k8s", "kube", "docker",
]


def _check_subdomain(sub: str, domain: str, found: list, lock: threading.Lock):
    host = f"{sub}.{domain}"
    try:
        dns.resolver.resolve(host, "A", lifetime=2)
        with lock:
            found.append(host)
            console.print(f"  [green]✓[/green] {host}")
    except Exception:
        pass


def run(target: str, wordlist: str = None):
    """Enumerate subdomains via DNS brute-force."""
    console.print(f"\n[bold cyan][ SUBDOMAIN ENUM ] {target}[/bold cyan]\n")

    subs = COMMON_SUBDOMAINS
    if wordlist:
        try:
            with open(wordlist) as f:
                subs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[yellow]Wordlist not found, using built-in list.[/yellow]")

    found = []
    lock = threading.Lock()
    threads = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task(f"Checking {len(subs)} subdomains...", total=None)
        for sub in subs:
            t = threading.Thread(target=_check_subdomain, args=(sub, target, found, lock))
            threads.append(t)
            t.start()
            # cap concurrency at 50
            if len([t for t in threads if t.is_alive()]) >= 50:
                for t in threads:
                    t.join(timeout=0.1)

        for t in threads:
            t.join()

    console.print(f"\n[bold]Found {len(found)} subdomain(s).[/bold]")
