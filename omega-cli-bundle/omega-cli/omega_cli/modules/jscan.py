"""JavaScript file analyzer — extract endpoints, API keys, secrets."""
import httpx
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

console = Console()

# Regex patterns for secrets and interesting strings
SECRET_PATTERNS = [
    ("AWS Access Key",    r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret Key",    r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]'),
    ("Google API Key",    r'AIza[0-9A-Za-z\-_]{35}'),
    ("GitHub Token",      r'ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}'),
    ("Slack Token",       r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),
    ("Stripe Key",        r'(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}'),
    ("Private Key",       r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    ("JWT Token",         r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
    ("Bearer Token",      r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}'),
    ("Basic Auth",        r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}'),
    ("Password in JS",    r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{6,}[\'"]'),
    ("API Key pattern",   r'(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]'),
    ("Hardcoded IP",      r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b'),
]

ENDPOINT_PATTERNS = [
    r'[\'"`](/[a-zA-Z0-9_\-/]+(?:\.[a-zA-Z0-9]+)?)[\'"`]',
    r'(?:url|endpoint|path|route|api)\s*[:=]\s*[\'"`]([^\'"`\s]{5,})[\'"`]',
    r'fetch\s*\([\'"`]([^\'"`]+)[\'"`]',
    r'axios\.[a-z]+\s*\([\'"`]([^\'"`]+)[\'"`]',
    r'(?:get|post|put|delete|patch)\s*\([\'"`]([^\'"`]+)[\'"`]',
]


def _get_js_files(url: str, html: str, base: str) -> list:
    soup = BeautifulSoup(html, "lxml")
    scripts = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        full = urljoin(base, src)
        if urlparse(full).netloc in ("", urlparse(base).netloc):
            scripts.append(full)
    return scripts[:20]  # cap at 20 JS files


def run(target: str):
    """Scrape and analyze JavaScript files for endpoints and secrets."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    base = f"{urlparse(target).scheme}://{urlparse(target).netloc}"

    console.print(f"\n[bold cyan][ JS ANALYZER ] {target}[/bold cyan]\n")

    try:
        with httpx.Client(follow_redirects=True, timeout=10,
                          headers={"User-Agent": "Mozilla/5.0 (omega-cli)"}) as client:
            r = client.get(target)
            js_urls = _get_js_files(target, r.text, base)

        console.print(f"[dim]Found {len(js_urls)} same-origin JS file(s)[/dim]\n")

        all_secrets = []
        all_endpoints = set()

        for js_url in js_urls:
            try:
                with httpx.Client(timeout=8, headers={"User-Agent": "Mozilla/5.0 (omega-cli)"}) as client:
                    js_r = client.get(js_url)
                content = js_r.text
                size_kb = len(content) // 1024

                # Secrets scan
                for name, pattern in SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    for m in matches:
                        all_secrets.append((js_url, name, m[:80]))

                # Endpoint extraction
                for pattern in ENDPOINT_PATTERNS:
                    for m in re.findall(pattern, content):
                        if len(m) > 4 and not m.startswith("//"):
                            all_endpoints.add(m[:100])

                console.print(f"  [dim]✓ {js_url} ({size_kb}kb)[/dim]")
            except Exception:
                pass

        console.print()

        if all_secrets:
            st = Table(title=f"[bold red]⚠ Potential Secrets Found ({len(all_secrets)})[/bold red]")
            st.add_column("JS File", style="dim", max_width=40)
            st.add_column("Type", style="bold red")
            st.add_column("Match", style="yellow", max_width=60)
            for js_url, name, match in all_secrets[:30]:
                fname = js_url.split("/")[-1]
                st.add_row(fname, name, match)
            console.print(st)
            console.print()
        else:
            console.print("[green]✓ No obvious secrets detected in JS files[/green]\n")

        if all_endpoints:
            api_endpoints = sorted(e for e in all_endpoints if e.startswith("/api") or "/v1/" in e or "/v2/" in e)
            other_endpoints = sorted(e for e in all_endpoints if e not in api_endpoints)

            if api_endpoints:
                at = Table(title=f"API Endpoints ({len(api_endpoints)})", show_header=False, box=None, padding=(0, 2))
                at.add_column("Endpoint", style="green")
                for ep in api_endpoints[:30]:
                    at.add_row(ep)
                console.print(at)
                console.print()

            if other_endpoints:
                ot = Table(title=f"Other Paths ({len(other_endpoints)})", show_header=False, box=None, padding=(0, 2))
                ot.add_column("Path", style="cyan")
                for ep in other_endpoints[:20]:
                    ot.add_row(ep)
                console.print(ot)

        return {"secrets": all_secrets, "endpoints": list(all_endpoints)}

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        return {}
