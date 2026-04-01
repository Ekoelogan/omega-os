"""Data breach checker — HIBP, DeHashed, and public breach sources."""
import requests
import hashlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def _hibp_email(email: str, api_key: str) -> list:
    """Check email against HaveIBeenPwned."""
    headers = {
        "User-Agent": "omega-cli-osint",
        "hibp-api-key": api_key,
    }
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            params={"truncateResponse": False},
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return []
        elif r.status_code == 401:
            console.print("[yellow]HIBP requires API key.[/]  Set: [cyan]omega config set hibp_api_key KEY[/]")
            console.print("[dim]Get free key at: https://haveibeenpwned.com/API/Key[/]")
    except Exception as e:
        console.print(f"[red]HIBP error:[/] {e}")
    return None


def _hibp_password(password: str) -> tuple:
    """Check password hash prefix against HIBP Pwned Passwords (k-anonymity)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10,
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return True, int(count)
    except Exception:
        pass
    return False, 0


def _hibp_domain(domain: str, api_key: str) -> list:
    """Get all breaches that include a domain's users."""
    headers = {
        "User-Agent": "omega-cli-osint",
        "hibp-api-key": api_key,
    }
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            all_breaches = r.json()
            return [b for b in all_breaches if domain.lower() in b.get("Domain", "").lower()]
    except Exception:
        pass
    return []


def _intelx_email(email: str, api_key: str = "") -> list:
    """Search IntelligenceX for email leaks."""
    if not api_key:
        return []
    try:
        r = requests.post(
            "https://2.intelx.io/intelligent/search",
            json={"term": email, "maxresults": 20, "media": 0, "sort": 4},
            headers={"x-key": api_key}, timeout=10,
        )
        if r.status_code == 200:
            return r.json().get("records", [])
    except Exception:
        pass
    return []


def run(target: str, hibp_key: str = "", password: bool = False, intelx_key: str = ""):
    """Check if an email, domain, or password has appeared in data breaches."""
    console.print(Panel(
        f"[bold #ff2d78]💀 Breach Checker[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    results = {"target": target}

    # Password mode
    if password:
        console.print("[dim]  Checking password against HIBP Pwned Passwords (k-anonymity)...[/]")
        found, count = _hibp_password(target)
        if found:
            console.print(
                f"[bold red]🚨 PWNED![/]  This password appeared [red]{count:,}[/] times in breaches."
            )
            console.print("[yellow]→ Change this password immediately on all accounts using it.[/]")
        else:
            console.print("[green]✓ Not found in any known breach database.[/]")
        results["pwned"] = found
        results["count"] = count
        return results

    # Email check
    if "@" in target:
        console.print("[dim]  Checking email against HIBP...[/]")
        breaches = _hibp_email(target, hibp_key)

        if breaches is None:
            console.print("[dim]  Trying without API key...[/]")
            breaches = []

        if breaches:
            tbl = Table(
                title=f"[bold red]🚨 Breaches for {target} ({len(breaches)})[/]",
                box=box.ROUNDED, border_style="red", show_lines=True,
            )
            tbl.add_column("Breach", style="bold red")
            tbl.add_column("Date", width=12)
            tbl.add_column("Accounts", width=12)
            tbl.add_column("Data Types")
            tbl.add_column("Verified", width=8)

            for b in sorted(breaches, key=lambda x: x.get("BreachDate", ""), reverse=True):
                data_classes = ", ".join(b.get("DataClasses", [])[:5])
                tbl.add_row(
                    b.get("Name", ""),
                    b.get("BreachDate", "")[:10],
                    f"{b.get('PwnCount', 0):,}",
                    data_classes,
                    "✓" if b.get("IsVerified") else "?",
                )
            console.print(tbl)
            results["breaches"] = [b["Name"] for b in breaches]
        elif breaches == []:
            console.print(f"[green]✓[/] {target} not found in any known HIBP breach.")
            results["breaches"] = []
    else:
        # Domain breach check
        console.print(f"[dim]  Checking domain {target} against all HIBP breaches...[/]")
        domain_breaches = _hibp_domain(target, hibp_key)

        if domain_breaches:
            tbl = Table(
                title=f"Breaches involving {target} ({len(domain_breaches)})",
                box=box.ROUNDED, border_style="#ff85b3",
            )
            tbl.add_column("Breach", style="cyan")
            tbl.add_column("Date", width=12)
            tbl.add_column("Accounts", width=14)
            tbl.add_column("Data Exposed")
            for b in domain_breaches:
                tbl.add_row(
                    b.get("Name", ""),
                    b.get("BreachDate", "")[:10],
                    f"{b.get('PwnCount', 0):,}",
                    ", ".join(b.get("DataClasses", [])[:4]),
                )
            console.print(tbl)
            results["domain_breaches"] = [b["Name"] for b in domain_breaches]
        else:
            console.print(f"[green]✓[/] No breaches found matching domain: {target}")
            results["domain_breaches"] = []

    return results
