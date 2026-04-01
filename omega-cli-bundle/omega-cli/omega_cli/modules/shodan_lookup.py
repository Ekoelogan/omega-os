"""Shodan.io integration — exposed services, banners, CVEs, open ports."""
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

console = Console()


def _shodan_host(ip: str, api_key: str) -> dict:
    r = requests.get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": api_key}, timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 401:
        console.print("[red]Invalid Shodan API key.[/]  Set: [cyan]omega config set shodan_api_key KEY[/]")
    elif r.status_code == 404:
        console.print(f"[yellow]No Shodan data for {ip}[/]")
    return {}


def _shodan_search(query: str, api_key: str, limit: int = 20) -> dict:
    r = requests.get(
        "https://api.shodan.io/shodan/host/search",
        params={"key": api_key, "query": query, "minify": False},
        timeout=15,
    )
    if r.status_code == 200:
        return r.json()
    elif r.status_code == 401:
        console.print("[red]Invalid Shodan API key.[/]")
    return {}


def _resolve_domain(domain: str) -> list:
    import socket
    try:
        infos = socket.getaddrinfo(domain, None)
        return list({i[4][0] for i in infos if "." in i[4][0]})
    except Exception:
        return []


def run_host(target: str, api_key: str):
    """Look up a specific host on Shodan."""
    import socket
    # Resolve if domain
    ip = target
    if not target.replace(".", "").isdigit():
        ips = _resolve_domain(target)
        if not ips:
            console.print(f"[red]Could not resolve {target}[/]")
            return {}
        ip = ips[0]
        console.print(f"[dim]  Resolved {target} → {ip}[/]")

    data = _shodan_host(ip, api_key)
    if not data:
        return {}

    # Header info
    tree = Tree(
        f"[bold #ff2d78]{ip}[/]  [dim]{data.get('org', '')}[/]",
        guide_style="dim #ff85b3",
    )
    tree.add(f"[dim]Hostnames:[/]  {', '.join(data.get('hostnames', [])) or 'none'}")
    tree.add(f"[dim]Country:[/]    {data.get('country_name', '')} ({data.get('country_code', '')})")
    tree.add(f"[dim]City:[/]       {data.get('city', '')}")
    tree.add(f"[dim]ISP:[/]        {data.get('isp', '')}")
    tree.add(f"[dim]ASN:[/]        {data.get('asn', '')}")
    tree.add(f"[dim]OS:[/]         {data.get('os', 'unknown')}")
    tree.add(f"[dim]Last update:[/] {str(data.get('last_update', ''))[:10]}")
    console.print(tree)

    # Open ports / services
    services = data.get("data", [])
    if services:
        tbl = Table(
            title=f"Open Services ({len(services)})",
            box=box.ROUNDED, border_style="#ff85b3", show_lines=True,
        )
        tbl.add_column("Port", width=8, style="cyan")
        tbl.add_column("Transport", width=6)
        tbl.add_column("Product")
        tbl.add_column("Version", width=14)
        tbl.add_column("Banner / Info")

        for svc in services:
            port = str(svc.get("port", ""))
            transport = svc.get("transport", "tcp")
            product = svc.get("product", "")
            version = svc.get("version", "")
            banner = (svc.get("data", "") or "").strip()[:120].replace("\n", " ")
            tbl.add_row(port, transport, product, version, banner)
        console.print(tbl)

    # CVEs
    vulns = data.get("vulns", [])
    if vulns:
        vtbl = Table(
            title=f"[bold red]🚨 CVEs Found ({len(vulns)})[/]",
            box=box.ROUNDED, border_style="red",
        )
        vtbl.add_column("CVE ID", style="bold red")
        for cve_id in sorted(vulns):
            vtbl.add_row(cve_id)
        console.print(vtbl)

    # Tags
    tags = data.get("tags", [])
    if tags:
        console.print(f"\n[bold]Tags:[/] " + "  ".join(f"[yellow]{t}[/]" for t in tags))

    return {
        "ip": ip,
        "org": data.get("org"),
        "ports": data.get("ports", []),
        "vulns": list(vulns),
        "os": data.get("os"),
        "country": data.get("country_code"),
        "services": len(services),
    }


def run_search(query: str, api_key: str, limit: int = 10):
    """Search Shodan with a custom query."""
    data = _shodan_search(query, api_key, limit)
    if not data:
        return {}

    total = data.get("total", 0)
    matches = data.get("matches", [])[:limit]

    console.print(f"[bold]Total results:[/] [cyan]{total:,}[/]")

    tbl = Table(
        title=f"Shodan Results: '{query}'",
        box=box.ROUNDED, border_style="#ff85b3", show_lines=True,
    )
    tbl.add_column("IP", style="cyan", width=16)
    tbl.add_column("Port", width=6)
    tbl.add_column("Org")
    tbl.add_column("Country", width=8)
    tbl.add_column("Product")
    tbl.add_column("Banner")

    for m in matches:
        tbl.add_row(
            m.get("ip_str", ""),
            str(m.get("port", "")),
            m.get("org", "")[:30],
            m.get("location", {}).get("country_code", ""),
            m.get("product", ""),
            (m.get("data", "") or "").strip()[:60].replace("\n", " "),
        )
    console.print(tbl)
    return {"query": query, "total": total, "results": matches}


def run(target: str, api_key: str, search: bool = False):
    """Run Shodan recon on a host or execute a search query."""
    console.print(Panel(
        f"[bold #ff2d78]👁 Shodan Intelligence[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))
    if not api_key:
        console.print("[red]Shodan API key required.[/]  Set: [cyan]omega config set shodan_api_key KEY[/]")
        console.print("[dim]Free key at: https://account.shodan.io/register[/]")
        return {}
    if search:
        return run_search(target, api_key)
    return run_host(target, api_key)
