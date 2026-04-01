"""torcheck.py — Tor exit node check, .onion address probe, Tor2Web, darknet mention scan."""
from __future__ import annotations
import json, re, socket
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

# Tor2Web gateways for .onion probing (no Tor client needed)
TOR2WEB_GATEWAYS = [
    "https://{onion}.tor2web.io/",
    "https://{onion}.tor2web.org/",
    "https://{onion}.onion.to/",
    "https://{onion}.onion.ws/",
    "https://{onion}.onion.pet/",
]

# Darknet search engines (clearnet front-ends)
AHMIA_SEARCH = "https://ahmia.fi/search/?q={query}"
ONIONLAND_SEARCH = "https://onionlandsearchengine.net/search?q={query}&engine=1"


def _get(url: str, timeout: int = 12) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(100_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _resolve_ip(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


def _check_tor_exit_list(ip: str) -> bool:
    """Check if IP is a Tor exit node using Tor Project's list."""
    status, body = _get("https://check.torproject.org/torbulkexitlist")
    if status == 200 and ip in body:
        return True
    # Also try Dan.me.uk
    status2, body2 = _get("https://www.dan.me.uk/torlist/?exit")
    if status2 == 200 and ip in body2:
        return True
    return False


def _check_onionoo(query: str) -> list[dict]:
    """Search Tor relay/bridge info via Onionoo API."""
    q = urllib.parse.quote(query)
    status, body = _get(f"https://onionoo.torproject.org/details?search={q}&limit=10")
    results = []
    if status == 200:
        try:
            data = json.loads(body)
            for relay in (data.get("relays") or [])[:10]:
                results.append({
                    "type":     "relay",
                    "nickname": relay.get("nickname"),
                    "fingerprint": relay.get("fingerprint"),
                    "addresses": relay.get("or_addresses", []),
                    "flags":    relay.get("flags", []),
                    "country":  relay.get("country_name"),
                    "bandwidth_rate": relay.get("bandwidth_rate"),
                    "exit_policy": relay.get("exit_policy_summary"),
                })
            for bridge in (data.get("bridges") or [])[:5]:
                results.append({
                    "type":      "bridge",
                    "nickname":  bridge.get("nickname"),
                    "fingerprint": bridge.get("fingerprint"),
                })
        except Exception:
            pass
    return results


def _probe_onion_tor2web(onion: str) -> dict:
    """Try to reach a .onion via Tor2Web gateways."""
    # Strip .onion suffix for gateway URL format
    base = onion.replace(".onion", "")
    for gw in TOR2WEB_GATEWAYS[:3]:
        url = gw.replace("{onion}", base)
        status, body = _get(url, timeout=10)
        if status in (200, 301, 302, 403):
            return {
                "reachable": True,
                "gateway":   url,
                "status":    status,
                "title":     re.search(r"<title[^>]*>([^<]{1,100})</title>", body, re.I).group(1) if re.search(r"<title", body, re.I) else "",
                "body_sample": body[:200],
            }
    return {"reachable": False}


def _search_ahmia(query: str) -> list[dict]:
    """Search Ahmia.fi darknet search engine."""
    url = AHMIA_SEARCH.format(query=urllib.parse.quote(query))
    status, body = _get(url)
    results = []
    if status != 200:
        return results
    # Extract .onion links from results
    onions = re.findall(r"([a-z2-7]{16,56}\.onion)", body)
    titles = re.findall(r'<h4[^>]*>(.*?)</h4>', body, re.S)
    descs  = re.findall(r'<p[^>]*class="[^"]*description[^"]*"[^>]*>(.*?)</p>', body, re.S | re.I)
    for i, onion in enumerate(onions[:15]):
        results.append({
            "onion": onion,
            "title": re.sub(r"<[^>]+>", "", titles[i]).strip() if i < len(titles) else "",
            "description": re.sub(r"<[^>]+>", "", descs[i]).strip()[:200] if i < len(descs) else "",
        })
    return results


def run(target: str, check_relay: bool = True, probe_onion: bool = False,
        search_darknet: bool = True, export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"🧅  Tor Intelligence — {target}", style="bold cyan"))

    results = {
        "target":           target,
        "is_tor_exit":      False,
        "tor_relays":       [],
        "onion_reachable":  None,
        "darknet_mentions": [],
        "risk_flags":       [],
    }

    is_onion = target.endswith(".onion")

    if is_onion:
        console.print(f"[magenta]Target is a .onion address[/magenta]")
        # Probe via Tor2Web
        if probe_onion:
            console.print("\n[bold]Probing .onion via Tor2Web gateways...[/bold]")
            onion_result = _probe_onion_tor2web(target)
            results["onion_reachable"] = onion_result
            if onion_result.get("reachable"):
                console.print(f"  [green]✓ Reachable via {onion_result['gateway']}[/green]")
                if onion_result.get("title"):
                    console.print(f"  Title: {onion_result['title']}")
            else:
                console.print("  [dim]Not reachable via Tor2Web (may be down or v3)[/dim]")
        else:
            console.print("[dim].onion probe skipped (use --probe to enable)[/dim]")

    else:
        # IP resolution
        ip = _resolve_ip(target)
        if ip:
            console.print(f"[cyan]IP:[/cyan] {ip}")

            # Tor exit node check
            if check_relay:
                console.print("\n[bold]Checking Tor exit node lists...[/bold]")
                is_exit = _check_tor_exit_list(ip)
                results["is_tor_exit"] = is_exit
                if is_exit:
                    console.print(f"  [red bold]⚠ {ip} IS A TOR EXIT NODE[/red bold]")
                    results["risk_flags"].append("Tor exit node")
                else:
                    console.print(f"  [green]✓ {ip} is not a known Tor exit node[/green]")

        # Onionoo relay search
        console.print(f"\n[bold]Searching Tor relay database (Onionoo)...[/bold]")
        relays = _check_onionoo(target.split(".")[0])
        results["tor_relays"] = relays
        if relays:
            t = Table(title="Tor Relays/Bridges Found", box=box.SIMPLE if box else None)
            t.add_column("Type",        style="cyan")
            t.add_column("Nickname",    style="yellow")
            t.add_column("Fingerprint", style="dim", max_width=20)
            t.add_column("Flags",       style="green")
            t.add_column("Country")
            for r in relays[:10]:
                t.add_row(
                    r.get("type", ""),
                    r.get("nickname", ""),
                    (r.get("fingerprint") or "")[:16] + "…",
                    ", ".join(r.get("flags", [])[:4]),
                    r.get("country", ""),
                )
            console.print(t)
        else:
            console.print("  [dim]No relay/bridge data found[/dim]")

    # Ahmia darknet search
    if search_darknet:
        console.print(f"\n[bold]Darknet search (Ahmia.fi)...[/bold]")
        mentions = _search_ahmia(target.replace(".onion", ""))
        results["darknet_mentions"] = mentions
        if mentions:
            console.print(f"  [yellow]Found {len(mentions)} darknet mentions[/yellow]")
            t2 = Table(box=box.SIMPLE if box else None)
            t2.add_column(".onion",      style="magenta", max_width=30)
            t2.add_column("Title",       style="cyan",    max_width=40)
            t2.add_column("Description", style="dim",     max_width=50)
            for m in mentions[:10]:
                t2.add_row(m["onion"][:30], m["title"][:40], m["description"][:50])
            console.print(t2)
        else:
            console.print("  [green]No darknet mentions found[/green]")

    # Risk summary
    if results["risk_flags"]:
        console.print(f"\n[red bold]Risk Flags: {', '.join(results['risk_flags'])}[/red bold]")
    else:
        console.print("\n[green]No Tor-related risk indicators found[/green]")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", target)
    out_path = Path(export) if export else out_dir / f"torcheck_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
