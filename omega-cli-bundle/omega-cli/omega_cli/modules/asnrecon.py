"""ASN / BGP / netblock recon — enumerate IP ranges, peers, prefixes, org info."""
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

console = Console()


def _bgpview_asn(asn: str) -> dict:
    asn = asn.upper().lstrip("AS")
    r = requests.get(f"https://api.bgpview.io/asn/{asn}", timeout=10)
    if r.status_code == 200:
        return r.json().get("data", {})
    return {}


def _bgpview_prefixes(asn: str) -> list:
    asn = asn.upper().lstrip("AS")
    r = requests.get(f"https://api.bgpview.io/asn/{asn}/prefixes", timeout=10)
    if r.status_code == 200:
        data = r.json().get("data", {})
        return data.get("ipv4_prefixes", []) + data.get("ipv6_prefixes", [])
    return []


def _bgpview_peers(asn: str) -> list:
    asn = asn.upper().lstrip("AS")
    r = requests.get(f"https://api.bgpview.io/asn/{asn}/peers", timeout=10)
    if r.status_code == 200:
        data = r.json().get("data", {})
        v4 = data.get("ipv4_peers", [])
        return v4[:20]
    return []


def _ip_to_asn(ip: str) -> dict:
    """Get ASN info for an IP address."""
    r = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=10)
    if r.status_code == 200:
        data = r.json().get("data", {})
        prefixes = data.get("prefixes", [])
        if prefixes:
            p = prefixes[0]
            return {
                "asn": p.get("asn", {}).get("asn"),
                "name": p.get("asn", {}).get("name"),
                "description": p.get("asn", {}).get("description_short"),
                "prefix": p.get("prefix"),
                "country": p.get("country_code"),
            }
    return {}


def _rdap_org(asn: str) -> dict:
    try:
        asn_num = asn.upper().lstrip("AS")
        r = requests.get(
            f"https://rdap.arin.net/registry/autnum/{asn_num}",
            timeout=10, headers={"Accept": "application/json"},
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "handle": d.get("handle"),
                "name": d.get("name"),
                "type": d.get("type"),
                "country": next((v.get("value") for v in d.get("entities", [{}])[0].get("vcardArray", [[]])[1] if isinstance(v, list) and v[0] == "country"), ""),
            }
    except Exception:
        pass
    return {}


def run(target: str):
    """Run ASN/BGP recon for an ASN number or IP address."""
    console.print(Panel(
        f"[bold #ff2d78]🌐 ASN / BGP Recon[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    is_asn = target.upper().startswith("AS") or target.isdigit()

    if not is_asn:
        # Resolve IP to ASN first
        console.print(f"[dim]  Resolving IP {target} → ASN...[/]")
        info = _ip_to_asn(target)
        if not info:
            console.print(f"[red]Could not resolve ASN for {target}[/]")
            return {}
        asn_num = str(info["asn"])
        console.print(f"  [dim]→[/] [cyan]AS{asn_num}[/]  {info.get('name','')}")
        tbl = Table(box=box.SIMPLE, show_header=False)
        tbl.add_column("", style="dim")
        tbl.add_column("")
        for k, v in info.items():
            tbl.add_row(k, str(v or ""))
        console.print(tbl)
        target = f"AS{asn_num}"

    asn_str = target.upper().lstrip("AS")

    console.print(f"[dim]  Fetching AS{asn_str} details...[/]")
    asn_data = _bgpview_asn(asn_str)

    if asn_data:
        tree = Tree(f"[bold #ff2d78]AS{asn_str}[/]  [yellow]{asn_data.get('name','')[:60]}[/]",
                    guide_style="dim #ff85b3")
        tree.add(f"[dim]Description:[/] {asn_data.get('description_short','')[:80]}")
        tree.add(f"[dim]Country:[/]     [cyan]{asn_data.get('country_code','')}[/]")
        tree.add(f"[dim]Website:[/]     {asn_data.get('website','')}")
        tree.add(f"[dim]Email:[/]       {asn_data.get('email','')}")
        tree.add(f"[dim]RIR:[/]         {asn_data.get('rir_allocation',{}).get('rir_name','')}")
        console.print(tree)

    console.print(f"[dim]  Fetching prefixes...[/]")
    prefixes = _bgpview_prefixes(asn_str)

    if prefixes:
        tbl = Table(
            title=f"IP Prefixes ({len(prefixes)})",
            box=box.ROUNDED, border_style="#ff85b3",
        )
        tbl.add_column("Prefix", style="cyan")
        tbl.add_column("Name")
        tbl.add_column("Country", width=8)
        tbl.add_column("Description")
        for p in prefixes[:30]:
            tbl.add_row(
                p.get("prefix", ""),
                p.get("name", "")[:40],
                p.get("country_code", ""),
                p.get("description", "")[:50],
            )
        if len(prefixes) > 30:
            tbl.add_row(f"[dim]... +{len(prefixes)-30} more[/]", "", "", "")
        console.print(tbl)

    console.print(f"[dim]  Fetching BGP peers...[/]")
    peers = _bgpview_peers(asn_str)
    if peers:
        ptbl = Table(
            title=f"BGP Peers (top {len(peers)})",
            box=box.SIMPLE, border_style="dim",
        )
        ptbl.add_column("ASN", style="yellow", width=10)
        ptbl.add_column("Name")
        ptbl.add_column("Country", width=8)
        for p in peers:
            ptbl.add_row(
                f"AS{p.get('asn','')}",
                p.get("name","")[:50],
                p.get("country_code",""),
            )
        console.print(ptbl)

    total_ips = sum(
        2 ** (32 - int(p["prefix"].split("/")[1]))
        for p in prefixes
        if "/" in p.get("prefix","") and "." in p.get("prefix","")
    )
    console.print(f"\n[bold]Total IPv4 space:[/] [cyan]{total_ips:,}[/] addresses across [yellow]{len(prefixes)}[/] prefixes")

    return {
        "asn": f"AS{asn_str}",
        "info": asn_data,
        "prefixes": [p.get("prefix") for p in prefixes],
        "peers": [f"AS{p.get('asn')}" for p in peers],
        "total_ipv4": total_ips,
    }
