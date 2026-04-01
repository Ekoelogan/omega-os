"""Network asset mapper — builds a visual relationship tree of discovered assets."""
import socket
import requests
from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.table import Table

console = Console()


def _resolve(hostname: str) -> list:
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = list({i[4][0] for i in infos})
        return ips
    except Exception:
        return []


def _fetch_subdomains(domain: str) -> list:
    subs = []
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json", timeout=10
        )
        if r.status_code == 200:
            seen = set()
            for entry in r.json():
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n not in seen:
                        seen.add(n)
                        subs.append(n)
    except Exception:
        pass
    return sorted(set(subs))[:30]


def _get_ports(ip: str, ports=(21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443)) -> list:
    open_ports = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            if s.connect_ex((ip, p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    return open_ports


def _geo(ip: str) -> str:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            d = r.json()
            return f"{d.get('city','?')}, {d.get('country','?')}  AS{d.get('org','').split()[0].replace('AS','')}"
    except Exception:
        pass
    return ""


def build_map(target: str, deep: bool = False) -> dict:
    """Build a complete network asset map for a domain."""
    results = {"target": target, "nodes": {}}

    console.print(Panel(
        f"[bold #ff2d78]🗺  Network Asset Map[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    root_tree = Tree(
        f"[bold #ff2d78]◆ {target}[/]",
        guide_style="dim #ff85b3",
    )

    # Resolve root
    root_ips = _resolve(target)
    ip_branch = root_tree.add("[bold yellow]🌐 IP Addresses[/]")
    for ip in root_ips:
        geo = _geo(ip)
        node = ip_branch.add(f"[cyan]{ip}[/]  [dim]{geo}[/]")
        if deep:
            ports = _get_ports(ip)
            if ports:
                for p in ports:
                    node.add(f"[green]:{p}[/]  [dim]{_port_label(p)}[/]")

    results["nodes"][target] = {"ips": root_ips}

    # Subdomains
    console.print("[dim]  Fetching subdomains from crt.sh...[/]")
    subs = _fetch_subdomains(target)

    sub_branch = root_tree.add(f"[bold magenta]📡 Subdomains ({len(subs)})[/]")
    for sub in subs[:20]:
        ips = _resolve(sub)
        ip_str = f"[cyan]{ips[0]}[/]" if ips else "[dim]unresolved[/]"
        node = sub_branch.add(f"[white]{sub}[/]  →  {ip_str}")
        if deep and ips:
            ports = _get_ports(ips[0])
            for p in ports:
                node.add(f"[green]:{p}[/]  [dim]{_port_label(p)}[/]")
        results["nodes"][sub] = {"ips": ips}

    if len(subs) > 20:
        sub_branch.add(f"[dim]... and {len(subs)-20} more[/]")

    # DNS records
    dns_branch = root_tree.add("[bold blue]🔤 DNS[/]")
    try:
        import dns.resolver
        for rtype in ("MX", "NS", "TXT"):
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=3)
                b = dns_branch.add(f"[yellow]{rtype}[/]")
                for r in answers:
                    val = str(r).strip('"')[:80]
                    b.add(f"[dim]{val}[/]")
            except Exception:
                pass
    except ImportError:
        dns_branch.add("[dim]dnspython not available[/]")

    console.print(root_tree)

    # Summary table
    total_subs = len(subs)
    total_ips = len(root_ips)
    tbl = Table(title="Asset Summary", box=box.ROUNDED, border_style="#ff85b3")
    tbl.add_column("Metric", style="bold")
    tbl.add_column("Count", style="cyan")
    tbl.add_row("Root domain", target)
    tbl.add_row("Root IPs", str(total_ips))
    tbl.add_row("Subdomains found", str(total_subs))
    tbl.add_row("Nodes mapped", str(len(results["nodes"])))
    console.print(tbl)

    results["subdomains"] = subs
    return results


def _port_label(port: int) -> str:
    labels = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    }
    return labels.get(port, "unknown")


def run(target: str, deep: bool = False):
    return build_map(target, deep)
