"""Global proxy/Tor anonymity layer — patches all requests through SOCKS5/HTTP proxy."""
import os
import socket
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

TOR_PROXY = "socks5h://127.0.0.1:9050"
DEFAULT_CHECK_URL = "https://httpbin.org/ip"
IP_CHECK_URLS = [
    "https://httpbin.org/ip",
    "https://api.ipify.org?format=json",
    "https://ipinfo.io/json",
]


def _get_real_ip() -> str:
    for url in IP_CHECK_URLS:
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                d = r.json()
                return d.get("ip") or d.get("origin") or d.get("query", "?")
        except Exception:
            continue
    return "unknown"


def _get_proxied_ip(proxy: str) -> str:
    proxies = {"http": proxy, "https": proxy}
    for url in IP_CHECK_URLS:
        try:
            r = requests.get(url, proxies=proxies, timeout=15)
            if r.status_code == 200:
                d = r.json()
                return d.get("ip") or d.get("origin") or d.get("query", "?")
        except Exception:
            continue
    return "unreachable"


def _check_tor() -> bool:
    """Check if Tor is running on default port."""
    try:
        s = socket.socket()
        s.settimeout(2)
        result = s.connect_ex(("127.0.0.1", 9050))
        s.close()
        return result == 0
    except Exception:
        return False


def apply_proxy(proxy: str):
    """Set environment variables so all requests use the proxy."""
    os.environ["HTTP_PROXY"] = proxy
    os.environ["HTTPS_PROXY"] = proxy
    os.environ["http_proxy"] = proxy
    os.environ["https_proxy"] = proxy


def remove_proxy():
    """Remove proxy environment variables."""
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ.pop(key, None)


def status():
    """Show current proxy/anonymity status."""
    from omega_cli.config import load
    cfg = load()
    proxy = cfg.get("proxy", "")

    console.print(Panel(
        "[bold #ff2d78]🕵  Proxy / Anonymity Status[/]",
        border_style="#ff85b3",
    ))

    tbl = Table(box=box.SIMPLE, show_header=False)
    tbl.add_column("", style="dim", width=20)
    tbl.add_column("")

    real_ip = _get_real_ip()
    tbl.add_row("Real IP", f"[yellow]{real_ip}[/]")
    tbl.add_row("Configured proxy", f"[cyan]{proxy or 'none'}[/]")

    if proxy:
        proxied_ip = _get_proxied_ip(proxy)
        match = proxied_ip == real_ip
        tbl.add_row("Proxied IP", f"[{'red' if match else 'green'}]{proxied_ip}[/]")
        tbl.add_row("Anonymized", f"[{'red]NO — same IP' if match else 'green]YES'}[/]")

    tor_up = _check_tor()
    tbl.add_row("Tor service", f"[{'green]running' if tor_up else 'red]not detected'}[/]")

    console.print(tbl)

    if tor_up and not proxy:
        console.print("\n[yellow]Tor is running![/] Enable it: [cyan]omega config set proxy socks5h://127.0.0.1:9050[/]")
    if not tor_up:
        console.print("\n[dim]Start Tor: [cyan]sudo systemctl start tor[/dim]  or  [cyan]sudo apt install tor && sudo tor[/]")

    return {"real_ip": real_ip, "proxy": proxy, "tor": tor_up}


def test_proxy(proxy: str):
    """Test a proxy and show before/after IP."""
    console.print(Panel(
        f"[bold #ff2d78]🕵  Testing Proxy[/]\n[dim]{proxy}[/]",
        border_style="#ff85b3",
    ))
    real = _get_real_ip()
    proxied = _get_proxied_ip(proxy)

    tbl = Table(box=box.ROUNDED, border_style="#ff85b3")
    tbl.add_column("", style="dim")
    tbl.add_column("IP Address", style="cyan")
    tbl.add_row("Without proxy", real)
    tbl.add_row("Through proxy", proxied if proxied != "unreachable" else "[red]unreachable[/]")
    tbl.add_row("Anonymized", "[green]YES[/]" if proxied != real and proxied != "unreachable" else "[red]NO[/]")
    console.print(tbl)

    return {"real": real, "proxied": proxied, "working": proxied != real and proxied != "unreachable"}


def run(action: str = "status", proxy: str = ""):
    if action == "status":
        return status()
    elif action == "test":
        from omega_cli.config import load
        cfg = load()
        p = proxy or cfg.get("proxy", TOR_PROXY)
        return test_proxy(p)
    elif action == "tor":
        if _check_tor():
            console.print(f"[green]✓[/] Tor detected. Run: [cyan]omega config set proxy {TOR_PROXY}[/]")
        else:
            console.print("[red]Tor not running.[/]  Install: [cyan]sudo apt install tor && sudo service tor start[/]")
    elif action == "clear":
        remove_proxy()
        console.print("[green]✓[/] Proxy environment variables cleared.")
