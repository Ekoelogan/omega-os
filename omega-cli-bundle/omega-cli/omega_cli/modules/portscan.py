"""Port scanning module (passive-safe TCP connect scan)."""
import socket
import threading
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/Sub",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def _scan_port(host: str, port: int, service: str, open_ports: list, lock: threading.Lock):
    try:
        with socket.create_connection((host, port), timeout=1):
            with lock:
                open_ports.append((port, service))
    except Exception:
        pass


def run(target: str, ports: str = "common"):
    """TCP connect scan on a host."""
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    console.print(f"\n[bold cyan][ PORT SCAN ] {host}[/bold cyan]\n")

    if ports == "common":
        port_map = COMMON_PORTS
    else:
        try:
            port_list = []
            for part in ports.split(","):
                if "-" in part:
                    start, end = part.split("-")
                    port_list.extend(range(int(start), int(end) + 1))
                else:
                    port_list.append(int(part))
            port_map = {p: "Unknown" for p in port_list}
        except ValueError:
            console.print("[red]Invalid port specification.[/red]")
            return

    open_ports = []
    lock = threading.Lock()
    threads = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        progress.add_task(f"Scanning {len(port_map)} ports...", total=None)
        for port, service in port_map.items():
            t = threading.Thread(target=_scan_port, args=(host, port, service, open_ports, lock))
            threads.append(t)
            t.start()
            if len([t for t in threads if t.is_alive()]) >= 100:
                for t in threads:
                    t.join(timeout=0.05)
        for t in threads:
            t.join()

    open_ports.sort()
    if open_ports:
        table = Table(title="Open Ports", show_header=True)
        table.add_column("Port", style="bold green")
        table.add_column("Service", style="cyan")
        for port, service in open_ports:
            table.add_row(str(port), service)
        console.print(table)
    else:
        console.print("[yellow]No open ports found.[/yellow]")

    console.print(f"\n[bold]Scanned {len(port_map)} ports, {len(open_ports)} open.[/bold]")
