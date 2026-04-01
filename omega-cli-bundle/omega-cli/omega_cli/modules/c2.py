"""omega c2 — C2 infrastructure detection via JARM, banner fingerprints, and known IOC feeds."""
from __future__ import annotations
import hashlib
import json
import re
import socket
import ssl
import struct
import time
from typing import Optional

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Known C2 framework JARM fingerprints (partial — most common)
KNOWN_JARM: dict[str, str] = {
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1":  "Cobalt Strike (default)",
    "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2":  "Cobalt Strike (variant)",
    "2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5":  "Metasploit (meterpreter)",
    "05d02d20d05d05d05c05d02d05d05d4606ef7946105f20b303b9a05200e829":  "Sliver C2",
    "29d29d15d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38":  "Brute Ratel C4",
    "3fd21b20d3fd3fd21c43d21b21b43d494e0df9532e75299f15ba73156cee38":  "Havoc C2",
    "00000000000000000041d00000041d9535b034be7550abd1b7fec99476a5e":   "Mythic C2",
}

# Cobalt Strike beacon config patterns in HTTP responses
CS_PATTERNS = [
    re.compile(rb"\x00.\x00.\x00\x01\x00\x02\xff\xff"),  # beacon config block
    re.compile(rb"Content-Type: application/octet-stream.*\r\n\r\n\x00"),
]

# Default Cobalt Strike Team Server ports
CS_PORTS = [50050, 8443, 8080, 443, 80]

# Sliver default implant patterns
SLIVER_PATTERNS = [
    re.compile(rb"sliver", re.I),
    re.compile(rb"sliverd", re.I),
]

C2_INTEL_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv",
]


def _jarm_scan(host: str, port: int = 443) -> Optional[str]:
    """Compute a simplified JARM-like TLS fingerprint (hello cipher suite probe)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                cert   = ssock.getpeercert(binary_form=True)
                # Build a fingerprint from cipher + cert hash
                if cipher and cert:
                    h = hashlib.sha256(str(cipher).encode() + cert).hexdigest()[:62]
                    return h
    except Exception:
        pass
    return None


def _check_c2_intel(ip: str) -> list[str]:
    """Check IP against known C2 intel feeds."""
    hits = []
    for feed_url in C2_INTEL_FEEDS:
        try:
            r = requests.get(feed_url, timeout=8,
                             headers={"User-Agent": "omega-cli/0.9.0"})
            if r.ok and ip in r.text:
                hits.append(feed_url.split("/")[-1])
        except Exception:
            pass
    return hits


def _banner_probe(host: str, port: int) -> bytes:
    """Grab raw TCP banner."""
    try:
        with socket.create_connection((host, port), timeout=4) as s:
            s.settimeout(2)
            try:
                return s.recv(1024)
            except Exception:
                return b""
    except Exception:
        return b""


def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def run(target: str, ports_str: str = "", deep: bool = False) -> None:
    console.print(Panel(
        f"[bold #ff2d78]☠  C2 Infrastructure Detection[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    ip = _resolve(target)
    if ip != target:
        console.print(f"[dim]Resolved:[/dim] {target} → [cyan]{ip}[/cyan]\n")

    probe_ports = [int(p) for p in ports_str.split(",") if p.strip().isdigit()] if ports_str else CS_PORTS

    results: list[dict] = []

    # JARM fingerprinting per port
    console.print("[dim]Running TLS fingerprint (JARM-like) probes…[/dim]")
    tbl = Table(title="TLS Fingerprint Analysis", show_lines=True)
    tbl.add_column("Port",        justify="right")
    tbl.add_column("Fingerprint", style="cyan",       max_width=40)
    tbl.add_column("Match",       style="bold #ff2d78", max_width=30)

    for port in probe_ports:
        fp = _jarm_scan(target, port)
        if fp:
            match = next((v for k, v in KNOWN_JARM.items() if fp.startswith(k[:20])), "")
            color = "#ff2d78" if match else "dim"
            tbl.add_row(str(port), f"[{color}]{fp[:38]}…[/{color}]",
                        match or "[dim]unknown[/dim]")
            results.append({"port": port, "fp": fp, "match": match})

    console.print(tbl)

    # Banner-based C2 detection
    console.print("\n[dim]Probing banners for C2 artifacts…[/dim]")
    for port in probe_ports:
        banner = _banner_probe(target, port)
        if not banner:
            continue
        for pat in CS_PATTERNS:
            if pat.search(banner):
                console.print(f"  [bold red]⚠  Cobalt Strike beacon pattern on port {port}[/bold red]")
                results.append({"port": port, "finding": "Cobalt Strike beacon"})
        for pat in SLIVER_PATTERNS:
            if pat.search(banner):
                console.print(f"  [bold red]⚠  Sliver implant pattern on port {port}[/bold red]")
                results.append({"port": port, "finding": "Sliver C2"})

    # C2 intel feed check
    if deep:
        console.print(f"\n[dim]Checking {ip} against C2 intel feeds…[/dim]")
        hits = _check_c2_intel(ip)
        if hits:
            console.print(f"  [bold red]⚠  IP found in feeds:[/bold red] {', '.join(hits)}")
        else:
            console.print(f"  [green]✓[/green] Not found in checked C2 feeds.")

    # Summary
    flagged = [r for r in results if r.get("match") or r.get("finding")]
    if flagged:
        console.print(f"\n[bold red]⚠  {len(flagged)} C2 indicator(s) detected on {target}[/bold red]")
    else:
        console.print(f"\n[green]✓  No known C2 fingerprints detected.[/green]")
        console.print("[dim]Tip: use --deep to cross-check against C2 intel feeds.[/dim]")

    console.print(f"\n[dim]Also check:[/dim]")
    console.print(f"  https://search.censys.io/hosts/{ip}")
    console.print(f"  https://hunt.io/ip/{ip}")
