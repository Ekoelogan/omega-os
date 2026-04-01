"""omega live — Full-screen live multi-panel TUI: simultaneous module outputs, keyboard nav."""
from __future__ import annotations
import asyncio
import queue
import threading
import time
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


def _make_header(target: str, uptime: float) -> Panel:
    mins, secs = divmod(int(uptime), 60)
    now = datetime.now().strftime("%H:%M:%S")
    txt = Text()
    txt.append("⚡ OMEGA LIVE", style="bold #ff2d78")
    txt.append(f"  target: ", style="dim")
    txt.append(target, style="bold cyan")
    txt.append(f"  │  {now}", style="dim")
    txt.append(f"  │  uptime: {mins:02d}:{secs:02d}", style="dim")
    return Panel(txt, style="#ff2d78 on default", height=3)


def _make_panel(title: str, lines: list[str], height: int = 20, color: str = "#ff2d78") -> Panel:
    content = Text()
    for ln in lines[-(height - 2):]:
        if any(w in ln.lower() for w in ("error", "fail", "critical")):
            content.append(ln + "\n", style="red")
        elif any(w in ln.lower() for w in ("ok", "✓", "found", "success")):
            content.append(ln + "\n", style="green")
        elif any(w in ln.lower() for w in ("warn", "⚠", "skip")):
            content.append(ln + "\n", style="yellow")
        else:
            content.append(ln + "\n", style="dim white")
    return Panel(content, title=f"[bold {color}]{title}[/bold {color}]",
                 border_style=color, height=height)


class LiveDashboard:
    def __init__(self, target: str):
        self.target    = target
        self.start     = time.time()
        self.panels: dict[str, list[str]] = {
            "DNS & WHOIS":    [f"Resolving {target}…"],
            "Subdomains":     ["Enumerating…"],
            "Ports & Banners":["Scanning…"],
            "SSL / Headers":  ["Checking…"],
            "Threat Intel":   ["Loading…"],
            "Activity Log":   [f"Session started — target: {target}"],
        }
        self._q: queue.Queue = queue.Queue()
        self._stop = threading.Event()

    def _append(self, panel: str, line: str) -> None:
        self._q.put((panel, line))

    def _worker_dns(self) -> None:
        try:
            import dns.resolver
            for rtype in ["A", "MX", "NS", "TXT"]:
                try:
                    answers = dns.resolver.resolve(self.target, rtype, lifetime=4)
                    for rr in answers:
                        self._append("DNS & WHOIS", f"[{rtype}] {rr}")
                except Exception:
                    self._append("DNS & WHOIS", f"[{rtype}] no records")
        except Exception as e:
            self._append("DNS & WHOIS", f"DNS error: {e}")

    def _worker_subdomain(self) -> None:
        wordlist = ["www", "mail", "ftp", "api", "dev", "staging", "admin",
                    "vpn", "cdn", "static", "app", "portal", "login", "mx"]
        import socket
        found = 0
        for sub in wordlist:
            if self._stop.is_set():
                break
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                self._append("Subdomains", f"✓ {fqdn} → {ip}")
                found += 1
            except Exception:
                pass
        self._append("Subdomains", f"Done — {found} found")

    def _worker_ports(self) -> None:
        import socket
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
        try:
            ip = socket.gethostbyname(self.target)
        except Exception:
            self._append("Ports & Banners", f"DNS resolve failed")
            return
        open_ports = []
        for port in ports:
            if self._stop.is_set():
                break
            try:
                with socket.create_connection((ip, port), timeout=0.8):
                    self._append("Ports & Banners", f"✓ {port}/tcp OPEN")
                    open_ports.append(port)
            except Exception:
                pass
        self._append("Ports & Banners", f"Done — {len(open_ports)}/{len(ports)} open")

    def _worker_ssl(self) -> None:
        import ssl, socket
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=self.target) as ss:
                    cert   = ss.getpeercert()
                    expiry = cert.get("notAfter", "")
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    self._append("SSL / Headers", f"Issuer: {issuer.get('organizationName','?')}")
                    self._append("SSL / Headers", f"Expires: {expiry}")
                    sans   = cert.get("subjectAltName", [])
                    for _, san in sans[:5]:
                        self._append("SSL / Headers", f"SAN: {san}")
        except Exception as e:
            self._append("SSL / Headers", f"SSL: {e}")

        try:
            import requests
            r = requests.get(f"https://{self.target}", timeout=6, verify=False)
            security_headers = ["x-frame-options", "content-security-policy",
                                 "strict-transport-security", "x-content-type-options"]
            for h in security_headers:
                val = r.headers.get(h)
                sym = "✓" if val else "✗"
                self._append("SSL / Headers", f"{sym} {h}")
        except Exception as e:
            self._append("SSL / Headers", f"Headers: {e}")

    def _worker_intel(self) -> None:
        import requests
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/general",
                timeout=8,
            )
            if r.ok:
                data   = r.json()
                pulses = data.get("pulse_info", {}).get("count", 0)
                self._append("Threat Intel", f"OTX Pulses: {pulses}")
                if pulses > 0:
                    self._append("Threat Intel", f"⚠ Domain flagged in {pulses} threat reports")
        except Exception as e:
            self._append("Threat Intel", f"OTX: {e}")

        try:
            import socket
            ip = socket.gethostbyname(self.target)
            r2 = requests.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=6)
            if r2.ok:
                d = r2.json()
                self._append("Threat Intel", f"GreyNoise: {d.get('classification','unknown')}")
        except Exception as e:
            self._append("Threat Intel", f"GreyNoise: {e}")

    def _make_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="log", size=6),
        )
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )
        layout["left"].split_column(
            Layout(name="dns",   ratio=1),
            Layout(name="subs",  ratio=1),
            Layout(name="ports", ratio=1),
        )
        layout["right"].split_column(
            Layout(name="ssl",   ratio=1),
            Layout(name="intel", ratio=1),
        )
        return layout

    def _update_layout(self, layout: Layout) -> None:
        uptime = time.time() - self.start
        layout["header"].update(_make_header(self.target, uptime))
        panel_map = {
            "DNS & WHOIS":     "dns",
            "Subdomains":      "subs",
            "Ports & Banners": "ports",
            "SSL / Headers":   "ssl",
            "Threat Intel":    "intel",
            "Activity Log":    "log",
        }
        colors = ["#ff2d78", "#ff6688", "#ff9900", "#ffcc00", "#aa44ff"]
        for i, (title, node) in enumerate(panel_map.items()):
            color = colors[i % len(colors)]
            layout[node].update(
                _make_panel(title, self.panels[title], color=color)
            )

    def run(self, duration: int = 60) -> None:
        # Start worker threads
        workers = [
            threading.Thread(target=self._worker_dns,       daemon=True),
            threading.Thread(target=self._worker_subdomain, daemon=True),
            threading.Thread(target=self._worker_ports,     daemon=True),
            threading.Thread(target=self._worker_ssl,       daemon=True),
            threading.Thread(target=self._worker_intel,     daemon=True),
        ]
        for w in workers:
            w.start()

        layout = self._make_layout()

        try:
            with Live(layout, refresh_per_second=4, screen=True) as live:
                end_time = time.time() + duration
                while time.time() < end_time:
                    # Drain queue
                    try:
                        while True:
                            panel, line = self._q.get_nowait()
                            self.panels[panel].append(line)
                            self.panels["Activity Log"].append(f"[{panel}] {line}")
                    except queue.Empty:
                        pass
                    self._update_layout(layout)
                    time.sleep(0.25)
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()

        console.print("\n[bold]Live session complete.[/bold]")


def run(target: str, duration: int = 120) -> None:
    if not target.startswith("http"):
        # Strip to hostname
        import urllib.parse
        target = urllib.parse.urlparse(f"https://{target}").netloc or target

    console.print(f"[bold #ff2d78]⚡  OMEGA LIVE[/bold #ff2d78]  launching for [cyan]{target}[/cyan] "
                  f"([dim]{duration}s — Ctrl+C to exit[/dim])")
    time.sleep(0.5)

    dashboard = LiveDashboard(target)
    dashboard.run(duration=duration)
