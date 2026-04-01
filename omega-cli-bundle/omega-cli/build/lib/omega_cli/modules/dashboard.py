"""
omega live dashboard — parallel recon with real-time Rich TUI.
All modules run concurrently; results stream into live panels.
"""
import asyncio
import time
import threading
from dataclasses import dataclass, field
from typing import Any
from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.spinner import Spinner
from rich.columns import Columns
from rich import box

console = Console()

BANNER = """[bold magenta]  ▄██████▄   ███▄▄▄▄      ▄████████    ▄██████▄   ▄████████ 
 ███    ███  ███▀▀▀██▄   ███    ███   ███    ███  ███    ███ 
 ███    ███  ███   ███   ███    █▀    ███    █▀   ███    ███ 
 ███    ███  ███   ███  ▄███▄▄▄       ███        ▄███▄▄▄▄██▀ 
 ███    ███  ███   ███ ▀▀███▀▀▀     ▀███████████▀▀███▀▀▀▀▀  
 ███    ███  ███   ███   ███    █▄           ███  ███████████ 
 ███    ███  ███   ███   ███    ███    ▄█    ███  ███    ███ 
  ▀██████▀    ▀█   █▀    ██████████  ▄████████▀   ███    ███[/bold magenta]"""

STATUS_ICONS = {
    "pending":  "[dim]◌[/dim]",
    "running":  "[yellow]◎[/yellow]",
    "done":     "[green]✓[/green]",
    "error":    "[red]✗[/red]",
    "skipped":  "[dim]–[/dim]",
}


@dataclass
class ModuleResult:
    name:     str
    status:   str = "pending"   # pending | running | done | error | skipped
    output:   list[str] = field(default_factory=list)
    duration: float = 0.0
    findings: int = 0


class OmegaDashboard:
    def __init__(self, target: str, modules: list[str] = None):
        self.target   = target
        self.start_ts = time.time()
        self.results: dict[str, ModuleResult] = {}
        self.lock     = threading.Lock()
        self._all_modules = [
            "whois", "dns", "crtsh", "subdomains", "ipinfo",
            "headers", "ssl", "tech", "ports", "spoofcheck",
            "reverseip", "wayback", "robots", "jscan", "buckets",
            "threat", "cve", "dorks",
        ]
        self.active_modules = modules or self._all_modules
        for m in self.active_modules:
            self.results[m] = ModuleResult(name=m)

    def update(self, name: str, status: str, line: str = "", findings: int = -1):
        with self.lock:
            r = self.results.get(name)
            if r:
                r.status = status
                if line:
                    r.output.append(line)
                if findings >= 0:
                    r.findings = findings
                if status == "done":
                    r.duration = time.time() - self.start_ts

    def _status_table(self) -> Table:
        t = Table(box=box.SIMPLE, show_header=True, expand=True)
        t.add_column("Module",    style="bold", width=16)
        t.add_column("Status",    width=22)
        t.add_column("Findings",  justify="right", width=8)
        t.add_column("Notes",     style="dim",  ratio=1)

        for name in self.active_modules:
            r = self.results[name]
            icon = STATUS_ICONS.get(r.status, "?")
            status_str = f"{icon} {r.status}"
            last_line  = r.output[-1][:60] if r.output else ""
            findings   = str(r.findings) if r.findings > 0 else ""
            t.add_row(name, status_str, findings, last_line)
        return t

    def _findings_panel(self) -> Panel:
        lines = []
        for name in self.active_modules:
            r = self.results[name]
            if r.status == "done" and r.output:
                lines.append(f"[bold cyan]{name}[/bold cyan]")
                for line in r.output[-3:]:
                    lines.append(f"  [dim]{line[:100]}[/dim]")
        content = "\n".join(lines[-40:]) if lines else "[dim]Waiting for results...[/dim]"
        return Panel(content, title="[bold]Latest Findings[/bold]", border_style="blue")

    def render(self) -> Layout:
        elapsed = time.time() - self.start_ts
        done    = sum(1 for r in self.results.values() if r.status in ("done", "error", "skipped"))
        total   = len(self.active_modules)
        pct     = int(done / total * 100) if total else 0

        bar_width = 40
        filled    = int(bar_width * pct / 100)
        bar       = f"[magenta]{'█' * filled}[/magenta][dim]{'░' * (bar_width - filled)}[/dim]"

        header_text = (
            f"{BANNER}\n\n"
            f"  [bold]Target:[/bold] [cyan]{self.target}[/cyan]   "
            f"[bold]Elapsed:[/bold] {elapsed:.1f}s   "
            f"[bold]Progress:[/bold] {done}/{total}  {bar}  [bold]{pct}%[/bold]"
        )

        layout = Layout()
        layout.split_column(
            Layout(Panel(header_text, border_style="magenta"), name="header", size=16),
            Layout(name="body"),
        )
        layout["body"].split_row(
            Layout(Panel(self._status_table(), title="[bold]Module Status[/bold]",
                         border_style="cyan"), name="status", ratio=1),
            Layout(self._findings_panel(), name="findings", ratio=1),
        )
        return layout


# ── Module runner wrappers ────────────────────────────────────────────────────

def _run_module(dash: OmegaDashboard, name: str, fn, *args):
    dash.update(name, "running")
    t0 = time.time()
    try:
        result = fn(*args)
        elapsed = time.time() - t0

        findings = 0
        lines    = []
        if isinstance(result, list):
            findings = len(result)
            lines    = [str(r) for r in result[:5]]
        elif isinstance(result, dict):
            findings = sum(len(v) if isinstance(v, list) else (1 if v else 0)
                           for v in result.values())
            for k, v in result.items():
                if v:
                    lines.append(f"{k}: {str(v)[:80]}")

        for l in lines[:5]:
            dash.update(name, "running", l)
        dash.update(name, "done", f"done in {elapsed:.1f}s", findings=findings)

    except Exception as e:
        dash.update(name, "error", str(e)[:80])


def run(target: str, modules: list[str] = None, report: bool = False, output_dir: str = None):
    """Run all (or selected) modules in parallel with a live TUI dashboard."""

    from omega_cli.modules import (
        whois_lookup, dns_lookup, crtsh, subdomain, ipinfo,
        headers, ssl_check, portscan, spoofcheck, reverseip,
        wayback, crawl, jscan, buckets, threatintel, dorks, techfp, cvemap
    )

    dash   = OmegaDashboard(target, modules)
    base   = f"https://{target}" if not target.startswith("http") else target

    MODULE_FNS = {
        "whois":      (whois_lookup.run,   target),
        "dns":        (dns_lookup.run,     target),
        "crtsh":      (crtsh.run,          target),
        "subdomains": (subdomain.run,      target),
        "ipinfo":     (ipinfo.run,         target),
        "headers":    (headers.run,        target),
        "ssl":        (ssl_check.run,      target),
        "tech":       (techfp.run,         target),
        "ports":      (portscan.run,       target),
        "spoofcheck": (spoofcheck.run,     target),
        "reverseip":  (reverseip.run,      target),
        "wayback":    (wayback.run,        target),
        "robots":     (crawl.run,          target),
        "jscan":      (jscan.run,          target),
        "buckets":    (buckets.run,        target),
        "threat":     (threatintel.run,    target),
        "dorks":      (dorks.run,          target),
        "cve":        (_cve_wrapper,       dash, techfp, cvemap, target),
    }

    active = dash.active_modules
    threads = []

    with Live(dash.render(), refresh_per_second=6, console=console, screen=False) as live:
        def refresh():
            while any(r.status in ("pending", "running") for r in dash.results.values()):
                live.update(dash.render())
                time.sleep(0.18)
            live.update(dash.render())

        refresh_thread = threading.Thread(target=refresh, daemon=True)
        refresh_thread.start()

        for name in active:
            if name not in MODULE_FNS:
                dash.update(name, "skipped")
                continue
            entry = MODULE_FNS[name]
            if name == "cve":
                t = threading.Thread(target=entry[0], args=entry[1:], daemon=True)
            else:
                fn, *args = entry
                t = threading.Thread(target=_run_module, args=(dash, name, fn, *args), daemon=True)
            threads.append(t)
            t.start()
            time.sleep(0.05)  # small stagger to avoid thundering herd

        for t in threads:
            t.join()

        refresh_thread.join(timeout=1)
        live.update(dash.render())

    # Final summary
    _print_summary(dash)

    if report:
        _export_report(target, dash, output_dir)


def _cve_wrapper(dash: OmegaDashboard, techfp_mod, cvemap_mod, target: str):
    dash.update("cve", "running", "waiting for tech fingerprint...")
    # Wait for tech module to finish
    for _ in range(60):
        if dash.results.get("tech", ModuleResult("")).status in ("done", "error", "skipped"):
            break
        time.sleep(0.5)
    dash.update("cve", "running", "mapping CVEs...")
    try:
        tech_result = techfp_mod.run(target)
        matches     = cvemap_mod.run(tech_detections=tech_result)
        findings    = len(matches) if matches else 0
        critical    = sum(1 for m in (matches or []) if m[2] >= 9.0)
        line        = f"{findings} CVEs matched" + (f" ({critical} CRITICAL)" if critical else "")
        dash.update("cve", "done", line, findings=findings)
    except Exception as e:
        dash.update("cve", "error", str(e)[:80])


def _print_summary(dash: OmegaDashboard):
    elapsed = time.time() - dash.start_ts
    done    = [r for r in dash.results.values() if r.status == "done"]
    errors  = [r for r in dash.results.values() if r.status == "error"]
    total_findings = sum(r.findings for r in done)

    console.print()
    t = Table(title=f"[bold magenta]OMEGA RECON COMPLETE — {dash.target}[/bold magenta]",
              show_header=True, box=box.ROUNDED)
    t.add_column("Stat", style="bold yellow")
    t.add_column("Value", style="cyan")
    t.add_row("Total time",      f"{elapsed:.1f}s")
    t.add_row("Modules run",     str(len(done)))
    t.add_row("Errors",          str(len(errors)) if errors else "[green]0[/green]")
    t.add_row("Total findings",  str(total_findings))
    console.print(t)


def _export_report(target: str, dash: OmegaDashboard, output_dir: str):
    from omega_cli import reporter
    data = {}
    for name, r in dash.results.items():
        if r.output:
            data[name] = r.output
    try:
        html_path, json_path = reporter.generate(target, data, output_dir=output_dir)
        console.print(f"\n[green]📄 HTML:[/green] {html_path}")
        console.print(f"[green]📄 JSON:[/green] {json_path}")
    except Exception as e:
        console.print(f"[red]Report error:[/red] {e}")
