"""Automated recon orchestrator — chains all modules and produces a complete intelligence package."""
import threading
import time
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich import box

console = Console()


PHASE_PASSIVE = [
    ("whois",      "WHOIS",           lambda t, cfg: _run("whois_lookup", t, cfg)),
    ("dns",        "DNS Records",     lambda t, cfg: _run("dns_lookup", t, cfg)),
    ("ssl",        "SSL Cert",        lambda t, cfg: _run("ssl_check", t, cfg)),
    ("headers",    "HTTP Headers",    lambda t, cfg: _run_url("headers", t, cfg)),
    ("tech",       "Tech Fingerprint",lambda t, cfg: _run_url("techfp", t, cfg)),
    ("crtsh",      "Cert Transparency",lambda t, cfg: _run("crtsh", t, cfg)),
    ("wayback",    "Wayback Machine", lambda t, cfg: _run("wayback", t, cfg)),
    ("crawl",      "robots/sitemap",  lambda t, cfg: _run("crawl", t, cfg)),
]

PHASE_ACTIVE = [
    ("ports",      "Port Scan",       lambda t, cfg: _run("portscan", t, cfg)),
    ("subdomains", "Subdomains",      lambda t, cfg: _run("subdomain", t, cfg)),
    ("reverseip",  "Reverse IP",      lambda t, cfg: _run("reverseip", t, cfg)),
    ("buckets",    "Cloud Buckets",   lambda t, cfg: _run("buckets", t, cfg)),
    ("spoofcheck", "Email Spoof",     lambda t, cfg: _run("spoofcheck", t, cfg)),
    ("jscan",      "JS Secrets",      lambda t, cfg: _run_url("jscan", t, cfg)),
    ("harvest",    "Email Harvest",   lambda t, cfg: _run("harvester", t, cfg)),
    ("typo",       "Typosquatting",   lambda t, cfg: _run_typo(t, cfg)),
]

PHASE_INTEL = [
    ("cvemap",     "CVE Map",         lambda t, cfg: _run("cvemap", t, cfg)),
    ("threat",     "Threat Intel",    lambda t, cfg: _run("threatintel", t, cfg)),
    ("cors",       "CORS Check",      lambda t, cfg: _run("corscheck", t, cfg)),
    ("phish",      "Phish Check",     lambda t, cfg: _run_phish(t, cfg)),
]


def _run(module: str, target: str, cfg: dict):
    try:
        mod = __import__(f"omega_cli.modules.{module}", fromlist=["run"])
        return mod.run(target) or {}
    except Exception as e:
        return {"error": str(e)}


def _run_url(module: str, target: str, cfg: dict):
    try:
        mod = __import__(f"omega_cli.modules.{module}", fromlist=["run"])
        url = target if target.startswith("http") else f"https://{target}"
        return mod.run(url) or {}
    except Exception as e:
        return {"error": str(e)}


def _run_typo(target: str, cfg: dict):
    try:
        from omega_cli.modules.typosquat import run
        return run(target, probe=True, limit=100) or {}
    except Exception as e:
        return {"error": str(e)}


def _run_phish(target: str, cfg: dict):
    try:
        from omega_cli.modules.phishcheck import run
        return run(target, api_key=cfg.get("urlscan_api_key", ""),
                   gsb_key=cfg.get("gsb_api_key", "")) or {}
    except Exception as e:
        return {"error": str(e)}


def run(target: str, passive_only: bool = False, output_dir: str = ""):
    """Full automated recon — chains all modules, saves PDF + JSON intelligence package."""
    start_time = time.time()

    console.print(Panel(
        f"[bold #ff2d78]⚡ OMEGA AUTO — Full Recon Orchestrator[/]\n"
        f"[dim]Target:[/] [cyan]{target}[/]  "
        f"[dim]Mode:[/] [yellow]{'passive-only' if passive_only else 'full'}[/]  "
        f"[dim]Started:[/] {datetime.now().strftime('%H:%M:%S')}",
        border_style="#ff85b3",
    ))

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()

    all_findings = {}
    all_phases = PHASE_PASSIVE + ([] if passive_only else PHASE_ACTIVE + PHASE_INTEL)
    total = len(all_phases)

    with Progress(
        SpinnerColumn(style="bold #ff2d78"),
        TextColumn("[bold #ff85b3]{task.description}"),
        BarColumn(bar_width=30, style="#ff2d78", complete_style="#ff85b3"),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Running modules...", total=total)
        lock = threading.Lock()
        completed = [0]

        def run_module(key, label, func):
            result = {}
            try:
                result = func(target, cfg) or {}
            except Exception as e:
                result = {"error": str(e)}
            with lock:
                all_findings[key] = result
                completed[0] += 1
                progress.update(task, advance=1, description=f"[bold #ff85b3]{label}[/]")

        # Run passive phase sequentially (avoids DNS storm)
        for key, label, func in PHASE_PASSIVE:
            run_module(key, label, func)

        if not passive_only:
            # Run active + intel phases in parallel threads
            threads = []
            for key, label, func in PHASE_ACTIVE + PHASE_INTEL:
                t = threading.Thread(target=run_module, args=(key, label, func), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=60)

    elapsed = time.time() - start_time

    # Summary table
    tbl = Table(
        title=f"[bold #ff2d78]OMEGA AUTO — Results for {target}[/]",
        box=box.ROUNDED, border_style="#ff85b3",
    )
    tbl.add_column("Module", style="bold")
    tbl.add_column("Status", width=10)
    tbl.add_column("Key Findings")

    for key, label, _ in all_phases:
        data = all_findings.get(key, {})
        if "error" in data:
            status = "[red]ERROR[/]"
            finding = str(data["error"])[:80]
        elif data:
            status = "[green]✓[/]"
            # Extract most meaningful field
            finding = _summarize(key, data)
        else:
            status = "[dim]empty[/]"
            finding = ""
        tbl.add_row(label, status, finding)

    console.print(tbl)
    console.print(f"\n[dim]Elapsed:[/] [cyan]{elapsed:.1f}s[/]  [dim]Modules:[/] {total}  [dim]Findings:[/] {sum(1 for v in all_findings.values() if v and 'error' not in v)}")

    # Export PDF
    try:
        from omega_cli.modules.pdfreport import export_pdf
        out_dir = Path(output_dir) if output_dir else Path.home() / "omega-reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = target.replace(".", "_").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        pdf_path = str(out_dir / f"omega_auto_{safe}_{ts}.pdf")
        saved = export_pdf(target, all_findings, pdf_path)
        console.print(f"[green]✓[/] Report: [cyan]{saved}[/]")
    except Exception as e:
        console.print(f"[yellow]PDF export failed:[/] {e}")

    # Save JSON
    try:
        import json
        json_path = str(out_dir / f"omega_auto_{safe}_{ts}.json")
        Path(json_path).write_text(json.dumps(all_findings, indent=2, default=str))
        console.print(f"[green]✓[/] JSON: [cyan]{json_path}[/]")
    except Exception as e:
        console.print(f"[yellow]JSON export failed:[/] {e}")

    return all_findings


def _summarize(key: str, data: dict) -> str:
    """Extract a one-line summary from module results."""
    if key == "whois":
        return str(data.get("registrar", data.get("org", "")))[:80]
    if key == "dns":
        a = data.get("A", data.get("a", []))
        return f"A: {', '.join(a[:3]) if isinstance(a, list) else a}"[:80]
    if key == "ssl":
        return f"Issuer: {data.get('issuer', {}).get('O', '')}  Expires: {str(data.get('not_after', ''))[:10]}"
    if key == "headers":
        score = data.get("security_score", data.get("score", ""))
        return f"Score: {score}" if score else str(list(data.keys())[:3])[:80]
    if key == "tech":
        techs = data.get("technologies", data.get("tech", []))
        if isinstance(techs, list):
            return ", ".join(str(t) for t in techs[:5])
    if key == "crtsh":
        subs = data.get("subdomains", [])
        return f"{len(subs)} subdomains" if subs else ""
    if key == "ports":
        open_p = data.get("open_ports", [])
        return f"Open: {open_p[:8]}" if open_p else "No open ports"
    if key == "harvest":
        emails = data.get("emails", [])
        return f"{len(emails)} emails found"
    if key == "typo":
        live = data.get("live", [])
        return f"{len(live)} live lookalikes" if live else f"{len(data.get('permutations', []))} permutations checked"
    if key == "cors":
        return "[red]VULNERABLE[/]" if data.get("vulnerable") else "clean"
    if key == "phish":
        return f"Risk: {data.get('risk_level', '?')}"
    if key == "cvemap":
        cves = data.get("cves", [])
        return f"{len(cves)} CVEs mapped" if cves else ""
    return str(list(data.values())[0])[:80] if data else ""
