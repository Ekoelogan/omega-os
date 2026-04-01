"""Intelligence timeline — weaves all OSINT data into a chronological narrative."""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
    "INFO": "cyan",
}


def _parse_date(val) -> datetime | None:
    if not val:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%d %b %Y",
        "%b %d %Y",
        "%Y%m%d",
    ]
    s = str(val).strip()
    for fmt in formats:
        try:
            dt = datetime.strptime(s[:len(fmt)], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    # Try extracting 4-digit year
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", s)
    if match:
        try:
            return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
        except Exception:
            pass
    return None


def _extract_events(target: str, findings: dict) -> list:
    events = []

    def add(date_val, category: str, title: str, detail: str, severity: str = "INFO"):
        dt = _parse_date(date_val)
        if dt:
            events.append({
                "date": dt,
                "date_str": dt.strftime("%Y-%m-%d"),
                "category": category,
                "title": title,
                "detail": str(detail)[:120],
                "severity": severity,
            })

    # WHOIS
    whois = findings.get("whois", {})
    if isinstance(whois, dict):
        add(whois.get("creation_date"), "Domain", "Domain Registered", f"Registrar: {whois.get('registrar','?')}")
        add(whois.get("updated_date"), "Domain", "WHOIS Updated", f"Registrar: {whois.get('registrar','?')}")
        add(whois.get("expiration_date"), "Domain", "Domain Expires", "⚠ Renewal due", "MEDIUM")

    # SSL
    ssl = findings.get("ssl", {})
    if isinstance(ssl, dict):
        add(ssl.get("not_before", ssl.get("valid_from")), "SSL", "SSL Cert Issued",
            f"Issuer: {ssl.get('issuer',{}).get('O','?') if isinstance(ssl.get('issuer'),dict) else ssl.get('issuer','?')}")
        add(ssl.get("not_after", ssl.get("valid_until")), "SSL", "SSL Cert Expires",
            "Certificate renewal required", "MEDIUM")

    # crtsh — cert transparency logs (subdomain discovery dates)
    crtsh = findings.get("crtsh", {})
    if isinstance(crtsh, dict):
        for sub in (crtsh.get("subdomains", []) or [])[:5]:
            if isinstance(sub, dict):
                add(sub.get("not_before"), "Subdomain", f"Subdomain cert issued: {sub.get('name','')}",
                    sub.get("name", ""))

    # Wayback Machine
    wayback = findings.get("wayback", {})
    if isinstance(wayback, dict):
        snapshots = wayback.get("snapshots", wayback.get("urls", []))
        if isinstance(snapshots, list) and snapshots:
            earliest = snapshots[0] if isinstance(snapshots[0], str) else snapshots[0].get("timestamp", "")
            latest = snapshots[-1] if isinstance(snapshots[-1], str) else snapshots[-1].get("timestamp", "")
            add(str(earliest)[:8], "Web Archive", "Earliest Wayback Snapshot", f"{len(snapshots)} snapshots total")
            add(str(latest)[:8], "Web Archive", "Latest Wayback Snapshot", f"{len(snapshots)} snapshots total")

    # Breach
    breach = findings.get("breach", {})
    if isinstance(breach, dict):
        for b in (breach.get("breaches") or []):
            if isinstance(b, dict):
                add(b.get("BreachDate"), "Breach", f"Data Breach: {b.get('Name','?')}",
                    f"{b.get('PwnCount',0):,} accounts  Data: {', '.join(b.get('DataClasses',[])[:3])}",
                    "HIGH")

    # CVEs
    cves = findings.get("cvemap", {})
    if isinstance(cves, dict):
        for cve in (cves.get("cves", []) or [])[:10]:
            if isinstance(cve, dict):
                score = cve.get("score", 0)
                sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM"
                add(cve.get("published"), "CVE", f"{cve.get('id','?')} — CVSS {score}",
                    cve.get("description", "")[:100], sev)

    # Monitor snapshots
    from omega_cli.modules.monitor import MONITOR_DIR
    snap_file = MONITOR_DIR / f"{target.replace('.','_').replace('/','_')}.json"
    if snap_file.exists():
        try:
            snap = json.loads(snap_file.read_text())
            add(snap.get("timestamp"), "Monitor", "Last Monitoring Snapshot",
                f"Hash: {snap.get('hash','?')}")
        except Exception:
            pass

    return sorted(events, key=lambda e: e["date"])


def run(target: str, findings: dict = None, json_file: str = ""):
    """Build a chronological intelligence timeline for a target."""
    console.print(Panel(
        f"[bold #ff2d78]📅 Intelligence Timeline[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    # Load findings
    if json_file:
        try:
            findings = json.loads(Path(json_file).read_text())
        except Exception as e:
            console.print(f"[red]Could not load:[/] {e}")
            findings = {}

    if not findings:
        report_dir = Path.home() / "omega-reports"
        safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
        candidates = sorted(report_dir.glob(f"omega_auto_{safe}_*.json"), reverse=True)
        if candidates:
            findings = json.loads(candidates[0].read_text())
            console.print(f"[dim]Loaded: {candidates[0].name}[/]")
        else:
            console.print("[yellow]No saved findings.[/]  Run: [cyan]omega auto {target}[/]")
            findings = {}

    events = _extract_events(target, findings)

    if not events:
        console.print("[yellow]No datable events found in findings.[/]")
        console.print("[dim]Tip: Run omega auto, breach, or cve first to populate dates.[/]")
        return []

    # Group by year
    from itertools import groupby
    events_by_year = {}
    for e in events:
        y = e["date"].year
        events_by_year.setdefault(y, []).append(e)

    for year in sorted(events_by_year.keys()):
        console.print(f"\n[bold #ff2d78]── {year} ──────────────────────────────[/]")
        for e in events_by_year[year]:
            sev_color = SEVERITY_COLORS.get(e["severity"], "white")
            cat_colors = {
                "Domain": "yellow", "SSL": "blue", "Breach": "red",
                "CVE": "red", "Subdomain": "magenta", "Web Archive": "dim",
                "Monitor": "cyan",
            }
            cat_color = cat_colors.get(e["category"], "white")
            console.print(
                f"  [dim]{e['date_str']}[/]  "
                f"[{cat_color}]{e['category']:<12}[/]  "
                f"[{sev_color}]{e['title']}[/]"
            )
            if e["detail"]:
                console.print(f"               [dim]{e['detail']}[/]")

    # Summary
    console.print()
    tbl = Table(title="Timeline Summary", box=box.ROUNDED, border_style="#ff85b3")
    tbl.add_column("Category", style="bold")
    tbl.add_column("Events", style="cyan", width=8)
    from collections import Counter
    for cat, count in Counter(e["category"] for e in events).most_common():
        tbl.add_row(cat, str(count))
    console.print(tbl)
    console.print(f"\n[bold]Total events:[/] [cyan]{len(events)}[/]  "
                  f"[bold]Span:[/] {events[0]['date_str']} → {events[-1]['date_str']}")

    return events
