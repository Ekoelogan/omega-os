"""Continuous target monitoring with change detection and alerting."""
import json
import time
import hashlib
import os
import threading
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box

console = Console()

MONITOR_DIR = Path.home() / ".config" / "omega-cli" / "monitor"
MONITOR_DIR.mkdir(parents=True, exist_ok=True)


def _snapshot_file(target: str) -> Path:
    safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
    return MONITOR_DIR / f"{safe}.json"


def _load_snapshot(target: str) -> dict:
    f = _snapshot_file(target)
    if f.exists():
        try:
            return json.loads(f.read_text())
        except Exception:
            pass
    return {}


def _save_snapshot(target: str, data: dict):
    _snapshot_file(target).write_text(json.dumps(data, indent=2, default=str))


def _hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _collect_snapshot(target: str) -> dict:
    """Collect lightweight snapshot of target state."""
    snap = {"timestamp": datetime.now().isoformat(), "checks": {}}

    # DNS A records
    try:
        import dns.resolver
        answers = dns.resolver.resolve(target, "A", lifetime=5)
        snap["checks"]["dns_a"] = sorted([str(r) for r in answers])
    except Exception as e:
        snap["checks"]["dns_a"] = f"error: {e}"

    # HTTP headers fingerprint
    try:
        import requests
        r = requests.head(f"https://{target}", timeout=8, allow_redirects=True)
        snap["checks"]["http_status"] = r.status_code
        snap["checks"]["http_server"] = r.headers.get("Server", "")
        snap["checks"]["http_powered"] = r.headers.get("X-Powered-By", "")
        snap["checks"]["final_url"] = r.url
    except Exception:
        try:
            import requests
            r = requests.head(f"http://{target}", timeout=8, allow_redirects=True)
            snap["checks"]["http_status"] = r.status_code
        except Exception as e:
            snap["checks"]["http_status"] = f"error: {e}"

    # SSL cert expiry
    try:
        import ssl
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(__import__("socket").socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            snap["checks"]["ssl_not_after"] = cert.get("notAfter", "")
            snap["checks"]["ssl_subject"] = dict(x[0] for x in cert.get("subject", []))
    except Exception:
        pass

    # crt.sh subdomain count
    try:
        import requests
        r = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        if r.status_code == 200:
            subs = set()
            for e in r.json():
                for n in e.get("name_value", "").split("\n"):
                    subs.add(n.strip().lstrip("*."))
            snap["checks"]["subdomain_count"] = len(subs)
    except Exception:
        pass

    snap["hash"] = _hash(snap["checks"])
    return snap


def _diff_snapshots(old: dict, new: dict) -> list:
    """Return list of change descriptions."""
    changes = []
    old_c = old.get("checks", {})
    new_c = new.get("checks", {})
    for key in set(list(old_c.keys()) + list(new_c.keys())):
        o = old_c.get(key)
        n = new_c.get(key)
        if o != n:
            changes.append({
                "field": key,
                "old": o,
                "new": n,
                "severity": _change_severity(key, o, n),
            })
    return changes


def _change_severity(field: str, old, new) -> str:
    if field == "dns_a":
        return "CRITICAL"
    if field == "http_status" and isinstance(new, int) and new >= 500:
        return "HIGH"
    if field in ("ssl_not_after", "ssl_subject"):
        return "HIGH"
    if field == "subdomain_count" and isinstance(old, int) and isinstance(new, int) and new > old:
        return "MEDIUM"
    if "server" in field.lower() or "powered" in field.lower():
        return "MEDIUM"
    return "LOW"


def _send_webhook(url: str, payload: dict):
    try:
        import requests
        requests.post(url, json=payload, timeout=10)
    except Exception:
        pass


def watch(target: str, interval: int = 300, webhook: str = ""):
    """Continuously monitor a target and alert on changes."""
    console.print(Panel(
        f"[bold #ff2d78]👁  Monitor Mode[/]\n"
        f"[dim]Target:[/] [cyan]{target}[/]  "
        f"[dim]Interval:[/] [yellow]{interval}s[/]  "
        f"[dim]Webhook:[/] [green]{'set' if webhook else 'not set'}[/]",
        border_style="#ff85b3",
    ))

    console.print("[dim]Taking initial snapshot...[/]")
    snapshot = _collect_snapshot(target)
    prev = _load_snapshot(target)

    if not prev:
        _save_snapshot(target, snapshot)
        console.print(f"[green]✓[/] Baseline snapshot saved. Hash: [cyan]{snapshot['hash']}[/]")
        prev = snapshot

    alert_count = 0

    def render_status():
        t = Table(box=box.SIMPLE, show_header=False)
        t.add_column("", style="dim")
        t.add_column("")
        t.add_row("Target", f"[cyan]{target}[/]")
        t.add_row("Last check", f"[white]{snapshot.get('timestamp','?')[:19]}[/]")
        t.add_row("Alerts fired", f"[{'red' if alert_count else 'green'}]{alert_count}[/]")
        t.add_row("Next check", f"[dim]in {interval}s[/]")
        return Panel(t, title="[bold #ff2d78]OMEGA MONITOR[/]", border_style="#ff85b3")

    console.print(render_status())
    console.print(f"\n[dim]Monitoring every {interval}s — press Ctrl+C to stop[/]\n")

    try:
        while True:
            time.sleep(interval)
            console.print(f"\n[dim]{datetime.now().strftime('%H:%M:%S')}[/] [#ff2d78]◆[/] Checking {target}...")
            snapshot = _collect_snapshot(target)
            changes = _diff_snapshots(prev, snapshot)

            if changes:
                alert_count += len(changes)
                tbl = Table(
                    title=f"[bold red]⚠  {len(changes)} Change(s) Detected[/]",
                    box=box.ROUNDED, border_style="red",
                )
                tbl.add_column("Field", style="bold")
                tbl.add_column("Severity")
                tbl.add_column("Before", style="dim")
                tbl.add_column("After", style="yellow")
                for c in changes:
                    sev_color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "dim"}.get(c["severity"], "white")
                    tbl.add_row(
                        c["field"],
                        f"[{sev_color}]{c['severity']}[/]",
                        str(c["old"])[:60],
                        str(c["new"])[:60],
                    )
                console.print(tbl)
                _save_snapshot(target, snapshot)
                prev = snapshot

                if webhook:
                    _send_webhook(webhook, {
                        "source": "omega-monitor",
                        "target": target,
                        "timestamp": snapshot["timestamp"],
                        "changes": changes,
                    })
            else:
                console.print(f"[green]✓[/] No changes detected  (hash: [dim]{snapshot['hash']}[/])")

    except KeyboardInterrupt:
        console.print("\n[bold #ff2d78]Monitor stopped.[/]")

    return {"target": target, "alerts": alert_count}


def status(target: str):
    """Show last saved snapshot for a target."""
    snap = _load_snapshot(target)
    if not snap:
        console.print(f"[yellow]No snapshot found for {target}[/]")
        return

    tbl = Table(title=f"Last Snapshot: {target}", box=box.ROUNDED, border_style="#ff85b3")
    tbl.add_column("Check", style="bold")
    tbl.add_column("Value", style="cyan")
    tbl.add_row("Timestamp", snap.get("timestamp", "?")[:19])
    tbl.add_row("Hash", snap.get("hash", "?"))
    for k, v in snap.get("checks", {}).items():
        tbl.add_row(k, str(v)[:80])
    console.print(tbl)
    return snap


def list_targets():
    """List all monitored targets."""
    files = list(MONITOR_DIR.glob("*.json"))
    if not files:
        console.print("[dim]No monitored targets yet.[/]")
        return []
    tbl = Table(title="Monitored Targets", box=box.ROUNDED, border_style="#ff85b3")
    tbl.add_column("Target", style="cyan")
    tbl.add_column("Last Snapshot", style="dim")
    tbl.add_column("Hash")
    targets = []
    for f in files:
        try:
            data = json.loads(f.read_text())
            tbl.add_row(
                f.stem.replace("_", "."),
                data.get("timestamp", "?")[:19],
                data.get("hash", "?"),
            )
            targets.append(f.stem)
        except Exception:
            pass
    console.print(tbl)
    return targets
