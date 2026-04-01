"""omega watcher — Persistent cron daemon: re-runs chains, diffs results, fires webhooks."""
from __future__ import annotations
import json
import os
import signal
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

WATCHER_DIR   = Path.home() / ".omega" / "watcher"
WATCHER_STATE = WATCHER_DIR / "state.json"
WATCHER_PID   = WATCHER_DIR / "watcher.pid"
WATCHER_LOG   = WATCHER_DIR / "watcher.log"


def _load_state() -> dict:
    WATCHER_DIR.mkdir(parents=True, exist_ok=True)
    if WATCHER_STATE.exists():
        try:
            return json.loads(WATCHER_STATE.read_text())
        except Exception:
            pass
    return {"watchers": {}, "history": []}


def _save_state(state: dict) -> None:
    WATCHER_DIR.mkdir(parents=True, exist_ok=True)
    WATCHER_STATE.write_text(json.dumps(state, indent=2, default=str))


def _log(msg: str) -> None:
    WATCHER_DIR.mkdir(parents=True, exist_ok=True)
    ts  = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(WATCHER_LOG, "a") as f:
        f.write(f"[{ts}] {msg}\n")


def _run_check(target: str, chain_name: str) -> dict | None:
    """Run a chain and capture JSON output."""
    try:
        from click.testing import CliRunner
        from omega_cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["auto", target, "--passive"], catch_exceptions=True)
        if result.exit_code == 0:
            # Try to find the generated JSON
            import glob
            files = sorted(
                glob.glob(f"omega_auto_{target}_*.json") +
                glob.glob(os.path.expanduser(f"~/omega_auto_{target}_*.json")),
                key=os.path.getmtime,
            )
            if files:
                return json.loads(Path(files[-1]).read_text())
        return None
    except Exception as e:
        _log(f"Check failed for {target}: {e}")
        return None


def _simple_fingerprint(data: dict) -> str:
    """Generate a stable fingerprint for comparison."""
    import hashlib
    flat = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(flat.encode()).hexdigest()[:16]


def _send_alert(target: str, change_summary: str, webhook_url: str) -> None:
    if not webhook_url:
        return
    try:
        import requests
        payload = {
            "text": f"🚨 omega watcher: **{target}** changed\n```{change_summary[:500]}```",
            "username": "omega-watcher",
        }
        requests.post(webhook_url, json=payload, timeout=8)
        _log(f"Alert sent for {target} to webhook")
    except Exception as e:
        _log(f"Alert send failed: {e}")


def _diff_fingerprints(old_fp: str, new_fp: str, target: str) -> str:
    if old_fp != new_fp:
        return f"Fingerprint changed: {old_fp} → {new_fp}"
    return ""


def add_watcher(target: str, interval: int = 3600,
                chain: str = "quick-recon", webhook: str = "") -> None:
    state = _load_state()
    state["watchers"][target] = {
        "target":       target,
        "interval":     interval,
        "chain":        chain,
        "webhook":      webhook,
        "added":        datetime.utcnow().isoformat(),
        "last_run":     None,
        "last_fp":      None,
        "run_count":    0,
        "change_count": 0,
    }
    _save_state(state)
    console.print(f"[green]✓[/green] Watcher added: [cyan]{target}[/cyan]  "
                  f"interval={interval}s  chain={chain}")


def remove_watcher(target: str) -> None:
    state = _load_state()
    if target in state["watchers"]:
        del state["watchers"][target]
        _save_state(state)
        console.print(f"[green]✓[/green] Watcher removed: [cyan]{target}[/cyan]")
    else:
        console.print(f"[yellow]No watcher found for:[/yellow] {target}")


def list_watchers() -> None:
    state = _load_state()
    ws    = state.get("watchers", {})
    if not ws:
        console.print("[dim]No active watchers.[/dim]")
        console.print("Add one: [bold]omega watcher add <target> --interval 3600[/bold]")
        return

    tbl = Table(title="Active Watchers", show_lines=True)
    tbl.add_column("Target",   style="bold cyan")
    tbl.add_column("Interval", justify="right")
    tbl.add_column("Chain",    style="dim")
    tbl.add_column("Last Run", style="dim")
    tbl.add_column("Runs",     justify="right")
    tbl.add_column("Changes",  justify="right", style="bold #ff2d78")

    for target, w in ws.items():
        last = w.get("last_run") or "never"
        if last != "never":
            last = last[:16]
        tbl.add_row(target, f"{w.get('interval',3600)}s",
                    w.get("chain",""), last,
                    str(w.get("run_count",0)),
                    str(w.get("change_count",0)))
    console.print(tbl)

    # Show daemon status
    if WATCHER_PID.exists():
        pid = WATCHER_PID.read_text().strip()
        try:
            os.kill(int(pid), 0)
            console.print(f"\n[green]✓  Daemon running[/green]  PID: {pid}")
        except ProcessLookupError:
            console.print(f"\n[yellow]⚠  Daemon not running (stale PID {pid})[/yellow]")
            WATCHER_PID.unlink(missing_ok=True)
    else:
        console.print("\n[dim]Daemon not running. Start with:[/dim] [bold]omega watcher daemon[/bold]")


def _daemon_loop() -> None:
    """Main daemon loop — runs in background."""
    _log("Daemon started")
    while True:
        state = _load_state()
        now   = time.time()
        for target, w in list(state["watchers"].items()):
            last_run = w.get("last_run_ts", 0)
            interval = w.get("interval", 3600)
            if now - last_run >= interval:
                _log(f"Running check: {target}")
                result = _run_check(target, w.get("chain", "quick-recon"))
                if result:
                    fp    = _simple_fingerprint(result)
                    old_fp = w.get("last_fp")
                    w["last_fp"]      = fp
                    w["last_run"]     = datetime.utcnow().isoformat()
                    w["last_run_ts"]  = now
                    w["run_count"]    = w.get("run_count", 0) + 1
                    if old_fp and old_fp != fp:
                        w["change_count"] = w.get("change_count", 0) + 1
                        summary = f"Fingerprint changed: {old_fp} → {fp}"
                        _log(f"CHANGE DETECTED: {target} — {summary}")
                        _send_alert(target, summary, w.get("webhook", ""))
                    _save_state(state)
        time.sleep(30)  # poll every 30s


def start_daemon() -> None:
    import subprocess, sys
    WATCHER_DIR.mkdir(parents=True, exist_ok=True)

    if WATCHER_PID.exists():
        pid = WATCHER_PID.read_text().strip()
        try:
            os.kill(int(pid), 0)
            console.print(f"[yellow]Daemon already running[/yellow]  PID: {pid}")
            return
        except ProcessLookupError:
            WATCHER_PID.unlink(missing_ok=True)

    # Fork daemon
    pid = os.fork() if hasattr(os, "fork") else None
    if pid is None:
        # No fork — run in foreground
        console.print("[dim]os.fork not available — running in foreground (Ctrl+C to stop)[/dim]")
        _daemon_loop()
        return
    if pid > 0:
        WATCHER_PID.write_text(str(pid))
        console.print(f"[green]✓[/green] Watcher daemon started  PID: {pid}")
        console.print(f"[dim]Log:[/dim] {WATCHER_LOG}")
    else:
        # Child
        os.setsid()
        _daemon_loop()


def stop_daemon() -> None:
    if not WATCHER_PID.exists():
        console.print("[yellow]No daemon PID file found.[/yellow]")
        return
    pid = int(WATCHER_PID.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        WATCHER_PID.unlink(missing_ok=True)
        console.print(f"[green]✓[/green] Daemon stopped  PID: {pid}")
    except ProcessLookupError:
        console.print("[yellow]Daemon process not found (already stopped?).[/yellow]")
        WATCHER_PID.unlink(missing_ok=True)


def run(action: str, target: str = "", interval: int = 3600,
        chain: str = "quick-recon", webhook: str = "") -> None:
    if action == "add":
        if not target:
            console.print("[red]Target required.[/red] Usage: omega watcher add <target>")
            return
        add_watcher(target, interval=interval, chain=chain, webhook=webhook)
    elif action == "remove":
        remove_watcher(target)
    elif action == "list":
        list_watchers()
    elif action == "daemon":
        start_daemon()
    elif action == "stop":
        stop_daemon()
    elif action == "log":
        if WATCHER_LOG.exists():
            console.print(WATCHER_LOG.read_text()[-3000:])
        else:
            console.print("[dim]No log file yet.[/dim]")
    else:
        console.print(f"[red]Unknown action:[/red] {action}  (add|remove|list|daemon|stop|log)")
