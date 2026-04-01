"""omega compare — Diff two omega recon JSON outputs to surface changes over time."""
from __future__ import annotations
import glob
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def _load(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]File not found:[/red] {path}")
        return {}
    return json.loads(p.read_text())


def _flatten(d: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict to dot-notation keys → scalar/list values."""
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        elif isinstance(v, list):
            out[key] = sorted(str(x) for x in v)
        else:
            out[key] = v
    return out


def _compare(old: dict, new: dict) -> dict:
    old_flat = _flatten(old)
    new_flat = _flatten(new)

    all_keys  = set(old_flat) | set(new_flat)
    added     = {k: new_flat[k] for k in all_keys if k not in old_flat}
    removed   = {k: old_flat[k] for k in all_keys if k not in new_flat}
    changed   = {k: (old_flat[k], new_flat[k]) for k in all_keys
                 if k in old_flat and k in new_flat and old_flat[k] != new_flat[k]}
    unchanged = {k for k in all_keys if k in old_flat and k in new_flat
                 and old_flat[k] == new_flat[k]}

    return {
        "added":     added,
        "removed":   removed,
        "changed":   changed,
        "unchanged": len(unchanged),
    }


def _auto_find(target: str, newest: bool = True) -> list[str]:
    patterns = [
        f"omega_auto_{target}_*.json",
        f"*{target}*.json",
    ]
    files = []
    for pat in patterns:
        files += glob.glob(pat) + glob.glob(os.path.expanduser(f"~/{pat}"))
    files = sorted(set(files), key=os.path.getmtime)
    return files


def run(target: str, old_file: str = "", new_file: str = "") -> None:
    console.print(Panel(
        f"[bold #ff2d78]📊  Recon Diff[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    # Auto-discover if files not specified
    if not old_file or not new_file:
        candidates = _auto_find(target)
        if len(candidates) < 2:
            console.print("[yellow]Need at least 2 recon JSON files to diff.[/yellow]")
            console.print(f"  Run [bold]omega auto {target}[/bold] twice, or pass --old FILE --new FILE")
            if candidates:
                console.print(f"  Found: {candidates[-1]}")
            return
        old_file = old_file or candidates[-2]
        new_file = new_file or candidates[-1]

    console.print(f"[dim]Old:[/dim] {old_file}")
    console.print(f"[dim]New:[/dim] {new_file}\n")

    old = _load(old_file)
    new = _load(new_file)
    if not old or not new:
        return

    delta = _compare(old, new)
    added   = delta["added"]
    removed = delta["removed"]
    changed = delta["changed"]

    # Summary
    summary_tbl = Table(show_header=False, box=None, padding=(0, 2))
    summary_tbl.add_column("", style="bold")
    summary_tbl.add_column("", style="white")
    summary_tbl.add_row("[green]Added[/green]",    str(len(added)))
    summary_tbl.add_row("[red]Removed[/red]",      str(len(removed)))
    summary_tbl.add_row("[yellow]Changed[/yellow]",str(len(changed)))
    summary_tbl.add_row("[dim]Unchanged[/dim]",    str(delta["unchanged"]))
    console.print(summary_tbl)

    if added:
        console.print(f"\n[bold green]➕ Added ({len(added)}):[/bold green]")
        tbl = Table(show_lines=True)
        tbl.add_column("Key",   style="bold green", max_width=35)
        tbl.add_column("Value", style="cyan",        max_width=60)
        for k, v in list(added.items())[:20]:
            tbl.add_row(k, str(v)[:58] + ("…" if len(str(v)) > 58 else ""))
        console.print(tbl)

    if removed:
        console.print(f"\n[bold red]➖ Removed ({len(removed)}):[/bold red]")
        tbl = Table(show_lines=True)
        tbl.add_column("Key",   style="bold red", max_width=35)
        tbl.add_column("Value", style="dim",      max_width=60)
        for k, v in list(removed.items())[:20]:
            tbl.add_row(k, str(v)[:58] + ("…" if len(str(v)) > 58 else ""))
        console.print(tbl)

    if changed:
        console.print(f"\n[bold yellow]🔄 Changed ({len(changed)}):[/bold yellow]")
        tbl = Table(show_lines=True)
        tbl.add_column("Key",    style="bold yellow", max_width=30)
        tbl.add_column("Before", style="red",         max_width=30)
        tbl.add_column("After",  style="green",       max_width=30)
        for k, (before, after) in list(changed.items())[:20]:
            tbl.add_row(k, str(before)[:28], str(after)[:28])
        console.print(tbl)

    # Security highlights
    security_keys = {"port", "vuln", "cve", "subdomain", "dns", "certificate",
                     "phish", "breach", "shodan", "cloud"}
    sec_added   = {k: v for k, v in added.items()   if any(s in k.lower() for s in security_keys)}
    sec_removed = {k: v for k, v in removed.items() if any(s in k.lower() for s in security_keys)}

    if sec_added or sec_removed:
        console.print(f"\n[bold #ff2d78]⚠  Security-relevant changes:[/bold #ff2d78]")
        for k, v in sec_added.items():
            console.print(f"  [green]+[/green] [bold]{k}[/bold]: {str(v)[:50]}")
        for k, v in sec_removed.items():
            console.print(f"  [red]-[/red] [bold]{k}[/bold]: {str(v)[:50]}")

    if not added and not removed and not changed:
        console.print("\n[green]✓  No differences found. Recon results are identical.[/green]")
