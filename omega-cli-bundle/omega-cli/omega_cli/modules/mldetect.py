"""omega ml — ML anomaly detection: baseline a target, detect deviations in future scans."""
from __future__ import annotations
import json
import math
import statistics
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

BASELINE_DIR = Path.home() / ".omega" / "baselines"


def _load_json(path: str) -> dict:
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else {}


def _flatten_numeric(d: dict, prefix: str = "") -> dict[str, float]:
    """Extract all numeric leaf values from a nested dict."""
    out: dict[str, float] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, (int, float)):
            out[key] = float(v)
        elif isinstance(v, list):
            out[key + ".count"] = float(len(v))
        elif isinstance(v, dict):
            out.update(_flatten_numeric(v, key))
    return out


def _flatten_sets(d: dict, prefix: str = "") -> dict[str, set[str]]:
    """Extract all list/set leaf values."""
    out: dict[str, set[str]] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, list):
            out[key] = set(str(x) for x in v)
        elif isinstance(v, dict):
            out.update(_flatten_sets(v, key))
    return out


def _zscore(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0
    return abs(value - mean) / std


class Baseline:
    def __init__(self, target: str):
        self.target = target
        self.file   = BASELINE_DIR / f"{target.replace('/', '_')}.json"
        self.data: dict[str, list[float]] = {}   # key → [values across scans]
        self.sets: dict[str, list[set]]   = {}   # key → [sets across scans]
        self._load()

    def _load(self) -> None:
        if self.file.exists():
            raw = json.loads(self.file.read_text())
            self.data = raw.get("numeric", {})
            self.sets = {k: [set(s) for s in v] for k, v in raw.get("sets", {}).items()}

    def _save(self) -> None:
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        raw = {
            "target":  self.target,
            "numeric": self.data,
            "sets":    {k: [list(s) for s in v] for k, v in self.sets.items()},
            "n_scans": len(next(iter(self.data.values()), [])),
        }
        self.file.write_text(json.dumps(raw, indent=2))

    def update(self, findings: dict) -> None:
        numeric = _flatten_numeric(findings)
        sets    = _flatten_sets(findings)
        for k, v in numeric.items():
            self.data.setdefault(k, []).append(v)
        for k, v in sets.items():
            self.sets.setdefault(k, []).append(v)
        self._save()

    def n_scans(self) -> int:
        vals = list(self.data.values())
        return len(vals[0]) if vals else 0

    def detect_anomalies(self, findings: dict, threshold: float = 2.0) -> list[dict]:
        if self.n_scans() < 2:
            return []

        anomalies: list[dict] = []
        numeric = _flatten_numeric(findings)
        sets    = _flatten_sets(findings)

        # Numeric anomalies (z-score)
        for k, v in numeric.items():
            history = self.data.get(k, [])
            if len(history) < 2:
                continue
            mean = statistics.mean(history)
            try:
                std  = statistics.stdev(history)
            except Exception:
                std = 0.0
            z = _zscore(v, mean, std)
            if z > threshold:
                anomalies.append({
                    "key":      k,
                    "type":     "numeric",
                    "value":    v,
                    "expected": f"{mean:.2f} ± {std:.2f}",
                    "z_score":  round(z, 2),
                    "severity": "HIGH" if z > 4 else "MEDIUM",
                })

        # Set anomalies — new items not seen before, items disappearing
        for k, current_set in sets.items():
            history = self.sets.get(k, [])
            if not history:
                continue
            # Union of all historical items
            historical_union = set().union(*history)
            new_items     = current_set - historical_union
            removed_items = historical_union - current_set

            if new_items:
                anomalies.append({
                    "key":      k,
                    "type":     "set_new",
                    "value":    list(new_items)[:5],
                    "expected": f"{len(historical_union)} known items",
                    "z_score":  None,
                    "severity": "MEDIUM",
                })
            if removed_items and len(history) >= 3:
                # Only flag disappearance if consistent across 3+ scans
                anomalies.append({
                    "key":      k,
                    "type":     "set_removed",
                    "value":    list(removed_items)[:5],
                    "expected": f"present in {len(history)} prior scans",
                    "z_score":  None,
                    "severity": "LOW",
                })

        return sorted(anomalies, key=lambda x: (0 if x["severity"] == "HIGH" else
                                                 1 if x["severity"] == "MEDIUM" else 2))


def run(target: str, json_file: str = "", action: str = "detect",
        threshold: float = 2.0) -> None:
    console.print(Panel(
        f"[bold #ff2d78]🤖  ML Anomaly Detection[/bold #ff2d78]  →  [cyan]{target}[/cyan]  "
        f"[dim][{action}][/dim]",
        expand=False,
    ))

    bl = Baseline(target)

    if action == "status":
        n = bl.n_scans()
        console.print(f"[bold]Baseline status for[/bold] [cyan]{target}[/cyan]:")
        console.print(f"  Scans in baseline: [bold]{n}[/bold]")
        console.print(f"  Baseline file:     {bl.file}")
        console.print(f"  Tracked metrics:   {len(bl.data)} numeric, {len(bl.sets)} set-valued")
        if n < 2:
            console.print(f"\n[yellow]Need at least 2 scans to detect anomalies.[/yellow]")
            console.print(f"Run [bold]omega ml {target} --action baseline[/bold] after each recon.")
        return

    # Load findings
    if not json_file:
        import glob as glob_mod
        import os
        patterns = [f"omega_auto_{target}_*.json", f"*{target}*.json"]
        files = []
        for pat in patterns:
            files += glob_mod.glob(pat) + glob_mod.glob(os.path.expanduser(f"~/{pat}"))
        if files:
            json_file = max(files, key=os.path.getmtime)
            console.print(f"[dim]Using:[/dim] {json_file}")

    findings = _load_json(json_file) if json_file else {}
    if not findings:
        console.print("[yellow]No findings JSON found.[/yellow] "
                      "Run [bold]omega auto " + target + "[/bold] first.")
        return

    if action == "baseline":
        bl.update(findings)
        n = bl.n_scans()
        console.print(f"[green]✓[/green] Baseline updated for [cyan]{target}[/cyan] "
                      f"([bold]{n}[/bold] scan{'s' if n != 1 else ''} recorded)")
        console.print(f"  Tracking [bold]{len(bl.data)}[/bold] numeric metrics, "
                      f"[bold]{len(bl.sets)}[/bold] set-valued metrics")
        if n < 2:
            console.print(f"\n[dim]Run at least one more scan then:[/dim] "
                          f"[bold]omega ml {target} --action detect[/bold]")
        return

    # Detect anomalies
    n = bl.n_scans()
    if n < 2:
        console.print(f"[yellow]Need at least 2 baseline scans (have {n}).[/yellow]")
        console.print(f"Run: [bold]omega ml {target} --action baseline[/bold]")
        return

    anomalies = bl.detect_anomalies(findings, threshold=threshold)
    console.print(f"[dim]Comparing against {n}-scan baseline (z-score threshold: {threshold})[/dim]\n")

    if not anomalies:
        console.print("[green]✓  No anomalies detected. Findings match baseline.[/green]")
        return

    tbl = Table(title=f"Anomalies Detected ({len(anomalies)})", show_lines=True)
    tbl.add_column("Severity", width=8)
    tbl.add_column("Metric",   style="bold white", max_width=30)
    tbl.add_column("Type",     style="dim",        max_width=12)
    tbl.add_column("Value",    style="cyan",        max_width=25)
    tbl.add_column("Expected", style="dim",         max_width=22)
    tbl.add_column("Z-Score",  justify="right",     max_width=8)

    for a in anomalies:
        sev   = a["severity"]
        color = "#ff2d78" if sev == "HIGH" else ("#ffaa00" if sev == "MEDIUM" else "dim")
        z     = str(a["z_score"]) if a["z_score"] else "—"
        val   = str(a["value"])[:23]
        tbl.add_row(f"[bold {color}]{sev}[/bold {color}]",
                    a["key"][-28:], a["type"], val, str(a["expected"])[:20], z)
    console.print(tbl)

    high = sum(1 for a in anomalies if a["severity"] == "HIGH")
    if high:
        console.print(f"\n[bold red]⚠  {high} HIGH-severity anomalies — investigate immediately.[/bold red]")
