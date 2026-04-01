"""omega chain — YAML workflow pipeline runner for multi-step recon chains."""
from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

CHAINS_DIR  = Path.home() / ".omega" / "chains"
BUILTIN_CHAINS: dict[str, dict] = {
    "quick-recon": {
        "name":        "Quick Recon",
        "description": "Fast passive fingerprint: DNS + WHOIS + SSL + headers",
        "steps": [
            {"cmd": "dns",     "args": ["{{target}}"]},
            {"cmd": "whois",   "args": ["{{target}}"]},
            {"cmd": "ssl",     "args": ["{{target}}"]},
            {"cmd": "headers", "args": ["{{target}}"]},
        ],
    },
    "full-passive": {
        "name":        "Full Passive",
        "description": "Deep passive: subdomain + wayback + cert + tech + email harvest",
        "steps": [
            {"cmd": "subdomain", "args": ["{{target}}"]},
            {"cmd": "crtsh",    "args": ["{{target}}"]},
            {"cmd": "wayback",  "args": ["{{target}}"]},
            {"cmd": "tech",     "args": ["{{target}}"]},
            {"cmd": "harvest",  "args": ["{{target}}"]},
        ],
    },
    "threat-hunt": {
        "name":        "Threat Hunt Pipeline",
        "description": "Auto recon → IOC extract → MITRE ATT&CK mapping",
        "steps": [
            {"cmd": "auto",     "args": ["{{target}}"], "flags": ["--passive"]},
            {"cmd": "hunt",     "args": ["{{target}}"]},
            {"cmd": "timeline", "args": ["{{target}}"]},
        ],
    },
    "brand-monitor": {
        "name":        "Brand Monitor",
        "description": "Typosquat + phishing + breach + social",
        "steps": [
            {"cmd": "typo",   "args": ["{{target}}"]},
            {"cmd": "phish",  "args": ["{{target}}"]},
            {"cmd": "breach", "args": ["{{target}}"]},
            {"cmd": "social", "args": ["{{target}}"]},
        ],
    },
    "red-team": {
        "name":        "Red Team Surface",
        "description": "Git secrets + wordlist + fuzz + creds + c2 check",
        "steps": [
            {"cmd": "git",      "args": ["{{target}}"]},
            {"cmd": "wordlist", "args": ["{{target}}"]},
            {"cmd": "fuzz",     "args": ["{{target}}"]},
            {"cmd": "creds",    "args": ["{{target}}"]},
            {"cmd": "c2",       "args": ["{{target}}"]},
        ],
    },
    "opsec-check": {
        "name":        "OpSec & Anonymity",
        "description": "Proxy status + Tor check + OpSec audit",
        "steps": [
            {"cmd": "proxy",  "args": ["status"]},
            {"cmd": "opsec",  "args": []},
        ],
    },
}


def _load_chain(name: str) -> dict | None:
    # Built-ins first
    if name in BUILTIN_CHAINS:
        return BUILTIN_CHAINS[name]
    # User chains
    CHAINS_DIR.mkdir(parents=True, exist_ok=True)
    p = CHAINS_DIR / f"{name}.json"
    if p.exists():
        return json.loads(p.read_text())
    # Try YAML
    try:
        import yaml
        yp = CHAINS_DIR / f"{name}.yaml"
        if yp.exists():
            return yaml.safe_load(yp.read_text())
    except ImportError:
        pass
    return None


def _save_chain(name: str, chain: dict) -> None:
    CHAINS_DIR.mkdir(parents=True, exist_ok=True)
    p = CHAINS_DIR / f"{name}.json"
    p.write_text(json.dumps(chain, indent=2))
    console.print(f"[green]✓[/green] Chain saved: {p}")


def _render(template: str, vars: dict) -> str:
    for k, v in vars.items():
        template = template.replace(f"{{{{{k}}}}}", str(v))
    return template


def _run_step(step: dict, vars: dict, idx: int, total: int) -> bool:
    """Execute a single pipeline step via Click's test runner."""
    cmd   = step.get("cmd", "")
    args  = [_render(a, vars) for a in step.get("args", [])]
    flags = step.get("flags", [])
    condition = step.get("if", "")

    if condition:
        # Simple condition: "{{var}} != empty"
        rendered = _render(condition, vars)
        if "!= empty" in rendered:
            val = rendered.split("!=")[0].strip()
            if not val:
                console.print(f"  [dim]Skipping step {idx+1} (condition false)[/dim]")
                return True

    cmd_args = [cmd] + args + flags
    console.print(f"  [dim][{idx+1}/{total}][/dim] [bold]omega {' '.join(cmd_args)}[/bold]")

    try:
        from click.testing import CliRunner
        from omega_cli.main import cli
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(cli, cmd_args, catch_exceptions=False)
        if result.output:
            # Print without banner (skip first 10 lines which are banner)
            lines = result.output.split("\n")
            clean = "\n".join(l for l in lines if not any(
                c in l for c in ["█", "╔", "╚", "╗", "╝", "║", "OMEGA-CLI"]
            ))
            console.print(clean.strip())
        return result.exit_code == 0
    except Exception as exc:
        console.print(f"  [red]Step failed:[/red] {exc}")
        if step.get("continue_on_error"):
            return True
        return False


def run_chain(name: str, target: str = "", vars_extra: dict | None = None,
              dry_run: bool = False) -> None:
    chain = _load_chain(name)
    if not chain:
        console.print(f"[red]Chain not found:[/red] {name}")
        console.print("Use [bold]omega chain list[/bold] to see available chains.")
        return

    vars: dict = {"target": target}
    if vars_extra:
        vars.update(vars_extra)

    console.print(Panel(
        f"[bold #ff2d78]⛓  Chain:[/bold #ff2d78] [bold]{chain.get('name', name)}[/bold]\n"
        f"[dim]{chain.get('description', '')}[/dim]\n"
        f"[dim]Target:[/dim] [cyan]{target}[/cyan]  "
        f"[dim]Steps:[/dim] {len(chain.get('steps', []))}",
        expand=False,
    ))

    if dry_run:
        for i, step in enumerate(chain.get("steps", []), 1):
            cmd   = step.get("cmd", "")
            args  = [_render(a, vars) for a in step.get("args", [])]
            flags = step.get("flags", [])
            console.print(f"  [dim][{i}][/dim] omega {cmd} {' '.join(args + flags)}")
        return

    steps   = chain.get("steps", [])
    total   = len(steps)
    passed  = 0
    start   = time.time()

    for i, step in enumerate(steps):
        ok = _run_step(step, vars, i, total)
        if ok:
            passed += 1
        elif not step.get("continue_on_error"):
            console.print(f"\n[red]Chain halted at step {i+1}.[/red] "
                          f"Add [bold]continue_on_error: true[/bold] to skip failures.")
            break
        console.print()

    elapsed = time.time() - start
    color   = "green" if passed == total else "#ffaa00"
    console.print(f"[bold {color}]Chain complete:[/bold {color}] "
                  f"{passed}/{total} steps passed in {elapsed:.1f}s")


def list_chains() -> None:
    tbl = Table(title="Available Chains", show_lines=True)
    tbl.add_column("Name",        style="bold #ff2d78", max_width=20)
    tbl.add_column("Description", style="dim",          max_width=50)
    tbl.add_column("Steps",       justify="right")
    tbl.add_column("Source",      style="dim")

    for name, chain in BUILTIN_CHAINS.items():
        tbl.add_row(name, chain.get("description", ""), str(len(chain.get("steps", []))), "built-in")

    CHAINS_DIR.mkdir(parents=True, exist_ok=True)
    for p in sorted(CHAINS_DIR.glob("*.json")):
        try:
            c = json.loads(p.read_text())
            tbl.add_row(p.stem, c.get("description", ""), str(len(c.get("steps", []))), "custom")
        except Exception:
            pass

    console.print(tbl)


def new_chain(name: str, target_placeholder: bool = True) -> None:
    """Scaffold a new chain template."""
    template = {
        "name":        name,
        "description": f"Custom chain: {name}",
        "steps": [
            {"cmd": "dns",   "args": ["{{target}}"]},
            {"cmd": "whois", "args": ["{{target}}"]},
        ],
    }
    _save_chain(name, template)
    console.print(f"[dim]Edit it at:[/dim] {CHAINS_DIR / f'{name}.json'}")


def run(action: str, name: str = "", target: str = "", dry_run: bool = False) -> None:
    if action == "list":
        list_chains()
    elif action == "run":
        if not name:
            console.print("[red]Chain name required.[/red] Usage: omega chain run <name> --target TARGET")
            return
        run_chain(name, target=target, dry_run=dry_run)
    elif action == "new":
        if not name:
            console.print("[red]Chain name required.[/red] Usage: omega chain new <name>")
            return
        new_chain(name)
    elif action == "show":
        if not name:
            list_chains()
            return
        chain = _load_chain(name)
        if not chain:
            console.print(f"[red]Not found:[/red] {name}")
            return
        console.print(Panel(json.dumps(chain, indent=2), title=f"Chain: {name}"))
    else:
        console.print(f"[red]Unknown action:[/red] {action}  (list|run|new|show)")
