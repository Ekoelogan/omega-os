"""omega plugin — Plugin system: load/list/install custom Python modules from ~/.omega/plugins/."""
from __future__ import annotations
import importlib.util
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

PLUGINS_DIR  = Path.home() / ".omega" / "plugins"
MANIFEST_FILE = PLUGINS_DIR / "manifest.json"

PLUGIN_TEMPLATE = '''"""
{name} — omega-cli plugin
Description: {description}
"""
from rich.console import Console
import click

console = Console()

# This function is called by omega plugin run {name} <target>
def run(target: str, **kwargs) -> None:
    console.print(f"[bold #ff2d78]{name}[/bold #ff2d78] running on [cyan]{{target}}[/cyan]")
    # Add your OSINT logic here
    console.print("  [dim]TODO: implement plugin logic[/dim]")


# Optional: register as a Click command under omega
# Uncomment and customize:
# @click.command()
# @click.argument("target")
# def command(target):
#     """{description}"""
#     run(target)
'''


def _load_manifest() -> dict:
    if MANIFEST_FILE.exists():
        try:
            return json.loads(MANIFEST_FILE.read_text())
        except Exception:
            pass
    return {"plugins": {}}


def _save_manifest(data: dict) -> None:
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_FILE.write_text(json.dumps(data, indent=2))


def _load_plugin(name: str):
    """Dynamically import a plugin module."""
    plugin_file = PLUGINS_DIR / f"{name}.py"
    if not plugin_file.exists():
        raise FileNotFoundError(f"Plugin not found: {plugin_file}")
    spec   = importlib.util.spec_from_file_location(f"omega_plugin_{name}", plugin_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def list_plugins() -> None:
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    manifest = _load_manifest()
    plugin_files = list(PLUGINS_DIR.glob("*.py"))

    if not plugin_files:
        console.print("[dim]No plugins installed.[/dim]")
        console.print(f"Create one: [bold]omega plugin new <name>[/bold]")
        console.print(f"Plugins dir: {PLUGINS_DIR}")
        return

    tbl = Table(title="Installed Plugins", show_lines=True)
    tbl.add_column("Name",        style="bold #ff2d78")
    tbl.add_column("Description", style="dim", max_width=45)
    tbl.add_column("Version",     style="cyan")
    tbl.add_column("File",        style="dim")

    for pf in sorted(plugin_files):
        name = pf.stem
        meta = manifest.get("plugins", {}).get(name, {})
        desc = meta.get("description", "")
        ver  = meta.get("version", "—")
        if not desc:
            # Try to read docstring from file
            try:
                content = pf.read_text()
                for line in content.split("\n")[1:5]:
                    line = line.strip().strip('"""').strip("'''").strip()
                    if line and not line.startswith("omega"):
                        desc = line[:45]
                        break
            except Exception:
                pass
        tbl.add_row(name, desc or "—", ver, pf.name)

    console.print(tbl)
    console.print(f"\n[dim]Plugins directory:[/dim] {PLUGINS_DIR}")


def new_plugin(name: str, description: str = "") -> None:
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    plugin_file = PLUGINS_DIR / f"{name}.py"
    if plugin_file.exists():
        console.print(f"[yellow]Plugin already exists:[/yellow] {plugin_file}")
        return

    desc = description or f"Custom OSINT plugin: {name}"
    plugin_file.write_text(PLUGIN_TEMPLATE.format(name=name, description=desc))

    manifest = _load_manifest()
    manifest.setdefault("plugins", {})[name] = {
        "description": desc,
        "version":     "0.1.0",
        "file":        str(plugin_file),
    }
    _save_manifest(manifest)

    console.print(f"[green]✓[/green] Plugin created: [bold]{name}[/bold]")
    console.print(f"[dim]Edit:[/dim] {plugin_file}")
    console.print(f"\nRun it with: [bold]omega plugin run {name} <target>[/bold]")


def run_plugin(name: str, target: str = "", args: tuple = ()) -> None:
    try:
        module = _load_plugin(name)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        console.print("Use [bold]omega plugin list[/bold] to see available plugins.")
        return
    except Exception as e:
        console.print(f"[red]Plugin load error:[/red] {e}")
        return

    if not hasattr(module, "run"):
        console.print(f"[red]Plugin '{name}' has no run() function.[/red]")
        return

    console.print(Panel(
        f"[bold #ff2d78]🔌  Plugin:[/bold #ff2d78] [bold]{name}[/bold]  "
        f"[dim]target:[/dim] [cyan]{target}[/cyan]",
        expand=False,
    ))

    try:
        sig = inspect.signature(module.run)
        if "target" in sig.parameters:
            module.run(target)
        else:
            module.run()
    except Exception as e:
        console.print(f"[red]Plugin runtime error:[/red] {e}")


def install_plugin(source: str) -> None:
    """Install a plugin from a URL or GitHub repo (user/repo)."""
    import requests
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)

    if source.startswith("http"):
        url = source
    elif "/" in source:
        # GitHub user/repo — fetch raw plugin files
        url = f"https://raw.githubusercontent.com/{source}/main/plugin.py"
    else:
        console.print(f"[red]Invalid source:[/red] {source}")
        return

    try:
        r = requests.get(url, timeout=12)
        r.raise_for_status()
        name        = url.split("/")[-1].replace(".py", "")
        plugin_file = PLUGINS_DIR / f"{name}.py"
        plugin_file.write_text(r.text)
        console.print(f"[green]✓[/green] Installed plugin [bold]{name}[/bold] from {source}")
    except Exception as e:
        console.print(f"[red]Install failed:[/red] {e}")


def run(action: str, name: str = "", target: str = "",
        description: str = "", source: str = "") -> None:
    if action == "list":
        list_plugins()
    elif action == "new":
        if not name:
            console.print("[red]Name required.[/red] Usage: omega plugin new <name>")
            return
        new_plugin(name, description=description)
    elif action == "run":
        if not name:
            console.print("[red]Name required.[/red] Usage: omega plugin run <name> [target]")
            return
        run_plugin(name, target=target)
    elif action == "install":
        if not source:
            console.print("[red]Source required.[/red] Usage: omega plugin install <url|user/repo>")
            return
        install_plugin(source)
    else:
        console.print(f"[red]Unknown action:[/red] {action}  (list|new|run|install)")
