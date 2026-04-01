"""omega supply — Software supply chain attack surface analysis."""
from __future__ import annotations
import json, re, time
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()

KNOWN_MALICIOUS = {
    "event-stream", "flatmap-stream", "node-currency", "twilio-npm",
    "electron-native-notify", "getcookies", "colourama", "python-dateutil-mock",
    "loglib-modules", "aioconsol", "xin-currency", "httpx-mock-bad",
}

TIMEOUT = 10


def _npm_deps(package: str, depth: int = 2) -> dict[str, Any]:
    results: dict[str, Any] = {"package": package, "version": None, "deps": {}, "issues": []}
    try:
        r = httpx.get(f"https://registry.npmjs.org/{package}/latest", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            results["version"] = data.get("version")
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            results["deps"] = deps
            for dep in deps:
                if dep.lower() in KNOWN_MALICIOUS:
                    results["issues"].append({"dep": dep, "type": "known_malicious"})
                if _is_typosquat(dep, package):
                    results["issues"].append({"dep": dep, "type": "possible_typosquat"})
    except Exception as e:
        results["error"] = str(e)
    return results


def _pypi_deps(package: str) -> dict[str, Any]:
    results: dict[str, Any] = {"package": package, "version": None, "requires": [], "issues": []}
    try:
        r = httpx.get(f"https://pypi.org/pypi/{package}/json", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            info = data.get("info", {})
            results["version"] = info.get("version")
            requires = info.get("requires_dist") or []
            results["requires"] = requires[:20]
            for req in requires:
                dep_name = re.split(r"[>=<!;\[]", req)[0].strip().lower()
                if dep_name in KNOWN_MALICIOUS:
                    results["issues"].append({"dep": dep_name, "type": "known_malicious"})
    except Exception as e:
        results["error"] = str(e)
    return results


def _check_npm_typosquats(package: str) -> list[dict]:
    squats = []
    variants = _generate_typos(package)
    for variant in variants[:10]:
        try:
            r = httpx.get(f"https://registry.npmjs.org/{variant}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                squats.append({
                    "variant": variant,
                    "exists": True,
                    "version": data.get("dist-tags", {}).get("latest"),
                    "author": data.get("maintainers", [{}])[0].get("name", "?") if data.get("maintainers") else "?",
                })
        except Exception:
            pass
    return squats


def _check_pypi_typosquats(package: str) -> list[dict]:
    squats = []
    for variant in _generate_typos(package)[:8]:
        try:
            r = httpx.get(f"https://pypi.org/pypi/{variant}/json", timeout=5)
            if r.status_code == 200:
                info = r.json().get("info", {})
                squats.append({
                    "variant": variant,
                    "exists": True,
                    "version": info.get("version"),
                    "author": info.get("author", "?"),
                })
        except Exception:
            pass
    return squats


def _generate_typos(name: str) -> list[str]:
    typos = set()
    for i in range(len(name)):
        typos.add(name[:i] + name[i+1:])
        typos.add(name[:i] + name[i]*2 + name[i+1:])
    typos.add(name.replace("-", "_"))
    typos.add(name.replace("_", "-"))
    typos.add(name + "s")
    typos.add(name + "-dev")
    typos.add(name + "-cli")
    typos.discard(name)
    return list(typos)[:15]


def _is_typosquat(dep: str, parent: str) -> bool:
    if abs(len(dep) - len(parent)) > 3:
        return False
    diffs = sum(a != b for a, b in zip(dep, parent))
    return 0 < diffs <= 2


def _osv_vulns(ecosystem: str, package: str) -> list[dict]:
    try:
        payload = {"package": {"name": package, "ecosystem": ecosystem}}
        r = httpx.post("https://api.osv.dev/v1/query", json=payload, timeout=TIMEOUT)
        if r.status_code == 200:
            vulns = r.json().get("vulns", [])
            return [{"id": v.get("id"), "summary": v.get("summary", "")[:80]} for v in vulns[:10]]
    except Exception:
        pass
    return []


def run(target: str, ecosystem: str = "auto", check_typos: bool = True):
    console.print(Panel(f"[bold #ff2d78]⛓  Supply Chain Analysis[/bold #ff2d78] — [cyan]{target}[/cyan]", box=box.ROUNDED))

    eco = ecosystem
    if eco == "auto":
        eco = "npm" if not target.startswith("pip:") else "pypi"
        if target.startswith("pypi:") or target.startswith("pip:"):
            eco = "pypi"
            target = target.split(":", 1)[1]

    findings: dict[str, Any] = {"target": target, "ecosystem": eco}

    with console.status(f"[cyan]Fetching {eco} metadata for {target}…"):
        if eco == "npm":
            dep_info = _npm_deps(target)
        else:
            dep_info = _pypi_deps(target)

    findings["metadata"] = dep_info

    # OSV vulnerability check
    eco_map = {"npm": "npm", "pypi": "PyPI"}
    with console.status("[cyan]Querying OSV vulnerability database…"):
        vulns = _osv_vulns(eco_map.get(eco, "npm"), target)
    findings["vulnerabilities"] = vulns

    # Typosquat check
    if check_typos:
        with console.status("[cyan]Checking for typosquatted variants…"):
            if eco == "npm":
                squats = _check_npm_typosquats(target)
            else:
                squats = _check_pypi_typosquats(target)
        findings["typosquats"] = squats
    else:
        squats = []
        findings["typosquats"] = []

    # ── Display ──────────────────────────────────────────────────────────────
    meta = dep_info
    console.print(f"\n[bold]Package:[/bold] [cyan]{meta.get('package')}[/cyan]  "
                  f"[bold]Version:[/bold] [green]{meta.get('version') or meta.get('version', '?')}[/green]  "
                  f"[bold]Ecosystem:[/bold] {eco}")

    # Dependencies
    deps = meta.get("deps") or meta.get("requires") or []
    if isinstance(deps, dict):
        dep_list = list(deps.items())[:20]
    else:
        dep_list = [(d, "") for d in deps[:20]]

    if dep_list:
        t = Table("Dependency", "Version/Spec", title="[bold]Direct Dependencies[/bold]",
                  box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
        for dep, ver in dep_list:
            t.add_row(dep, str(ver) if ver else "")
        console.print(t)

    # Issues in deps
    issues = meta.get("issues", [])
    if issues:
        console.print(f"\n[bold red]⚠  {len(issues)} dependency issue(s) found:[/bold red]")
        for iss in issues:
            console.print(f"  [red]•[/red] [yellow]{iss['dep']}[/yellow] — {iss['type']}")

    # Vulnerabilities
    if vulns:
        t2 = Table("CVE / ID", "Summary", title="[bold red]Known Vulnerabilities (OSV)[/bold red]",
                   box=box.SIMPLE_HEAD, header_style="bold red")
        for v in vulns:
            t2.add_row(v["id"], v["summary"])
        console.print(t2)
    else:
        console.print("\n[green]✓  No known vulnerabilities found in OSV database.[/green]")

    # Typosquats
    if squats:
        t3 = Table("Variant", "Version", "Author",
                   title="[bold yellow]⚠  Potential Typosquats Found[/bold yellow]",
                   box=box.SIMPLE_HEAD, header_style="bold yellow")
        for s in squats:
            t3.add_row(s["variant"], s.get("version", "?"), s.get("author", "?"))
        console.print(t3)
    else:
        console.print("[green]✓  No typosquatted variants detected.[/green]")

    # Save
    import os, datetime
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(out_dir, f"supply_{target}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
