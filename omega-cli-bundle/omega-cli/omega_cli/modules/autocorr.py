"""omega autocorr — Auto-correlation engine: cross-reference all omega findings,
surface shared IPs, domains, emails, hashes across modules, build relationship graph."""
from __future__ import annotations
import json, os, re, glob, datetime, collections
from typing import Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box

console = Console()


def _load_reports(target: str, report_dir: str) -> list[dict]:
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    pattern = os.path.join(report_dir, f"*{safe}*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime)
    reports = []
    for fpath in files:
        try:
            with open(fpath) as f:
                data = json.load(f)
            data["_module"] = os.path.basename(fpath).split("_")[0]
            data["_file"]   = os.path.basename(fpath)
            reports.append(data)
        except Exception:
            continue
    return reports


def _extract_iocs(data: dict) -> dict[str, set]:
    """Extract all IOCs from a report dict."""
    iocs: dict[str, set] = {
        "ipv4":       set(),
        "domain":     set(),
        "email":      set(),
        "hash_md5":   set(),
        "hash_sha256":set(),
        "url":        set(),
        "cve":        set(),
        "port":       set(),
        "asn":        set(),
    }
    text = json.dumps(data)

    # IPs
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        parts = ip.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            iocs["ipv4"].add(ip)

    # Domains
    for d in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|jp|br|au|in|info|biz|me|tv|cc|onion)\b", text):
        if len(d) < 80:
            iocs["domain"].add(d.lower())

    # Emails
    for e in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text):
        iocs["email"].add(e.lower())

    # MD5
    for h in re.findall(r"\b[0-9a-fA-F]{32}\b", text):
        iocs["hash_md5"].add(h.lower())

    # SHA256
    for h in re.findall(r"\b[0-9a-fA-F]{64}\b", text):
        iocs["hash_sha256"].add(h.lower())

    # CVEs
    for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I):
        iocs["cve"].add(c.upper())

    # ASNs
    for a in re.findall(r"\bAS\d{4,6}\b", text, re.I):
        iocs["asn"].add(a.upper())

    # Filter noise
    noise_ips = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
    iocs["ipv4"] -= noise_ips

    return iocs


def _correlate(reports: list[dict]) -> dict[str, Any]:
    """Find IOCs that appear in multiple modules."""
    # ioc_type -> ioc_value -> [modules that saw it]
    seen: dict[str, dict[str, list[str]]] = {}

    for report in reports:
        module = report.get("_module", "unknown")
        iocs = _extract_iocs(report)
        for ioc_type, values in iocs.items():
            if ioc_type not in seen:
                seen[ioc_type] = {}
            for val in values:
                if val not in seen[ioc_type]:
                    seen[ioc_type][val] = []
                if module not in seen[ioc_type][val]:
                    seen[ioc_type][val].append(module)

    # Correlations: IOCs seen in 2+ modules
    correlations: list[dict] = []
    for ioc_type, vals in seen.items():
        for val, modules in vals.items():
            if len(modules) >= 2:
                correlations.append({
                    "type":    ioc_type,
                    "value":   val,
                    "modules": modules,
                    "count":   len(modules),
                })

    # Sort by appearance count descending
    correlations.sort(key=lambda x: -x["count"])
    return {"correlations": correlations, "all_iocs": {k: list(v.keys()) for k, v in seen.items()}}


def _build_graph(correlations: list[dict]) -> dict[str, Any]:
    """Build simple adjacency for module-IOC relationships."""
    nodes = set()
    edges = []
    for c in correlations[:50]:
        ioc_node = f"{c['type']}:{c['value'][:40]}"
        nodes.add(ioc_node)
        for mod in c["modules"]:
            nodes.add(f"module:{mod}")
            edges.append({"from": f"module:{mod}", "to": ioc_node, "type": c["type"]})
    return {"nodes": list(nodes), "edges": edges}


def run(target: str, report_dir: str = "", min_modules: int = 2, show_graph: bool = False):
    rdir = report_dir or os.path.expanduser("~/.omega/reports")
    console.print(Panel(
        f"[bold #ff2d78]🔗  Auto-Correlation Engine[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    with console.status("[cyan]Loading omega reports…"):
        reports = _load_reports(target, rdir)
    console.print(f"[dim]Loaded {len(reports)} report file(s)[/dim]\n")

    if not reports:
        console.print("[yellow]No reports found. Run omega auto <target> first.[/yellow]")
        return

    with console.status("[cyan]Cross-correlating IOCs across modules…"):
        result = _correlate(reports)

    correlations = result["correlations"]
    all_iocs     = result["all_iocs"]

    # Module coverage summary
    modules_seen = set()
    for r in reports:
        modules_seen.add(r.get("_module","?"))
    console.print(f"[bold]Modules covered:[/bold] {', '.join(sorted(modules_seen))}\n")

    # IOC inventory
    t_inv = Table("IOC Type", "Count", box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
    for ioc_type, vals in all_iocs.items():
        if vals:
            t_inv.add_row(ioc_type, str(len(vals)))
    console.print(t_inv)

    # Correlations
    filtered = [c for c in correlations if c["count"] >= min_modules]
    if filtered:
        console.print(f"\n[bold red]🔗 {len(filtered)} Cross-Module Correlation(s) (seen in {min_modules}+ modules):[/bold red]")
        t = Table("Type", "Value", "Modules", "Count",
                  box=box.ROUNDED, header_style="bold red")
        for c in filtered[:30]:
            color = "#ff0000" if c["count"] >= 4 else "#ffd700" if c["count"] >= 3 else "#00d4ff"
            t.add_row(
                c["type"],
                f"[{color}]{c['value'][:55]}[/{color}]",
                ", ".join(c["modules"]),
                f"[{color}]{c['count']}[/{color}]",
            )
        console.print(t)

        # Pivots
        console.print("\n[bold]Recommended pivots:[/bold]")
        for c in filtered[:5]:
            if c["type"] in ("ipv4", "domain"):
                console.print(f"  [cyan]omega pivot {c['value']} --depth 2[/cyan]")
            elif c["type"] == "cve":
                console.print(f"  [cyan]omega cvemap {c['value']}[/cyan]")
            elif c["type"] == "email":
                console.print(f"  [cyan]omega leaked {c['value']}[/cyan]")
    else:
        console.print(f"[green]✓  No cross-module correlations found (min {min_modules} modules)[/green]")

    # Graph view
    if show_graph:
        graph = _build_graph(filtered)
        console.print(f"\n[bold]Graph:[/bold] {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
        tree = Tree("[bold #ff2d78]Correlation Graph[/bold #ff2d78]")
        mods = [n for n in graph["nodes"] if n.startswith("module:")]
        for mod in sorted(mods):
            mod_name = mod.replace("module:", "")
            branch = tree.add(f"[cyan]{mod_name}[/cyan]")
            mod_edges = [e for e in graph["edges"] if e["from"] == mod]
            for e in mod_edges[:10]:
                branch.add(f"[dim]{e['to'].replace(e['type']+':','')}[/dim]")
        console.print(tree)

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out = os.path.join(out_dir, f"autocorr_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump({
            "target": target,
            "modules_analysed": list(modules_seen),
            "total_iocs": {k: len(v) for k, v in all_iocs.items()},
            "correlations": filtered[:50],
            "graph": _build_graph(filtered),
        }, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
