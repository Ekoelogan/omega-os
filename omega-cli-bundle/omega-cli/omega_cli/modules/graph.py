"""Entity relationship graph — maps all OSINT findings into a visual tree/graph."""
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table
from rich import box

console = Console()


def _load_latest_findings(target: str) -> dict:
    """Try to load the latest auto-recon JSON for a target."""
    report_dir = Path.home() / "omega-reports"
    safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
    candidates = sorted(report_dir.glob(f"omega_auto_{safe}_*.json"), reverse=True)
    if candidates:
        try:
            return json.loads(candidates[0].read_text())
        except Exception:
            pass
    return {}


def _extract_entities(target: str, findings: dict) -> dict:
    """Extract structured entities from findings dict."""
    entities = {
        "domain": target,
        "ips": [],
        "subdomains": [],
        "emails": [],
        "technologies": [],
        "open_ports": [],
        "cves": [],
        "cloud_assets": [],
        "lookalikes": [],
        "certificates": [],
        "nameservers": [],
        "mx_records": [],
    }

    # DNS
    dns = findings.get("dns", {})
    if isinstance(dns, dict):
        entities["ips"] = dns.get("A", dns.get("a", []))
        entities["nameservers"] = dns.get("NS", dns.get("ns", []))
        entities["mx_records"] = dns.get("MX", dns.get("mx", []))
        if isinstance(entities["ips"], str):
            entities["ips"] = [entities["ips"]]

    # crtsh subdomains
    crtsh = findings.get("crtsh", {})
    if isinstance(crtsh, dict):
        subs = crtsh.get("subdomains", [])
        if isinstance(subs, list):
            entities["subdomains"] = subs[:30]

    # Email harvest
    harvest = findings.get("harvest", {})
    if isinstance(harvest, dict):
        entities["emails"] = harvest.get("emails", [])[:20]

    # Tech fingerprint
    tech = findings.get("tech", {})
    if isinstance(tech, dict):
        t = tech.get("technologies", tech.get("tech", []))
        if isinstance(t, list):
            entities["technologies"] = [str(x) for x in t[:15]]

    # Port scan
    ports = findings.get("ports", {})
    if isinstance(ports, dict):
        entities["open_ports"] = ports.get("open_ports", [])[:20]

    # CVE map
    cve = findings.get("cvemap", {})
    if isinstance(cve, dict):
        entities["cves"] = cve.get("cves", [])[:10]

    # Cloud assets
    cloud = findings.get("buckets", findings.get("cloud", {}))
    if isinstance(cloud, dict):
        entities["cloud_assets"] = cloud.get("open", [])[:10]

    # Typosquatting
    typo = findings.get("typo", {})
    if isinstance(typo, dict):
        live = typo.get("live", [])
        entities["lookalikes"] = [d.get("domain", d) if isinstance(d, dict) else d for d in live[:10]]

    return entities


def build_tree(target: str, entities: dict) -> Tree:
    """Build a Rich Tree from entities."""
    root = Tree(
        f"[bold #ff2d78]◆ {target}[/]",
        guide_style="dim #ff85b3",
    )

    # IPs
    if entities["ips"]:
        ip_branch = root.add(f"[bold yellow]🌐 IPs ({len(entities['ips'])})[/]")
        for ip in entities["ips"][:10]:
            n = ip_branch.add(f"[cyan]{ip}[/]")
            # Attach open ports under IPs
            if entities["open_ports"]:
                ports_str = "  ".join(f"[green]:{p}[/]" for p in entities["open_ports"][:8])
                n.add(f"[dim]ports:[/] {ports_str}")

    # Subdomains
    if entities["subdomains"]:
        sub_branch = root.add(f"[bold magenta]📡 Subdomains ({len(entities['subdomains'])})[/]")
        for sub in entities["subdomains"][:15]:
            sub_branch.add(f"[white]{sub}[/]")
        if len(entities["subdomains"]) > 15:
            sub_branch.add(f"[dim]+{len(entities['subdomains'])-15} more[/]")

    # DNS
    if entities["nameservers"]:
        dns_b = root.add("[bold blue]🔤 DNS[/]")
        ns_b = dns_b.add("[dim]NS[/]")
        for ns in entities["nameservers"][:4]:
            ns_b.add(f"[dim]{ns}[/]")
        if entities["mx_records"]:
            mx_b = dns_b.add("[dim]MX[/]")
            for mx in entities["mx_records"][:3]:
                mx_b.add(f"[dim]{mx}[/]")

    # Technologies
    if entities["technologies"]:
        tech_branch = root.add(f"[bold green]⚙  Technologies ({len(entities['technologies'])})[/]")
        for t in entities["technologies"][:10]:
            tech_branch.add(f"[green]{t}[/]")
        # Attach CVEs under tech
        if entities["cves"]:
            cve_b = tech_branch.add(f"[bold red]CVEs ({len(entities['cves'])})[/]")
            for cve in entities["cves"][:5]:
                cve_id = cve.get("id", cve) if isinstance(cve, dict) else cve
                score = cve.get("score", "") if isinstance(cve, dict) else ""
                cve_b.add(f"[red]{cve_id}[/] [dim]{score}[/]")

    # Emails
    if entities["emails"]:
        email_branch = root.add(f"[bold cyan]📧 Emails ({len(entities['emails'])})[/]")
        for email in entities["emails"][:8]:
            email_branch.add(f"[cyan]{email}[/]")

    # Cloud assets
    if entities["cloud_assets"]:
        cloud_b = root.add(f"[bold orange1]☁  Cloud Assets ({len(entities['cloud_assets'])})[/]")
        for asset in entities["cloud_assets"][:5]:
            cloud_b.add(f"[orange1]{asset}[/]")

    # Lookalike domains
    if entities["lookalikes"]:
        typo_b = root.add(f"[bold red]🎭 Lookalikes ({len(entities['lookalikes'])})[/]")
        for d in entities["lookalikes"][:8]:
            typo_b.add(f"[red]{d}[/]")

    return root


def _stats_table(target: str, entities: dict) -> Table:
    tbl = Table(
        title="Entity Summary",
        box=box.ROUNDED, border_style="#ff85b3",
    )
    tbl.add_column("Entity Type", style="bold")
    tbl.add_column("Count", style="cyan", width=8)
    tbl.add_column("Sample")

    rows = [
        ("IPs", entities["ips"], ", ".join(entities["ips"][:3])),
        ("Subdomains", entities["subdomains"], entities["subdomains"][0] if entities["subdomains"] else ""),
        ("Emails", entities["emails"], entities["emails"][0] if entities["emails"] else ""),
        ("Technologies", entities["technologies"], ", ".join(entities["technologies"][:3])),
        ("Open Ports", entities["open_ports"], str(entities["open_ports"][:6])),
        ("CVEs", entities["cves"], entities["cves"][0].get("id", "") if entities["cves"] and isinstance(entities["cves"][0], dict) else str(entities["cves"][0]) if entities["cves"] else ""),
        ("Cloud Assets", entities["cloud_assets"], entities["cloud_assets"][0][:60] if entities["cloud_assets"] else ""),
        ("Lookalikes", entities["lookalikes"], entities["lookalikes"][0] if entities["lookalikes"] else ""),
    ]
    for label, data, sample in rows:
        count = len(data)
        color = "red" if (label == "CVEs" and count) or (label == "Cloud Assets" and count) else "cyan"
        tbl.add_row(label, f"[{color}]{count}[/]", str(sample)[:70])
    return tbl


def run(target: str, findings: dict = None, json_file: str = ""):
    """Build and display an entity relationship graph."""
    console.print(Panel(
        f"[bold #ff2d78]🕸  Entity Relationship Graph[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    # Load findings
    if json_file:
        try:
            findings = json.loads(Path(json_file).read_text())
        except Exception as e:
            console.print(f"[red]Could not load {json_file}:[/] {e}")
            findings = {}

    if not findings:
        findings = _load_latest_findings(target)
        if findings:
            console.print(f"[dim]Loaded latest auto-recon data[/]")
        else:
            console.print("[yellow]No findings found. Run:[/] [cyan]omega auto {target}[/] first, or pass --json-file")
            findings = {}

    entities = _extract_entities(target, findings)
    tree = build_tree(target, entities)
    console.print(tree)
    console.print()
    console.print(_stats_table(target, entities))

    total = sum(len(v) for v in entities.values() if isinstance(v, list))
    console.print(f"\n[bold]Total entities mapped:[/] [cyan]{total}[/]")
    return entities
