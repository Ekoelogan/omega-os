"""omega pivot — IOC pivot engine: given any observable → auto-expand all related intel via graph walk."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.tree import Tree

console = Console()
TIMEOUT = 10

# IOC type patterns
PATTERNS = {
    "ipv4":   re.compile(r"^\d{1,3}(\.\d{1,3}){3}$"),
    "domain": re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"),
    "md5":    re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1":   re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "email":  re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"),
    "url":    re.compile(r"^https?://"),
    "cve":    re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    "asn":    re.compile(r"^AS\d+$", re.IGNORECASE),
    "btc":    re.compile(r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$"),
}


def _classify(ioc: str) -> str:
    for name, pat in PATTERNS.items():
        if pat.match(ioc.strip()):
            return name
    return "unknown"


def _pivot_ip(ip: str, cfg: dict) -> dict[str, Any]:
    pivots: dict[str, Any] = {"related": []}
    # PTR record
    try:
        import socket
        ptr = socket.gethostbyaddr(ip)[0]
        pivots["ptr"] = ptr
        pivots["related"].append({"type": "domain", "value": ptr, "source": "PTR"})
    except Exception:
        pass

    # ipapi geo
    try:
        r = httpx.get(f"https://ipapi.co/{ip}/json/", timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            pivots["geo"] = {"city": d.get("city"), "country": d.get("country_name"),
                             "asn": d.get("asn"), "org": d.get("org")}
            if d.get("asn"):
                pivots["related"].append({"type": "asn", "value": d["asn"], "source": "ipapi"})
    except Exception:
        pass

    # Shodan InternetDB (no key needed)
    try:
        r2 = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=TIMEOUT)
        if r2.status_code == 200:
            d2 = r2.json()
            pivots["shodan"] = {
                "ports": d2.get("ports", []),
                "hostnames": d2.get("hostnames", []),
                "cpes": d2.get("cpes", []),
                "vulns": d2.get("vulns", []),
                "tags": d2.get("tags", []),
            }
            for host in d2.get("hostnames", [])[:5]:
                pivots["related"].append({"type": "domain", "value": host, "source": "Shodan"})
            for vuln in d2.get("vulns", [])[:5]:
                pivots["related"].append({"type": "cve", "value": vuln, "source": "Shodan"})
    except Exception:
        pass

    # HackerTarget reverse IP
    try:
        r3 = httpx.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=TIMEOUT)
        if r3.status_code == 200 and "error" not in r3.text[:30].lower():
            for d in r3.text.splitlines()[:10]:
                d = d.strip()
                if d:
                    pivots["related"].append({"type": "domain", "value": d, "source": "ReverseIP"})
    except Exception:
        pass

    return pivots


def _pivot_domain(domain: str, cfg: dict) -> dict[str, Any]:
    pivots: dict[str, Any] = {"related": []}
    # DNS resolution
    try:
        import socket
        ips = list({r[4][0] for r in socket.getaddrinfo(domain, None)})
        pivots["ips"] = ips
        for ip in ips:
            pivots["related"].append({"type": "ipv4", "value": ip, "source": "DNS"})
    except Exception:
        pass

    # HackerTarget DNS
    try:
        r = httpx.get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=TIMEOUT)
        if r.status_code == 200 and "error" not in r.text[:30].lower():
            for line in r.text.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    rec_type = parts[-2] if len(parts) > 2 else "?"
                    value = parts[-1]
                    pivots["related"].append({"type": rec_type, "value": value, "source": "DNS"})
    except Exception:
        pass

    # CRT.sh cert transparency
    try:
        r2 = httpx.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=TIMEOUT)
        if r2.status_code == 200:
            subs = set()
            for cert in r2.json()[:50]:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub and sub.endswith(domain) and sub != domain:
                        subs.add(sub)
            pivots["subdomains"] = list(subs)[:20]
            for sub in list(subs)[:10]:
                pivots["related"].append({"type": "domain", "value": sub, "source": "CRT.sh"})
    except Exception:
        pass

    # WHOIS email → further pivot
    try:
        r3 = httpx.get(f"https://api.hackertarget.com/whois/?q={domain}", timeout=TIMEOUT)
        if r3.status_code == 200 and "error" not in r3.text[:30].lower():
            emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', r3.text)
            for e in set(emails):
                pivots["related"].append({"type": "email", "value": e, "source": "WHOIS"})
    except Exception:
        pass

    return pivots


def _pivot_hash(h: str, cfg: dict, hash_type: str) -> dict[str, Any]:
    pivots: dict[str, Any] = {"related": []}

    # MalwareBazaar
    try:
        r = httpx.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": h},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "hash_found":
                info = data.get("data", [{}])[0]
                pivots["malwarebazaar"] = {
                    "name": info.get("file_name"),
                    "type": info.get("file_type"),
                    "tags": info.get("tags", []),
                    "signature": info.get("signature"),
                    "first_seen": info.get("first_seen"),
                }
                for tag in info.get("tags", [])[:5]:
                    pivots["related"].append({"type": "malware_tag", "value": tag, "source": "MalwareBazaar"})
                if info.get("signature"):
                    pivots["related"].append({"type": "malware_family", "value": info["signature"], "source": "MalwareBazaar"})
    except Exception:
        pass

    # VirusTotal (no key needed for basic hash info via public API)
    vt_key = cfg.get("vt_api_key", "")
    if vt_key:
        try:
            r2 = httpx.get(
                f"https://www.virustotal.com/api/v3/files/{h}",
                headers={"x-apikey": vt_key},
                timeout=TIMEOUT,
            )
            if r2.status_code == 200:
                attrs = r2.json().get("data", {}).get("attributes", {})
                pivots["virustotal"] = {
                    "malicious": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "type": attrs.get("type_description"),
                    "names": attrs.get("names", [])[:5],
                }
                for name in attrs.get("names", [])[:3]:
                    pivots["related"].append({"type": "filename", "value": name, "source": "VirusTotal"})
        except Exception:
            pass

    return pivots


def _pivot_email(email: str, cfg: dict) -> dict[str, Any]:
    pivots: dict[str, Any] = {"related": []}
    domain = email.split("@")[1] if "@" in email else ""
    if domain:
        pivots["related"].append({"type": "domain", "value": domain, "source": "email_domain"})

    # HIBP
    hibp_key = cfg.get("hibp_api_key", "")
    if hibp_key:
        try:
            r = httpx.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": hibp_key, "User-Agent": "omega-cli"},
                params={"truncateResponse": "false"},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                breaches = r.json()
                pivots["hibp"] = [b.get("Name") for b in breaches]
                for b in breaches[:5]:
                    pivots["related"].append({"type": "breach", "value": b.get("Name", "?"), "source": "HIBP"})
        except Exception:
            pass

    return pivots


def _pivot_cve(cve: str, cfg: dict) -> dict[str, Any]:
    pivots: dict[str, Any] = {"related": []}
    nvd_key = cfg.get("nvd_api_key", "")
    headers = {}
    if nvd_key:
        headers["apiKey"] = nvd_key
    try:
        r = httpx.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve.upper()},
            headers=headers,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                pivots["nvd"] = {
                    "description": (cve_data.get("descriptions", [{}])[0].get("value", ""))[:200],
                    "cvss": cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore"),
                    "cpe": [c.get("criteria") for c in
                            cve_data.get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [])[:5]],
                }
                for cpe in pivots["nvd"].get("cpe", [])[:3]:
                    if cpe:
                        pivots["related"].append({"type": "cpe", "value": cpe, "source": "NVD"})
    except Exception:
        pass
    return pivots


def run(target: str, depth: int = 2, max_nodes: int = 50):
    console.print(Panel(
        f"[bold #ff2d78]🔗  IOC Pivot Engine[/bold #ff2d78] — [cyan]{target}[/cyan]  "
        f"[dim](depth={depth})[/dim]",
        box=box.ROUNDED
    ))

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()

    ioc_type = _classify(target)
    console.print(f"[dim]Detected: [cyan]{ioc_type}[/cyan][/dim]\n")

    # Graph: {ioc: {type, pivots}}
    graph: dict[str, dict] = {}
    queue = [(target, ioc_type, 0)]
    visited: set = set()

    PIVOT_FNS = {
        "ipv4":   _pivot_ip,
        "domain": _pivot_domain,
        "md5":    lambda h, c: _pivot_hash(h, c, "md5"),
        "sha1":   lambda h, c: _pivot_hash(h, c, "sha1"),
        "sha256": lambda h, c: _pivot_hash(h, c, "sha256"),
        "email":  _pivot_email,
        "cve":    _pivot_cve,
    }

    with console.status("[cyan]Pivoting…") as status:
        while queue and len(graph) < max_nodes:
            node, ntype, d = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)

            status.update(f"[cyan]Pivoting {ntype}: {node[:50]}…[/cyan]")
            pivot_fn = PIVOT_FNS.get(ntype)
            if pivot_fn:
                try:
                    pivots = pivot_fn(node, cfg)
                except Exception:
                    pivots = {"related": []}
            else:
                pivots = {"related": []}

            graph[node] = {"type": ntype, "depth": d, "data": pivots}

            if d < depth:
                for rel in pivots.get("related", [])[:8]:
                    child = rel.get("value", "")
                    ctype = rel.get("type", _classify(child))
                    if child and child not in visited and ctype in PIVOT_FNS:
                        queue.append((child, ctype, d + 1))

    # Display as tree
    tree = Tree(f"[bold #ff2d78]🔗 {target}[/bold #ff2d78] [dim]({ioc_type})[/dim]")

    def build_subtree(node: str, parent_tree, visited_tree: set, max_depth: int):
        if node in visited_tree or max_depth <= 0:
            return
        visited_tree.add(node)
        data = graph.get(node, {})
        pivots = data.get("data", {})
        related = pivots.get("related", [])

        # Node details
        details = []
        if pivots.get("geo"):
            g = pivots["geo"]
            details.append(f"[dim]{g.get('city')}, {g.get('country')} — {g.get('org')}[/dim]")
        if pivots.get("shodan", {}).get("ports"):
            details.append(f"[dim]Ports: {', '.join(str(p) for p in pivots['shodan']['ports'][:8])}[/dim]")
        if pivots.get("shodan", {}).get("vulns"):
            details.append(f"[red]CVEs: {', '.join(pivots['shodan']['vulns'][:3])}[/red]")
        if pivots.get("malwarebazaar"):
            mb = pivots["malwarebazaar"]
            details.append(f"[red]Malware: {mb.get('signature', '?')} ({mb.get('type', '?')})[/red]")

        by_source: dict[str, list] = {}
        for rel in related[:15]:
            src = rel.get("source", "?")
            by_source.setdefault(src, []).append(rel)

        for src, rels in by_source.items():
            src_branch = parent_tree.add(f"[bold cyan]{src}[/bold cyan] ({len(rels)})")
            for d_line in details:
                src_branch.add(d_line)
            for rel in rels[:6]:
                color = {"ipv4": "green", "domain": "cyan", "cve": "red",
                         "email": "yellow", "md5": "magenta", "sha256": "magenta"}.get(rel.get("type", ""), "white")
                child_node = parent_tree.add(
                    f"[{color}]{rel.get('value', '?')}[/{color}] [dim]({rel.get('type', '?')})[/dim]"
                )
                if rel.get("value") in graph and max_depth > 1:
                    build_subtree(rel["value"], child_node, visited_tree, max_depth - 1)

    build_subtree(target, tree, set(), depth + 1)
    console.print(tree)

    # Summary
    console.print(f"\n[bold]Pivot summary:[/bold] {len(graph)} nodes explored, "
                  f"{sum(len(v.get('data', {}).get('related', [])) for v in graph.values())} edges")

    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"pivot_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump({"target": target, "graph": graph}, f, indent=2)
    console.print(f"[dim]Saved → {out_file}[/dim]")
