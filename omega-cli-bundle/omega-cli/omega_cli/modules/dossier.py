"""omega dossier — Full OSINT dossier builder: structured intelligence profile JSON + PDF."""
from __future__ import annotations
import json
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

OUTPUT_DIR = Path(".")


def _run_module(func, *args, **kwargs):
    """Run a module function, return its result silently."""
    import io
    from rich.console import Console as RC
    buf = io.StringIO()
    try:
        return func(*args, **kwargs)
    except Exception:
        return None


def _section(title: str, data) -> dict:
    return {"section": title, "data": data, "timestamp": datetime.utcnow().isoformat()}


def build_dossier(target: str, passive_only: bool = True) -> dict:
    dossier: dict = {
        "target":    target,
        "generated": datetime.utcnow().isoformat() + "Z",
        "version":   "omega-cli/1.1.0",
        "sections":  {},
    }

    tasks = [
        ("WHOIS",         _collect_whois,       target),
        ("DNS",           _collect_dns,          target),
        ("SSL",           _collect_ssl,          target),
        ("Subdomains",    _collect_subdomains,   target),
        ("Headers",       _collect_headers,      target),
        ("Technology",    _collect_tech,         target),
        ("Certificates",  _collect_certs,        target),
        ("Wayback",       _collect_wayback,      target),
        ("ASN",           _collect_asn,          target),
        ("Email Harvest", _collect_emails,       target),
        ("Social",        _collect_social,       target),
    ]

    if not passive_only:
        tasks += [
            ("Ports",    _collect_ports,   target),
            ("Cloud",    _collect_cloud,   target),
        ]

    with Progress(SpinnerColumn(), TextColumn("[bold #ff2d78]{task.description}"),
                  BarColumn(), console=console) as progress:
        task_id = progress.add_task("Building dossier…", total=len(tasks))
        for name, func, arg in tasks:
            progress.update(task_id, description=f"[bold #ff2d78]{name}[/bold #ff2d78]…")
            try:
                result = func(arg)
                if result:
                    dossier["sections"][name] = result
            except Exception as exc:
                dossier["sections"][name] = {"error": str(exc)}
            progress.advance(task_id)

    return dossier


# ── Collectors ────────────────────────────────────────────────────────────────

def _collect_whois(target: str) -> dict:
    try:
        import whois
        w = whois.whois(target)
        return {
            "registrar":    w.registrar,
            "creation_date": str(w.creation_date),
            "expiry_date":  str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails":       w.emails,
            "org":          w.org,
        }
    except Exception as e:
        return {"error": str(e)}


def _collect_dns(target: str) -> dict:
    import dns.resolver
    result: dict = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]:
        try:
            ans = dns.resolver.resolve(target, rtype, lifetime=4)
            result[rtype] = [str(r) for r in ans]
        except Exception:
            pass
    return result


def _collect_ssl(target: str) -> dict:
    import ssl, socket
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=target) as ss:
                cert = ss.getpeercert()
                return {
                    "subject":    dict(x[0] for x in cert.get("subject", [])),
                    "issuer":     dict(x[0] for x in cert.get("issuer", [])),
                    "not_after":  cert.get("notAfter"),
                    "not_before": cert.get("notBefore"),
                    "sans":       [v for _, v in cert.get("subjectAltName", [])],
                    "version":    ss.version(),
                    "cipher":     ss.cipher()[0] if ss.cipher() else None,
                }
    except Exception as e:
        return {"error": str(e)}


def _collect_subdomains(target: str) -> dict:
    wordlist = ["www", "mail", "ftp", "api", "dev", "staging", "admin", "vpn",
                "cdn", "static", "app", "portal", "login", "mx", "ns1", "ns2",
                "smtp", "pop", "imap", "autodiscover", "webmail", "remote"]
    import socket
    found = {}
    for sub in wordlist:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            found[fqdn] = ip
        except Exception:
            pass
    return found


def _collect_headers(target: str) -> dict:
    import requests
    try:
        r = requests.get(f"https://{target}", timeout=8, verify=False,
                         headers={"User-Agent": "omega-cli/1.1.0"})
        security = ["x-frame-options", "content-security-policy", "strict-transport-security",
                    "x-content-type-options", "permissions-policy", "x-xss-protection",
                    "referrer-policy"]
        return {
            "status_code": r.status_code,
            "server":      r.headers.get("server", ""),
            "powered_by":  r.headers.get("x-powered-by", ""),
            "security_headers": {h: r.headers.get(h, "MISSING") for h in security},
            "all_headers": dict(r.headers),
        }
    except Exception as e:
        return {"error": str(e)}


def _collect_tech(target: str) -> dict:
    import requests
    from bs4 import BeautifulSoup
    try:
        r = requests.get(f"https://{target}", timeout=8, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        tech: list[str] = []
        text = r.text.lower()
        for fw, kw in [("WordPress", "wp-content"), ("Drupal", "drupal"),
                       ("Joomla", "joomla"), ("React", "react.js"),
                       ("Vue.js", "vue.js"), ("Angular", "angular"),
                       ("jQuery", "jquery"), ("Bootstrap", "bootstrap"),
                       ("Laravel", "laravel"), ("Django", "django")]:
            if kw in text:
                tech.append(fw)
        return {"detected": tech, "generator": soup.find("meta", attrs={"name": "generator"})
                and soup.find("meta", attrs={"name": "generator"}).get("content", "")}
    except Exception as e:
        return {"error": str(e)}


def _collect_certs(target: str) -> dict:
    import requests
    try:
        r = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=10)
        r.raise_for_status()
        certs = r.json()[:20]
        return {"count": len(certs),
                "domains": list({c.get("name_value","") for c in certs})[:20]}
    except Exception as e:
        return {"error": str(e)}


def _collect_wayback(target: str) -> dict:
    import requests
    try:
        r = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={target}&output=json&limit=10&fl=timestamp,original",
            timeout=10)
        r.raise_for_status()
        rows = r.json()[1:]
        return {"count": len(rows), "samples": [{"ts": row[0], "url": row[1]} for row in rows[:5]]}
    except Exception as e:
        return {"error": str(e)}


def _collect_asn(target: str) -> dict:
    import socket
    from ipwhois import IPWhois
    try:
        ip = socket.gethostbyname(target)
        obj = IPWhois(ip)
        r   = obj.lookup_rdap(depth=1)
        return {"ip": ip, "asn": r.get("asn"), "asn_description": r.get("asn_description"),
                "network": r.get("network", {}).get("cidr")}
    except Exception as e:
        return {"error": str(e)}


def _collect_emails(target: str) -> dict:
    import requests
    emails: set[str] = set()
    try:
        r = requests.get(f"https://hunter.io/api/v2/domain-search?domain={target}&api_key=&limit=10",
                         timeout=8)
        if r.ok:
            for e in r.json().get("data", {}).get("emails", []):
                emails.add(e.get("value", ""))
    except Exception:
        pass
    return {"emails": list(emails), "count": len(emails)}


def _collect_social(target: str) -> dict:
    import requests
    mentions = {"reddit": 0, "github": 0}
    try:
        r = requests.get(f"https://www.reddit.com/search.json?q={target}&limit=5",
                         headers={"User-Agent": "omega-cli/1.1.0"}, timeout=8)
        if r.ok:
            mentions["reddit"] = r.json().get("data", {}).get("dist", 0)
    except Exception:
        pass
    return mentions


def _collect_ports(target: str) -> dict:
    import socket
    open_ports = []
    for port in [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]:
        try:
            with socket.create_connection((target, port), timeout=0.8):
                open_ports.append(port)
        except Exception:
            pass
    return {"open": open_ports}


def _collect_cloud(target: str) -> dict:
    import requests
    found = []
    name = target.split(".")[0]
    for bucket in [f"{name}", f"{name}-backup", f"{name}-assets", f"{name}-data"]:
        for tpl in [f"https://{bucket}.s3.amazonaws.com", f"https://storage.googleapis.com/{bucket}"]:
            try:
                r = requests.head(tpl, timeout=4)
                if r.status_code in (200, 403):
                    found.append({"url": tpl, "status": r.status_code})
            except Exception:
                pass
    return {"buckets": found}


def _display_dossier(dossier: dict) -> None:
    target = dossier["target"]
    tree   = Tree(f"[bold #ff2d78]🗂  Dossier:[/bold #ff2d78] [bold cyan]{target}[/bold cyan]")

    for section, data in dossier["sections"].items():
        if isinstance(data, dict) and "error" in data and len(data) == 1:
            branch = tree.add(f"[dim]{section}[/dim]  [red]error[/red]")
            continue
        branch = tree.add(f"[bold]{section}[/bold]")
        if isinstance(data, dict):
            for k, v in list(data.items())[:6]:
                if v and str(v) != "None":
                    branch.add(f"[dim]{k}:[/dim] {str(v)[:55]}")
        elif isinstance(data, list):
            for item in data[:4]:
                branch.add(str(item)[:55])

    console.print(tree)


def run(target: str, passive_only: bool = True, output_dir: str = "") -> None:
    console.print(Panel(
        f"[bold #ff2d78]🗂  OSINT Dossier[/bold #ff2d78]  →  [cyan]{target}[/cyan]  "
        f"[dim]({'passive' if passive_only else 'active'})[/dim]",
        expand=False,
    ))

    out = Path(output_dir) if output_dir else Path(".")
    out.mkdir(parents=True, exist_ok=True)

    start   = time.time()
    dossier = build_dossier(target, passive_only=passive_only)
    elapsed = time.time() - start

    _display_dossier(dossier)

    # Save JSON
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_out = out / f"dossier_{target}_{ts}.json"
    json_out.write_text(json.dumps(dossier, indent=2, default=str))
    console.print(f"\n[green]✓[/green] JSON saved: [bold]{json_out}[/bold]")

    sections_ok = sum(1 for v in dossier["sections"].values()
                      if not (isinstance(v, dict) and list(v.keys()) == ["error"]))
    console.print(f"[dim]{sections_ok}/{len(dossier['sections'])} sections populated in {elapsed:.1f}s[/dim]")
    console.print(f"[dim]Generate PDF:[/dim] [bold]omega pdf {target}[/bold]")
