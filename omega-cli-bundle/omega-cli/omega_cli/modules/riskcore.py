"""omega riskcore — Unified risk scoring engine: aggregate all omega JSON findings into
a weighted risk score, CVSS-like category matrix, and prioritised remediation list."""
from __future__ import annotations
import json, os, re, glob, datetime
from typing import Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import BarColumn, Progress, TextColumn

console = Console()

# Risk weights: (max_score, weight)
CATEGORIES: dict[str, dict] = {
    "exposure":       {"label": "Attack Surface Exposure",  "weight": 0.20, "max": 100, "score": 0, "findings": []},
    "vulnerabilities":{"label": "Known Vulnerabilities",    "weight": 0.25, "max": 100, "score": 0, "findings": []},
    "leaks":          {"label": "Data Leaks & Credentials", "weight": 0.20, "max": 100, "score": 0, "findings": []},
    "infrastructure": {"label": "Infrastructure Risk",      "weight": 0.15, "max": 100, "score": 0, "findings": []},
    "reputation":     {"label": "Threat Reputation",        "weight": 0.10, "max": 100, "score": 0, "findings": []},
    "compliance":     {"label": "Compliance & Config",      "weight": 0.10, "max": 100, "score": 0, "findings": []},
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff0000",
    "HIGH":     "#ff4444",
    "MEDIUM":   "#ffd700",
    "LOW":      "#39ff14",
    "INFO":     "#888888",
}

def _score_label(score: float) -> tuple[str, str]:
    if score >= 80: return "CRITICAL", "#ff0000"
    if score >= 60: return "HIGH",     "#ff4444"
    if score >= 40: return "MEDIUM",   "#ffd700"
    if score >= 20: return "LOW",      "#39ff14"
    return "INFO", "#888888"


def _load_all_findings(target: str, report_dir: str) -> list[dict]:
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    pattern = os.path.join(report_dir, f"*{safe}*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime)
    findings = []
    for fpath in files:
        try:
            with open(fpath) as f:
                data = json.load(f)
            data["_source_file"] = os.path.basename(fpath)
            findings.append(data)
        except Exception:
            continue
    return findings


def _analyse(findings_list: list[dict]) -> dict[str, Any]:
    cats = {k: {"score": 0.0, "details": [], "max": 100} for k in CATEGORIES}

    for data in findings_list:
        src = data.get("_source_file", "?")

        # Exposure: open ports, subdomains
        ports = data.get("ports", [])
        subdomains = data.get("subdomains", [])
        cats["exposure"]["score"] += min(len(ports) * 3, 30)
        cats["exposure"]["score"] += min(len(subdomains) * 0.5, 20)
        if ports:
            cats["exposure"]["details"].append(f"{len(ports)} open ports [{src}]")
        if subdomains:
            cats["exposure"]["details"].append(f"{len(subdomains)} subdomains [{src}]")

        # High-risk ports
        risky_ports = [p for p in ports if (isinstance(p, dict) and p.get("port") in
                       [21,22,23,25,110,111,135,137,139,445,1433,3306,3389,5432,6379,27017])
                       or (isinstance(p, int) and p in [21,22,23,25,445,3389,6379,27017])]
        if risky_ports:
            cats["exposure"]["score"] += min(len(risky_ports) * 8, 30)
            cats["exposure"]["details"].append(f"{len(risky_ports)} high-risk ports open [{src}]")

        # Vulnerabilities: CVEs
        cves = data.get("cves", []) or data.get("known_cves", []) or []
        cats["vulnerabilities"]["score"] += min(len(cves) * 10, 60)
        if cves:
            cats["vulnerabilities"]["details"].append(f"{len(cves)} CVEs [{src}]: {', '.join(str(c) for c in cves[:3])}")

        # Shodan vulns
        shodan_vulns = []
        for r in (data.get("shodan") or []):
            shodan_vulns.extend(r.get("vulns", []))
        if shodan_vulns:
            cats["vulnerabilities"]["score"] += min(len(shodan_vulns) * 12, 40)
            cats["vulnerabilities"]["details"].append(f"{len(shodan_vulns)} Shodan vulns [{src}]")

        # Leaks: breaches, leaked creds
        breaches = data.get("hibp_breaches") or data.get("breaches") or []
        paste_count = len(data.get("pastes", []))
        cats["leaks"]["score"] += min(len(breaches) * 10, 50)
        cats["leaks"]["score"] += min(paste_count * 5, 20)
        if breaches:
            cats["leaks"]["details"].append(f"{len(breaches)} breach(es) [{src}]")
        if paste_count:
            cats["leaks"]["details"].append(f"{paste_count} paste(s) [{src}]")

        # Git secrets
        for secret in (data.get("secrets") or []):
            cats["leaks"]["score"] += 15
            cats["leaks"]["details"].append(f"Secret: {secret.get('type','?')} [{src}]")
            if cats["leaks"]["score"] >= 100:
                break

        # Infrastructure: missing security headers, no HSTS, etc.
        headers = data.get("headers", {}) or {}
        missing = []
        for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
            if h not in headers:
                missing.append(h)
        if missing:
            cats["infrastructure"]["score"] += len(missing) * 5
            cats["infrastructure"]["details"].append(f"Missing headers: {', '.join(missing[:3])} [{src}]")

        # SPF/DMARC
        if data.get("spf_result") == "missing" or data.get("dmarc") == "missing":
            cats["infrastructure"]["score"] += 15
            cats["infrastructure"]["details"].append(f"SPF/DMARC misconfigured [{src}]")

        # Expired cert
        if data.get("ssl_error") or data.get("cert_expired"):
            cats["infrastructure"]["score"] += 20
            cats["infrastructure"]["details"].append(f"SSL/TLS issue [{src}]")

        # Reputation: threat intel flags
        for key in ["abuse_score", "otx_score", "greynoise_score"]:
            if isinstance(data.get(key), (int, float)) and data[key] > 0:
                cats["reputation"]["score"] += min(float(data[key]), 30)

        if data.get("malware_detections"):
            cats["reputation"]["score"] += 40
            cats["reputation"]["details"].append(f"Malware detections [{src}]")

        if data.get("phishing"):
            cats["reputation"]["score"] += 30
            cats["reputation"]["details"].append(f"Phishing indicator [{src}]")

        # Compliance: CORS wildcard, HTTPS redirect missing
        if data.get("cors_wildcard"):
            cats["compliance"]["score"] += 20
            cats["compliance"]["details"].append(f"CORS wildcard (*) [{src}]")
        if data.get("http_redirect_missing"):
            cats["compliance"]["score"] += 10
            cats["compliance"]["details"].append(f"No HTTP→HTTPS redirect [{src}]")
        if data.get("cookies_no_httponly"):
            cats["compliance"]["score"] += 15
            cats["compliance"]["details"].append(f"Cookies missing HttpOnly [{src}]")

    # Cap all scores at 100
    for cat in cats.values():
        cat["score"] = min(cat["score"], 100.0)

    return cats


def _weighted_total(cats: dict) -> float:
    total = 0.0
    for key, cfg in CATEGORIES.items():
        cat_score = cats[key]["score"]
        total += cat_score * cfg["weight"]
    return min(total, 100.0)


def _remediation(cats: dict) -> list[dict]:
    remediation = []
    s = cats
    if s["vulnerabilities"]["score"] >= 40:
        remediation.append({"priority": 1, "severity": "CRITICAL", "action": "Patch identified CVEs immediately — run `omega redteam` for exploit mapping"})
    if s["leaks"]["score"] >= 40:
        remediation.append({"priority": 2, "severity": "CRITICAL", "action": "Rotate all exposed credentials — invalidate leaked API keys/passwords"})
    if s["exposure"]["score"] >= 60:
        remediation.append({"priority": 3, "severity": "HIGH", "action": "Close unnecessary open ports — restrict 22/3389/6379/27017 to allowlist IPs"})
    if s["infrastructure"]["score"] >= 30:
        remediation.append({"priority": 4, "severity": "HIGH", "action": "Add missing security headers (HSTS, CSP, X-Frame-Options)"})
    if s["reputation"]["score"] >= 30:
        remediation.append({"priority": 5, "severity": "HIGH", "action": "Investigate threat intel flags — check AbuseIPDB/OTX/GreyNoise for context"})
    if s["compliance"]["score"] >= 20:
        remediation.append({"priority": 6, "severity": "MEDIUM", "action": "Fix CORS policy, enable HttpOnly/Secure cookies, enforce HTTPS redirect"})
    if s["infrastructure"]["score"] >= 15 and "SPF" in str(s["infrastructure"]["details"]):
        remediation.append({"priority": 7, "severity": "MEDIUM", "action": "Configure SPF/DMARC records to prevent email spoofing"})
    if not remediation:
        remediation.append({"priority": 1, "severity": "LOW", "action": "Run `omega auto <target>` to gather full findings first"})
    return sorted(remediation, key=lambda x: x["priority"])


def run(target: str, report_dir: str = "", json_file: str = ""):
    rdir = report_dir or os.path.expanduser("~/.omega/reports")

    console.print(Panel(
        f"[bold #ff2d78]🎯  Risk Scoring Engine[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    if json_file and os.path.exists(json_file):
        with open(json_file) as f:
            data = json.load(f)
        data["_source_file"] = os.path.basename(json_file)
        all_findings = [data]
    else:
        with console.status("[cyan]Loading all omega findings…"):
            all_findings = _load_all_findings(target, rdir)

    console.print(f"[dim]Analysing {len(all_findings)} report file(s)…[/dim]\n")

    cats = _analyse(all_findings)
    total = _weighted_total(cats)
    total_label, total_color = _score_label(total)

    # Risk matrix table
    t = Table(
        "Category", "Score", "Risk Bar", "Severity",
        title="[bold]Risk Category Matrix[/bold]",
        box=box.ROUNDED, header_style="bold #ff2d78"
    )
    for key, cfg in CATEGORIES.items():
        score = cats[key]["score"]
        lbl, color = _score_label(score)
        bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
        t.add_row(
            cfg["label"],
            f"[bold {color}]{score:.0f}/100[/bold {color}]",
            f"[{color}]{bar}[/{color}]",
            f"[bold {color}]{lbl}[/bold {color}]",
        )
    console.print(t)

    # Overall score panel
    bar_total = "█" * int(total / 5) + "░" * (20 - int(total / 5))
    console.print(Panel(
        f"[bold {total_color}]  OVERALL RISK: {total:.1f} / 100   {total_label}[/bold {total_color}]\n"
        f"[{total_color}]{bar_total}[/{total_color}]",
        box=box.HEAVY, border_style=total_color
    ))

    # Key findings
    any_details = any(cats[k]["details"] for k in cats)
    if any_details:
        console.print("\n[bold]Key Findings:[/bold]")
        for key in CATEGORIES:
            for d in cats[key]["details"][:3]:
                lbl, color = _score_label(cats[key]["score"])
                console.print(f"  [{color}]•[/{color}] {d}")

    # Remediation
    console.print("\n[bold]Remediation Priority:[/bold]")
    rt = Table("Priority", "Severity", "Action",
               box=box.SIMPLE_HEAD, header_style="bold yellow")
    for r in _remediation(cats):
        _, color = _score_label({"CRITICAL":85,"HIGH":65,"MEDIUM":45,"LOW":10}.get(r["severity"],10))
        rt.add_row(
            str(r["priority"]),
            f"[bold {color}]{r['severity']}[/bold {color}]",
            r["action"],
        )
    console.print(rt)

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out = os.path.join(out_dir, f"riskcore_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump({
            "target": target,
            "overall_score": round(total, 2),
            "severity": total_label,
            "categories": {k: {"score": cats[k]["score"], "details": cats[k]["details"]} for k in cats},
            "remediation": _remediation(cats),
        }, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
