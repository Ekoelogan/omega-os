"""Real-time CVE lookup from NIST NVD API v2."""
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime

console = Console()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(keyword: str, limit: int = 10, min_score: float = 0.0,
                api_key: str = "") -> list:
    """Search NVD for CVEs matching a keyword."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": min(limit, 20),
        "startIndex": 0,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            results = []
            for v in vulns:
                cve_id = v["cve"]["id"]
                desc = v["cve"]["descriptions"]
                desc_en = next((d["value"] for d in desc if d["lang"] == "en"), "No description")

                # Extract CVSS score
                score = 0.0
                severity = "UNKNOWN"
                metrics = v["cve"].get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss = metrics[key][0]
                        score = cvss.get("cvssData", {}).get("baseScore", 0.0)
                        severity = cvss.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                        break

                if score >= min_score:
                    published = v["cve"].get("published", "")[:10]
                    refs = v["cve"].get("references", [])
                    cwe = v["cve"].get("weaknesses", [])
                    cwe_ids = [w["description"][0]["value"] for w in cwe if w.get("description")]

                    results.append({
                        "id": cve_id,
                        "score": score,
                        "severity": severity,
                        "description": desc_en[:300],
                        "published": published,
                        "references": [r["url"] for r in refs[:3]],
                        "cwe": cwe_ids[:2],
                    })
            return results
        elif r.status_code == 403:
            console.print("[yellow]NVD rate limit — add API key with:[/] [cyan]omega config set nvd_api_key KEY[/]")
            console.print("[dim]Get free key at: https://nvd.nist.gov/developers/request-an-api-key[/]")
        else:
            console.print(f"[red]NVD API error {r.status_code}[/]")
    except Exception as e:
        console.print(f"[red]Error querying NVD:[/] {e}")

    return []


def run(keyword: str, limit: int = 10, min_score: float = 0.0, api_key: str = ""):
    """Query NIST NVD for real-time CVE data."""
    console.print(Panel(
        f"[bold #ff2d78]🔍 NVD CVE Lookup[/]\n"
        f"[dim]Keyword:[/] [cyan]{keyword}[/]  "
        f"[dim]Min CVSS:[/] [yellow]{min_score}[/]",
        border_style="#ff85b3",
    ))

    results = search_cves(keyword, limit, min_score, api_key)

    if not results:
        console.print("[yellow]No CVEs found.[/]")
        return []

    tbl = Table(
        title=f"CVEs for '{keyword}' — {len(results)} results",
        box=box.ROUNDED, border_style="#ff85b3", show_lines=True,
    )
    tbl.add_column("CVE ID", style="bold cyan", width=16)
    tbl.add_column("CVSS", width=6)
    tbl.add_column("Severity", width=10)
    tbl.add_column("Published", width=12)
    tbl.add_column("Description")

    for cve in results:
        score = cve["score"]
        sev = cve["severity"]
        color = "red" if score >= 9.0 else "orange1" if score >= 7.0 else "yellow" if score >= 4.0 else "green"
        tbl.add_row(
            cve["id"],
            f"[{color}]{score}[/]",
            f"[{color}]{sev}[/]",
            cve["published"],
            cve["description"][:120],
        )

    console.print(tbl)

    # Show references for critical/high
    critical = [c for c in results if c["score"] >= 7.0]
    if critical:
        console.print("\n[bold red]🚨 High/Critical CVEs — References:[/]")
        for c in critical[:5]:
            console.print(f"\n  [bold cyan]{c['id']}[/]  CVSS {c['score']}")
            for ref in c["references"]:
                console.print(f"    [dim link={ref}]{ref}[/]")

    return results
