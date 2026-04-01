"""omega vuln2 — Advanced vulnerability intelligence:
NVD CPE search, EPSS exploit probability, CISA KEV check, PoC finder."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
TIMEOUT = 10

CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API      = "https://api.first.org/data/v1/epss"
NVD_SEARCH    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH = "https://api.github.com/search/repositories"


def _fetch_cisa_kev() -> dict[str, dict]:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    try:
        r = httpx.get(CISA_KEV_URL, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return {
                v["cveID"]: {
                    "vendor":       v.get("vendorProject", "?"),
                    "product":      v.get("product", "?"),
                    "vuln_name":    v.get("vulnerabilityName", "?"),
                    "date_added":   v.get("dateAdded", "?"),
                    "due_date":     v.get("dueDate", "?"),
                    "ransomware":   v.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes":        v.get("notes", ""),
                }
                for v in data.get("vulnerabilities", [])
            }
    except Exception:
        pass
    return {}


def _fetch_epss(cves: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores for a list of CVEs."""
    if not cves:
        return {}
    try:
        cve_str = ",".join(cves[:30])
        r = httpx.get(EPSS_API, params={"cve": cve_str, "envelope": "true"}, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            return {
                item["cve"]: {
                    "epss":       float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
                for item in data.get("data", [])
            }
    except Exception:
        pass
    return {}


def _nvd_search(keyword: str, api_key: str = "", limit: int = 10) -> list[dict]:
    """Search NVD for CVEs matching a keyword."""
    params: dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": limit}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        r = httpx.get(NVD_SEARCH, params=params, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            items = r.json().get("vulnerabilities", [])
            results = []
            for item in items:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "?")
                desc = next((d["value"] for d in cve.get("descriptions", [])
                             if d.get("lang") == "en"), "?")
                # CVSS
                metrics = cve.get("metrics", {})
                cvss_score = None
                cvss_sev   = "?"
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_score = m.get("baseScore")
                        cvss_sev   = m.get("baseSeverity", "?")
                        break
                results.append({
                    "cve":         cve_id,
                    "description": desc[:120],
                    "cvss":        cvss_score,
                    "severity":    cvss_sev,
                    "published":   cve.get("published", "?")[:10],
                })
            return results
    except Exception:
        pass
    return []


def _nvd_cve_detail(cve_id: str, api_key: str = "") -> dict:
    """Get full detail for a single CVE."""
    params = {"cveId": cve_id}
    headers = {"apiKey": api_key} if api_key else {}
    try:
        r = httpx.get(NVD_SEARCH, params=params, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            items = r.json().get("vulnerabilities", [])
            if items:
                cve = items[0].get("cve", {})
                desc = next((d["value"] for d in cve.get("descriptions", [])
                             if d.get("lang") == "en"), "?")
                refs = [r_item.get("url", "") for r_item in cve.get("references", [])[:10]]
                metrics = cve.get("metrics", {})
                cvss = None
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        cvss = metrics[key][0].get("cvssData", {})
                        break
                weaknesses = [w.get("description", [{}])[0].get("value", "?")
                              for w in cve.get("weaknesses", [])[:3]]
                cpe_list = []
                for config in cve.get("configurations", []):
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            cpe_list.append(cpe_match.get("criteria", ""))
                return {
                    "cve":         cve_id,
                    "description": desc,
                    "cvss":        cvss,
                    "published":   cve.get("published", "?")[:10],
                    "modified":    cve.get("lastModified", "?")[:10],
                    "references":  refs,
                    "weaknesses":  weaknesses,
                    "cpe":         cpe_list[:5],
                }
    except Exception:
        pass
    return {}


def _search_poc(cve_id: str, github_token: str = "") -> list[dict]:
    """Search GitHub for PoC repositories matching CVE."""
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    pocs = []
    try:
        r = httpx.get(
            GITHUB_SEARCH,
            params={"q": f"{cve_id} poc exploit", "sort": "stars", "per_page": 5},
            headers=headers,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            for repo in r.json().get("items", [])[:5]:
                pocs.append({
                    "name":        repo.get("full_name"),
                    "stars":       repo.get("stargazers_count", 0),
                    "description": (repo.get("description") or "")[:80],
                    "url":         repo.get("html_url"),
                    "updated":     (repo.get("updated_at") or "")[:10],
                })
    except Exception:
        pass
    return pocs


def _cvss_color(score: float | None) -> str:
    if score is None: return "#888"
    if score >= 9.0:  return "#ff0000"
    if score >= 7.0:  return "#ff4444"
    if score >= 4.0:  return "#ffd700"
    return "#39ff14"


def run(target: str, api_key: str = "", github_token: str = "",
        search: bool = False, check_kev: bool = True, epss: bool = True):
    console.print(Panel(
        f"[bold #ff2d78]🔴  Advanced Vuln Intelligence[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()
    nvd_key = api_key or cfg.get("nvd_api_key", "")
    gh_key  = github_token or cfg.get("github_token", "")

    findings: dict[str, Any] = {"target": target}
    is_cve = bool(re.match(r"CVE-\d{4}-\d{4,7}", target, re.I))

    # Load CISA KEV
    kev: dict[str, dict] = {}
    if check_kev:
        with console.status("[cyan]Fetching CISA KEV catalog…"):
            kev = _fetch_cisa_kev()
        console.print(f"[dim]CISA KEV: {len(kev)} known exploited vulnerabilities loaded[/dim]")

    if is_cve:
        cve_id = target.upper()
        # Detailed CVE lookup
        with console.status(f"[cyan]Fetching NVD detail for {cve_id}…"):
            detail = _nvd_cve_detail(cve_id, nvd_key)
        findings["cve_detail"] = detail

        if detail:
            cvss = detail.get("cvss", {}) or {}
            score = cvss.get("baseScore")
            color = _cvss_color(score)
            console.print(f"\n[bold]CVE:[/bold] [cyan]{cve_id}[/cyan]")
            console.print(f"[bold]Published:[/bold]   {detail.get('published','?')}")
            console.print(f"[bold]Modified:[/bold]    {detail.get('modified','?')}")
            if score:
                console.print(f"[bold]CVSS Score:[/bold]  [{color}]{score} ({cvss.get('baseSeverity','?')})[/{color}]")
            console.print(f"\n[italic]{detail.get('description','?')[:200]}[/italic]")

            if detail.get("weaknesses"):
                console.print(f"\n[bold]CWE:[/bold] {', '.join(detail['weaknesses'])}")
            if detail.get("cpe"):
                console.print(f"[bold]Affected:[/bold] {' | '.join(detail['cpe'][:3])}")

        # KEV check
        kev_info = kev.get(cve_id)
        if kev_info:
            console.print(Panel(
                f"[bold red]⚠  IN CISA KEV — Actively Exploited in the Wild[/bold red]\n"
                f"Vendor: {kev_info['vendor']}  |  Product: {kev_info['product']}\n"
                f"Added: {kev_info['date_added']}  |  Ransomware: {kev_info['ransomware']}\n"
                f"Remediation due: {kev_info['due_date']}",
                box=box.HEAVY, border_style="red"
            ))
            findings["kev"] = kev_info
        else:
            console.print("[green]✓  Not in CISA KEV catalog[/green]")

        # EPSS
        if epss:
            with console.status("[cyan]Fetching EPSS exploit probability…"):
                epss_data = _fetch_epss([cve_id])
            e = epss_data.get(cve_id, {})
            if e:
                epss_score = e["epss"]
                pct = e["percentile"]
                color = "#ff0000" if epss_score > 0.5 else "#ffd700" if epss_score > 0.1 else "#39ff14"
                console.print(f"\n[bold]EPSS Score:[/bold]  [{color}]{epss_score:.4f}[/{color}]  "
                              f"({pct*100:.1f}th percentile — exploit probability in 30 days)")
                findings["epss"] = e

        # PoC search
        with console.status("[cyan]Searching GitHub for PoC exploits…"):
            pocs = _search_poc(cve_id, gh_key)
        findings["poc_repos"] = pocs
        if pocs:
            console.print(f"\n[bold red]⚠  {len(pocs)} PoC/Exploit Repo(s) on GitHub:[/bold red]")
            t = Table("Repo", "Stars", "Description", "Updated",
                      box=box.SIMPLE_HEAD, header_style="bold red")
            for p in pocs:
                t.add_row(p["name"], str(p["stars"]), p["description"][:50], p["updated"])
            console.print(t)
            if detail.get("references"):
                console.print(f"\n[bold]NVD References:[/bold]")
                for ref in detail["references"][:5]:
                    console.print(f"  [cyan]•[/cyan] {ref}")
        else:
            console.print("[green]✓  No public PoC repos found on GitHub[/green]")

    else:
        # Keyword/product search
        with console.status(f"[cyan]Searching NVD for '{target}'…"):
            results = _nvd_search(target, nvd_key, limit=15)
        findings["nvd_results"] = results

        if results:
            cve_ids = [r["cve"] for r in results]

            # Batch EPSS
            epss_scores: dict = {}
            if epss:
                with console.status("[cyan]Fetching EPSS scores…"):
                    epss_scores = _fetch_epss(cve_ids)

            t = Table("CVE", "CVSS", "Severity", "EPSS", "Published", "Description",
                      title=f"[bold]NVD Results for '{target}' ({len(results)})[/bold]",
                      box=box.ROUNDED, header_style="bold #ff2d78")
            for r in results:
                score = r.get("cvss")
                color = _cvss_color(score)
                epss_val = epss_scores.get(r["cve"], {}).get("epss")
                epss_str = f"{epss_val:.3f}" if epss_val is not None else "—"
                kev_flag = " [red]KEV[/red]" if r["cve"] in kev else ""
                t.add_row(
                    f"[cyan]{r['cve']}[/cyan]{kev_flag}",
                    f"[{color}]{score or '?'}[/{color}]",
                    f"[{color}]{r.get('severity','?')}[/{color}]",
                    epss_str,
                    r.get("published", "?"),
                    r.get("description", "?")[:50],
                )
            console.print(t)

            # KEV hits
            kev_hits = [r for r in results if r["cve"] in kev]
            if kev_hits:
                console.print(f"\n[bold red]⚠  {len(kev_hits)} CVE(s) in CISA KEV (actively exploited):[/bold red]")
                for h in kev_hits:
                    console.print(f"  [red]•[/red] {h['cve']} — {kev[h['cve']]['product']}")
        else:
            console.print(f"[dim]No CVEs found for '{target}' in NVD[/dim]")

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out = os.path.join(out_dir, f"vuln2_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
