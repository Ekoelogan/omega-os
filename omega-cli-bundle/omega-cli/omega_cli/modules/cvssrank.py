"""cvssrank.py — Bulk CVE ranker: accept list of CVEs, rank by CVSS+EPSS+KEV, output triage table."""
from __future__ import annotations
import json, re, time
from pathlib import Path
from typing import Optional
import urllib.request, urllib.error

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **kw): print(*a)
    console = Console()
    Table = Panel = box = None

BANNER = r"""
██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  OMEGA-CLI v1.8.0 — OSINT & Passive Recon Toolkit
"""

UA = "Mozilla/5.0 (compatible; OmegaCLI/1.8.0)"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"
NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

_KEV_CACHE: Optional[set] = None


def _get_json(url: str, timeout: int = 15) -> Optional[dict | list]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _load_kev() -> set:
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    data = _get_json(CISA_KEV_URL)
    if data:
        _KEV_CACHE = {v["cveID"] for v in data.get("vulnerabilities", [])}
    else:
        _KEV_CACHE = set()
    return _KEV_CACHE


def _get_epss(cve: str) -> tuple[float, float]:
    """Returns (epss_score, epss_percentile)."""
    data = _get_json(EPSS_URL.format(cve=cve))
    if data and data.get("data"):
        d = data["data"][0]
        return float(d.get("epss", 0)), float(d.get("percentile", 0))
    return 0.0, 0.0


def _get_nvd(cve: str, api_key: str = "") -> dict:
    url = NVD_URL.format(cve=cve)
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode())
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return {}
            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})
            # Try CVSS v3.1 → v3.0 → v2
            cvss_score, cvss_severity, vector = None, "", ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = metrics.get(key, [])
                if m:
                    cvss_data = m[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity", m[0].get("baseSeverity", ""))
                    vector = cvss_data.get("vectorString", "")
                    break
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break
            return {
                "cvss":       cvss_score,
                "severity":   cvss_severity,
                "vector":     vector,
                "published":  cve_data.get("published", "")[:10],
                "description": desc,
            }
    except Exception:
        return {}


def _omega_score(cvss: Optional[float], epss: float, in_kev: bool) -> float:
    """Composite triage score 0-100 weighting CVSS + EPSS + KEV."""
    score = 0.0
    if cvss is not None:
        score += (cvss / 10.0) * 40   # 40% weight
    score += epss * 40               # 40% weight  (epss 0.0–1.0)
    if in_kev:
        score += 20                  # 20% bonus for KEV
    return round(min(100, score), 1)


def _severity_color(sev: str) -> str:
    s = (sev or "").upper()
    return {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"green"}.get(s, "dim")


def run(cves_input: str, api_key: str = "", file: str = "",
        top: int = 0, export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel("📊  Bulk CVE Ranker — CVSS + EPSS + CISA KEV", style="bold cyan"))

    # Build CVE list
    cves: list[str] = []

    if file and Path(file).exists():
        raw = Path(file).read_text()
        cves = re.findall(r"CVE-\d{4}-\d{4,}", raw, re.I)
        console.print(f"[cyan]Loaded {len(cves)} CVEs from {file}[/cyan]")
    else:
        cves = re.findall(r"CVE-\d{4}-\d{4,}", cves_input, re.I)

    if not cves:
        console.print("[yellow]No CVE IDs found. Provide CVE-YYYY-NNNNN format.[/yellow]")
        return

    cves = list(dict.fromkeys(c.upper() for c in cves))  # dedup preserve order
    console.print(f"[cyan]Ranking {len(cves)} CVEs...[/cyan]")

    # Load KEV
    console.print("[dim]Loading CISA KEV database...[/dim]")
    kev_set = _load_kev()
    console.print(f"[dim]KEV: {len(kev_set)} known exploited vulnerabilities[/dim]")

    ranked = []
    for i, cve in enumerate(cves):
        console.print(f"  [{i+1}/{len(cves)}] {cve}", end="\r")
        nvd  = _get_nvd(cve, api_key=api_key)
        epss_score, epss_pct = _get_epss(cve)
        in_kev = cve in kev_set
        omega  = _omega_score(nvd.get("cvss"), epss_score, in_kev)

        ranked.append({
            "cve":         cve,
            "cvss":        nvd.get("cvss"),
            "severity":    nvd.get("severity", ""),
            "epss":        epss_score,
            "epss_pct":    epss_pct,
            "kev":         in_kev,
            "omega_score": omega,
            "published":   nvd.get("published", ""),
            "description": nvd.get("description", ""),
            "vector":      nvd.get("vector", ""),
        })
        time.sleep(0.6)  # NVD rate limit (10 req/min without key, 50 with key)

    console.print()  # newline after \r

    # Sort by omega score descending
    ranked.sort(key=lambda x: x["omega_score"], reverse=True)
    if top:
        ranked = ranked[:top]

    # Display
    t = Table(title=f"📊 CVE Triage Ranking (top {len(ranked)})", box=box.SIMPLE if box else None)
    t.add_column("Rank",         style="dim",    width=5)
    t.add_column("CVE",          style="cyan",   min_width=18)
    t.add_column("CVSS",         style="bold",   width=6)
    t.add_column("Severity",     width=10)
    t.add_column("EPSS",         width=8)
    t.add_column("EPSS%ile",     style="dim",    width=9)
    t.add_column("KEV",          width=5)
    t.add_column("Ω Score",      style="bold",   width=8)
    t.add_column("Published",    style="dim",    width=12)

    for i, r in enumerate(ranked, 1):
        sev_color = _severity_color(r["severity"])
        kev_mark  = "[red]YES[/red]" if r["kev"] else "[dim]no[/dim]"
        omega_color = "red" if r["omega_score"] >= 70 else "orange3" if r["omega_score"] >= 50 else "yellow" if r["omega_score"] >= 30 else "green"
        t.add_row(
            str(i),
            r["cve"],
            str(r["cvss"] or "N/A"),
            f"[{sev_color}]{r['severity']}[/{sev_color}]" if r["severity"] else "[dim]N/A[/dim]",
            f"{r['epss']:.3f}",
            f"{r['epss_pct']*100:.0f}%" if r["epss_pct"] else "N/A",
            kev_mark,
            f"[{omega_color}]{r['omega_score']}[/{omega_color}]",
            r["published"],
        )
    console.print(t)

    # Summary stats
    critical_count = sum(1 for r in ranked if r["severity"] == "CRITICAL")
    kev_count      = sum(1 for r in ranked if r["kev"])
    high_epss      = sum(1 for r in ranked if r["epss"] >= 0.5)
    console.print(
        f"\n[bold]Summary:[/bold] {len(ranked)} CVEs | "
        f"[red]{critical_count} CRITICAL[/red] | "
        f"[red]{kev_count} in CISA KEV[/red] | "
        f"[orange3]{high_epss} EPSS ≥50%[/orange3]"
    )
    if ranked:
        top1 = ranked[0]
        console.print(f"[bold]Top Priority:[/bold] [cyan]{top1['cve']}[/cyan] — Ω{top1['omega_score']} | "
                      f"CVSS {top1['cvss']} | EPSS {top1['epss']:.3f} | KEV {'✓' if top1['kev'] else '✗'}")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = re.sub(r"[^\w]", "_", cves_input[:20]) if not file else Path(file).stem
    out_path = Path(export) if export else out_dir / f"cvssrank_{ts}.json"
    out_path.write_text(json.dumps(ranked, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
