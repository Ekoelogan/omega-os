"""Phishing detection — URLScan.io, PhishTank, Google Safe Browsing."""
import requests
import json
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def _urlscan_submit(url: str, api_key: str = "") -> str:
    """Submit URL to URLScan.io and return scan UUID."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["API-Key"] = api_key
    try:
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json={"url": url, "visibility": "public"},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("uuid", "")
        elif r.status_code == 401:
            console.print("[yellow]URLScan API key invalid/missing — scanning as anonymous[/]")
    except Exception as e:
        console.print(f"[red]URLScan submit error:[/] {e}")
    return ""


def _urlscan_result(uuid: str) -> dict:
    """Fetch URLScan result (may need polling)."""
    for attempt in range(6):
        try:
            r = requests.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                timeout=15,
            )
            if r.status_code == 200:
                return r.json()
            elif r.status_code == 404:
                time.sleep(5)
        except Exception:
            break
    return {}


def _urlscan_search(domain: str) -> list:
    """Search existing URLScan results for a domain."""
    try:
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 20},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("results", [])
    except Exception:
        pass
    return []


def _phishtank_check(url: str, api_key: str = "") -> dict:
    """Check URL against PhishTank database."""
    try:
        params = {"url": url, "format": "json"}
        if api_key:
            params["app_key"] = api_key
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=params, timeout=15,
            headers={"User-Agent": "phishtank/omega-cli"},
        )
        if r.status_code == 200:
            return r.json().get("results", {})
    except Exception:
        pass
    return {}


def _gsb_check(url: str, api_key: str) -> list:
    """Check URL against Google Safe Browsing API v4."""
    if not api_key:
        return []
    try:
        payload = {
            "client": {"clientId": "omega-cli", "clientVersion": "0.6.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            }
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload, timeout=10,
        )
        if r.status_code == 200:
            return r.json().get("matches", [])
    except Exception:
        pass
    return []


def _score_indicators(data: dict) -> list:
    """Extract phishing risk indicators from URLScan result."""
    indicators = []
    page = data.get("page", {})
    lists = data.get("lists", {})
    verdicts = data.get("verdicts", {})
    stats = data.get("stats", {})

    if verdicts.get("overall", {}).get("malicious"):
        indicators.append(("CRITICAL", "URLScan flagged as malicious"))
    if verdicts.get("overall", {}).get("score", 0) > 50:
        indicators.append(("HIGH", f"URLScan score: {verdicts['overall']['score']}"))
    if lists.get("maliciousUrls"):
        indicators.append(("HIGH", f"Malicious URLs in page: {len(lists['maliciousUrls'])}"))
    if stats.get("ipStats"):
        countries = {s.get("countries", [None])[0] for s in stats["ipStats"]}
        if len(countries) > 5:
            indicators.append(("MEDIUM", f"Loaded resources from {len(countries)} countries"))
    if page.get("tlsIssuer", "").lower() in ("let's encrypt", "zerossl"):
        indicators.append(("LOW", "Free TLS cert (common in phishing)"))

    return indicators


def run(target: str, api_key: str = "", phishtank_key: str = "", gsb_key: str = "", live_scan: bool = False):
    """Check a URL or domain for phishing indicators."""
    if not target.startswith("http"):
        target_url = f"https://{target}"
        domain = target
    else:
        target_url = target
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    console.print(Panel(
        f"[bold #ff2d78]🎣 Phishing Detection[/]\n[dim]Target:[/] [cyan]{target_url}[/]",
        border_style="#ff85b3",
    ))

    results = {"target": target_url, "verdicts": {}}
    risk_items = []

    # URLScan historical search
    console.print("[dim]  Searching URLScan.io history...[/]")
    scan_results = _urlscan_search(domain)
    if scan_results:
        tbl = Table(
            title=f"URLScan History ({len(scan_results)} scans)",
            box=box.ROUNDED, border_style="#ff85b3",
        )
        tbl.add_column("Date", width=12)
        tbl.add_column("URL", style="cyan")
        tbl.add_column("Country", width=8)
        tbl.add_column("Malicious", width=10)
        tbl.add_column("Score", width=6)

        for s in scan_results[:10]:
            page = s.get("page", {})
            verdicts = s.get("verdicts", {})
            mal = verdicts.get("overall", {}).get("malicious", False)
            score = verdicts.get("overall", {}).get("score", 0)
            tbl.add_row(
                s.get("task", {}).get("time", "")[:10],
                page.get("url", "")[:70],
                page.get("country", ""),
                f"[red]YES[/]" if mal else "[green]no[/]",
                str(score),
            )
        console.print(tbl)

        malicious_count = sum(1 for s in scan_results if s.get("verdicts", {}).get("overall", {}).get("malicious"))
        if malicious_count:
            risk_items.append(("CRITICAL", f"{malicious_count} of {len(scan_results)} scans flagged as malicious"))

    # Live scan
    if live_scan:
        console.print("[dim]  Submitting to URLScan.io for live scan...[/]")
        uuid = _urlscan_submit(target_url, api_key)
        if uuid:
            console.print(f"[dim]  Scan submitted (UUID: {uuid}), waiting 15s...[/]")
            time.sleep(15)
            scan_data = _urlscan_result(uuid)
            if scan_data:
                indicators = _score_indicators(scan_data)
                risk_items.extend(indicators)
                console.print(f"[dim]  Full report: https://urlscan.io/result/{uuid}/[/]")
                results["urlscan_uuid"] = uuid

    # PhishTank
    console.print("[dim]  Checking PhishTank...[/]")
    pt = _phishtank_check(target_url, phishtank_key)
    if pt.get("in_database"):
        if pt.get("valid"):
            risk_items.append(("CRITICAL", "Listed in PhishTank as ACTIVE phishing site"))
            results["phishtank"] = "ACTIVE"
        else:
            risk_items.append(("MEDIUM", "URL listed in PhishTank (possibly expired)"))
            results["phishtank"] = "LISTED"
    else:
        results["phishtank"] = "clean"

    # Google Safe Browsing
    if gsb_key:
        console.print("[dim]  Checking Google Safe Browsing...[/]")
        matches = _gsb_check(target_url, gsb_key)
        if matches:
            for m in matches:
                risk_items.append(("CRITICAL", f"GSB: {m.get('threatType')} detected"))
            results["gsb"] = [m.get("threatType") for m in matches]
        else:
            results["gsb"] = "clean"

    # Risk summary
    if risk_items:
        rtbl = Table(
            title=f"[bold red]⚠  Risk Indicators ({len(risk_items)})[/]",
            box=box.ROUNDED, border_style="red",
        )
        rtbl.add_column("Severity", width=10)
        rtbl.add_column("Finding")
        for sev, msg in risk_items:
            c = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(sev, "white")
            rtbl.add_row(f"[{c}]{sev}[/]", msg)
        console.print(rtbl)
        results["risk_level"] = risk_items[0][0]
    else:
        console.print("[green]✓[/] No phishing indicators found.")
        results["risk_level"] = "CLEAN"

    results["indicators"] = risk_items
    return results
