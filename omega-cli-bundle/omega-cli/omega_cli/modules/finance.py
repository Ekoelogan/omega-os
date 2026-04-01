"""omega finance — Financial OSINT: SEC EDGAR, OpenCorporates, funding rounds, insider trading."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

console = Console()
TIMEOUT = 12


def _sec_company_search(name: str) -> list[dict]:
    try:
        r = httpx.get(
            "https://efts.sec.gov/LATEST/search-index?q=%22{}%22&dateRange=custom&startdt=2020-01-01&forms=10-K,10-Q,8-K".format(
                name.replace(" ", "+")
            ),
            timeout=TIMEOUT,
            headers={"User-Agent": "omega-cli osint@example.com"},
        )
        if r.status_code == 200:
            hits = r.json().get("hits", {}).get("hits", [])
            return [{"company": h.get("_source", {}).get("entity_name"),
                     "form": h.get("_source", {}).get("form_type"),
                     "filed": h.get("_source", {}).get("file_date"),
                     "cik": h.get("_source", {}).get("entity_id")} for h in hits[:10]]
    except Exception:
        pass
    return []


def _sec_edgar_filings(query: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        # Full-text search
        r = httpx.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": f'"{query}"', "forms": "10-K,10-Q,8-K,S-1", "dateRange": "custom",
                    "startdt": "2020-01-01"},
            headers={"User-Agent": "omega-cli osint@example.com"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            hits = r.json().get("hits", {}).get("hits", [])
            result["filings"] = [
                {
                    "company": h.get("_source", {}).get("entity_name"),
                    "form": h.get("_source", {}).get("form_type"),
                    "filed": h.get("_source", {}).get("file_date"),
                    "description": h.get("_source", {}).get("file_description", "")[:80],
                    "url": f"https://www.sec.gov/Archives/edgar/data/{h.get('_source', {}).get('entity_id')}/",
                }
                for h in hits[:15]
            ]
    except Exception:
        pass

    # Company ticker/CIK lookup
    try:
        r2 = httpx.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": query, "forms": "DEF 14A,4,SC 13G"},
            headers={"User-Agent": "omega-cli osint@example.com"},
            timeout=TIMEOUT,
        )
        if r2.status_code == 200:
            result["ownership_filings"] = len(r2.json().get("hits", {}).get("hits", []))
    except Exception:
        pass

    return result


def _opencorporates(company: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    try:
        r = httpx.get(
            "https://api.opencorporates.com/v0.4/companies/search",
            params={"q": company, "per_page": 10},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            companies = r.json().get("results", {}).get("companies", [])
            result["companies"] = [
                {
                    "name": c.get("company", {}).get("name"),
                    "jurisdiction": c.get("company", {}).get("jurisdiction_code"),
                    "company_number": c.get("company", {}).get("company_number"),
                    "status": c.get("company", {}).get("current_status"),
                    "incorporation_date": c.get("company", {}).get("incorporation_date"),
                    "registered_address": c.get("company", {}).get("registered_address_in_full"),
                    "url": c.get("company", {}).get("opencorporates_url"),
                }
                for c in companies
            ]
    except Exception:
        pass
    return result


def _crunchbase_funding(company: str) -> dict[str, Any]:
    """Fetch public Crunchbase funding data."""
    result: dict[str, Any] = {}
    slug = re.sub(r"[^a-z0-9]", "-", company.lower()).strip("-")
    try:
        r = httpx.get(
            f"https://www.crunchbase.com/organization/{slug}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
            follow_redirects=True,
        )
        if r.status_code == 200:
            body = r.text
            # Extract funding info from page
            total_m = re.search(r'"fundingTotal":\{"value":([0-9.]+)', body)
            rounds_m = re.search(r'"numFundingRounds":(\d+)', body)
            investors_m = re.findall(r'"investorName":"([^"]+)"', body)
            last_round_m = re.search(r'"lastFundingType":"([^"]+)"', body)
            result["funding"] = {
                "total_usd": float(total_m.group(1)) if total_m else None,
                "rounds": int(rounds_m.group(1)) if rounds_m else None,
                "last_round_type": last_round_m.group(1) if last_round_m else None,
                "investors": list(set(investors_m))[:15],
            }
    except Exception:
        pass
    return result


def _sec_insider_trading(ticker: str) -> list[dict]:
    """Fetch Form 4 (insider trading) filings for a ticker."""
    results = []
    try:
        r = httpx.get(
            "https://efts.sec.gov/LATEST/search-index",
            params={"q": ticker, "forms": "4", "dateRange": "custom",
                    "startdt": (datetime.date.today() - datetime.timedelta(days=180)).isoformat()},
            headers={"User-Agent": "omega-cli osint@example.com"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            hits = r.json().get("hits", {}).get("hits", [])
            for h in hits[:10]:
                s = h.get("_source", {})
                results.append({
                    "filer": s.get("display_names", ["?"])[0] if s.get("display_names") else "?",
                    "filed": s.get("file_date"),
                    "form": s.get("form_type"),
                    "company": s.get("entity_name"),
                })
    except Exception:
        pass
    return results


def _company_news(company: str) -> list[dict]:
    """Search for recent company news via HN + RSS."""
    results = []
    try:
        r = httpx.get(
            "https://hn.algolia.com/api/v1/search",
            params={"query": company, "tags": "story", "hitsPerPage": 5,
                    "numericFilters": "created_at_i>{}".format(
                        int((datetime.datetime.now() - datetime.timedelta(days=90)).timestamp())
                    )},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            for h in r.json().get("hits", []):
                results.append({
                    "title": h.get("title"),
                    "url": h.get("url"),
                    "points": h.get("points"),
                    "date": h.get("created_at", "")[:10],
                    "source": "HackerNews",
                })
    except Exception:
        pass
    return results


def run(target: str, ticker: str = "", deep: bool = False):
    console.print(Panel(
        f"[bold #ff2d78]💰  Financial OSINT[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    findings: dict[str, Any] = {"target": target}

    # SEC EDGAR
    with console.status("[cyan]Querying SEC EDGAR…"):
        edgar = _sec_edgar_filings(ticker or target)
    findings["edgar"] = edgar

    filings = edgar.get("filings", [])
    if filings:
        t = Table("Company", "Form", "Filed", "Description",
                  title=f"[bold]📑 {len(filings)} SEC Filing(s)[/bold]",
                  box=box.SIMPLE_HEAD, header_style="bold cyan")
        for f in filings:
            t.add_row(
                (f.get("company") or "?")[:35],
                f.get("form", "?"),
                f.get("filed", "?"),
                (f.get("description") or "")[:50],
            )
        console.print(t)
    else:
        console.print("[dim]No SEC filings found.[/dim]")

    # Insider trading
    if ticker:
        with console.status("[cyan]Checking insider trading (Form 4)…"):
            insider = _sec_insider_trading(ticker)
        findings["insider_trading"] = insider
        if insider:
            t2 = Table("Filer", "Company", "Form", "Filed",
                       title=f"[bold yellow]📊 {len(insider)} Insider Filing(s)[/bold yellow]",
                       box=box.SIMPLE_HEAD, header_style="bold yellow")
            for i in insider:
                t2.add_row(i.get("filer", "?")[:40], i.get("company", "?")[:30],
                           i.get("form", "?"), i.get("filed", "?"))
            console.print(t2)

    # OpenCorporates
    with console.status("[cyan]Searching OpenCorporates…"):
        oc = _opencorporates(target)
    findings["opencorporates"] = oc

    companies = oc.get("companies", [])
    if companies:
        t3 = Table("Name", "Jurisdiction", "Status", "Incorporated", "Number",
                   title=f"[bold]🏛  {len(companies)} Corporate Registration(s)[/bold]",
                   box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
        for c in companies:
            t3.add_row(
                (c.get("name") or "?")[:35],
                c.get("jurisdiction", "?"),
                c.get("status") or "?",
                c.get("incorporation_date") or "?",
                c.get("company_number") or "?",
            )
        console.print(t3)
    else:
        console.print("[dim]No OpenCorporates records found.[/dim]")

    # Crunchbase funding
    with console.status("[cyan]Checking Crunchbase funding…"):
        cb = _crunchbase_funding(target)
    findings["crunchbase"] = cb

    funding = cb.get("funding", {})
    if funding and funding.get("total_usd"):
        total = funding["total_usd"]
        console.print(f"\n[bold]💵 Funding:[/bold] "
                      f"[green]${total:,.0f}[/green] across "
                      f"[cyan]{funding.get('rounds', '?')}[/cyan] rounds "
                      f"(last: {funding.get('last_round_type', '?')})")
        investors = funding.get("investors", [])
        if investors:
            console.print(f"  [dim]Investors: {', '.join(investors[:8])}[/dim]")

    # News
    with console.status("[cyan]Fetching recent news…"):
        news = _company_news(target)
    findings["news"] = news
    if news:
        console.print(f"\n[bold]📰 Recent News ({len(news)}):[/bold]")
        for n in news:
            console.print(f"  [{n.get('points', 0)} pts] [cyan]{n.get('title', '?')[:70]}[/cyan]")
            console.print(f"  [dim]{n.get('date')} — {n.get('url', '')[:70]}[/dim]")

    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"finance_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
