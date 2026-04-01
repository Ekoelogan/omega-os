"""omega phoneosint — Phone number OSINT: carrier lookup, line type, location,
spam/robocall score, and OSINT aggregation from free sources."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
TIMEOUT = 8

# Country code prefix map (sample)
CC_MAP: dict[str, str] = {
    "+1": "US/CA", "+44": "GB", "+49": "DE", "+33": "FR", "+34": "ES",
    "+39": "IT", "+31": "NL", "+46": "SE", "+47": "NO", "+45": "DK",
    "+61": "AU", "+64": "NZ", "+81": "JP", "+82": "KR", "+86": "CN",
    "+91": "IN", "+7": "RU", "+55": "BR", "+52": "MX", "+27": "ZA",
    "+20": "EG", "+234": "NG", "+254": "KE", "+971": "AE", "+966": "SA",
    "+972": "IL", "+90": "TR", "+62": "ID", "+63": "PH", "+60": "MY",
    "+66": "TH", "+84": "VN", "+880": "BD", "+92": "PK", "+93": "AF",
}

# US area code → state
US_AREA: dict[str, str] = {
    "212": "New York, NY", "213": "Los Angeles, CA", "312": "Chicago, IL",
    "415": "San Francisco, CA", "617": "Boston, MA", "202": "Washington, DC",
    "305": "Miami, FL", "404": "Atlanta, GA", "713": "Houston, TX",
    "206": "Seattle, WA", "303": "Denver, CO", "214": "Dallas, TX",
    "702": "Las Vegas, NV", "602": "Phoenix, AZ", "503": "Portland, OR",
    "512": "Austin, TX", "919": "Raleigh, NC", "615": "Nashville, TN",
    "801": "Salt Lake City, UT", "804": "Richmond, VA",
}


def _normalize(number: str) -> str:
    """Strip formatting, ensure E.164 format."""
    cleaned = re.sub(r"[\s\-\(\)\.]+", "", number)
    if not cleaned.startswith("+"):
        if cleaned.startswith("00"):
            cleaned = "+" + cleaned[2:]
        elif cleaned.startswith("1") and len(cleaned) == 11:
            cleaned = "+" + cleaned
        else:
            cleaned = "+1" + cleaned  # assume US
    return cleaned


def _detect_country(e164: str) -> str:
    for prefix in sorted(CC_MAP.keys(), key=len, reverse=True):
        if e164.startswith(prefix):
            return CC_MAP[prefix]
    return "Unknown"


def _detect_us_region(e164: str) -> str:
    if e164.startswith("+1") and len(e164) >= 5:
        area = e164[2:5]
        return US_AREA.get(area, f"Area code {area}")
    return ""


def _numverify(number: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        r = httpx.get(
            "http://apilayer.net/api/validate",
            params={"access_key": api_key, "number": number, "country_code": "", "format": 1},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _abstract_api(number: str, api_key: str) -> dict:
    """Abstract Phone Validation API (free tier: 250/month)."""
    if not api_key:
        return {}
    try:
        r = httpx.get(
            "https://phonevalidation.abstractapi.com/v1/",
            params={"api_key": api_key, "phone": number},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _opencnam(number: str) -> dict:
    """OpenCNAM CNAM lookup (free tier)."""
    try:
        e164 = number.replace("+", "")
        r = httpx.get(
            f"https://api.opencnam.com/v3/phone/{e164}",
            params={"format": "json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _check_sync_me(number: str) -> dict:
    """Query sync.me public API for spam/robocall score."""
    try:
        clean = re.sub(r"[^\d+]", "", number)
        r = httpx.get(
            f"https://sync.me/api/phone/{clean}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _check_should_i_answer(number: str) -> str:
    """Scrape shouldianswer.com rating."""
    try:
        clean = re.sub(r"[^\d]", "", number).lstrip("1")
        r = httpx.get(
            f"https://www.shouldianswer.com/phone-number/{clean}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            m = re.search(r'rating["\s:]+([0-9.-]+)', r.text, re.I)
            if m:
                return m.group(1)
    except Exception:
        pass
    return ""


def _line_type_heuristic(e164: str) -> str:
    """Heuristic line type from number patterns."""
    if e164.startswith("+1800") or e164.startswith("+1888") or \
       e164.startswith("+1877") or e164.startswith("+1866") or \
       e164.startswith("+1855") or e164.startswith("+1844") or \
       e164.startswith("+1833"):
        return "Toll-free"
    if e164.startswith("+1900"):
        return "Premium rate"
    return "Mobile/Landline"


def run(number: str, api_key: str = "", abstract_key: str = ""):
    e164 = _normalize(number)
    console.print(Panel(
        f"[bold #ff2d78]📞  Phone Number OSINT[/bold #ff2d78] — [cyan]{e164}[/cyan]",
        box=box.ROUNDED
    ))

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()
    numverify_key = api_key or cfg.get("numverify_api_key", "")
    abstract_key  = abstract_key or cfg.get("abstract_api_key", "")

    findings: dict[str, Any] = {"number": e164, "original": number}

    # Basic inference
    country = _detect_country(e164)
    region  = _detect_us_region(e164)
    ltype   = _line_type_heuristic(e164)

    t = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
    t.add_column("Field", style="bold #ff2d78", width=18)
    t.add_column("Value", style="cyan")
    t.add_row("E.164",       e164)
    t.add_row("Country",     country)
    if region:
        t.add_row("Region",  region)
    t.add_row("Line type",   ltype)
    console.print(t)
    findings.update({"country": country, "region": region, "line_type": ltype})

    # NumVerify
    if numverify_key:
        with console.status("[cyan]Querying NumVerify…"):
            nv = _numverify(e164, numverify_key)
        if nv.get("valid"):
            console.print(f"\n[bold]NumVerify:[/bold]")
            console.print(f"  Carrier:    {nv.get('carrier','?')}")
            console.print(f"  Line type:  {nv.get('line_type','?')}")
            console.print(f"  Location:   {nv.get('location','?')}")
            findings["numverify"] = nv

    # Abstract API
    if abstract_key:
        with console.status("[cyan]Querying Abstract Phone API…"):
            ab = _abstract_api(e164, abstract_key)
        if ab.get("valid"):
            console.print(f"\n[bold]Abstract API:[/bold]")
            console.print(f"  Carrier:  {ab.get('carrier',{}).get('name','?')}")
            console.print(f"  Type:     {ab.get('type','?')}")
            console.print(f"  Country:  {ab.get('country',{}).get('name','?')}")
            findings["abstract"] = ab

    # CNAM
    with console.status("[cyan]CNAM lookup…"):
        cnam = _opencnam(e164)
    if cnam.get("name"):
        console.print(f"\n[bold]Caller ID (CNAM):[/bold] [yellow]{cnam['name']}[/yellow]")
        findings["cnam"] = cnam.get("name")

    # Spam check
    with console.status("[cyan]Checking spam databases…"):
        rating = _check_should_i_answer(e164)
    if rating:
        try:
            r_float = float(rating)
            color = "#ff0000" if r_float < 2 else "#ffd700" if r_float < 3.5 else "#39ff14"
            console.print(f"\n[bold]Spam Rating:[/bold] [{color}]{rating}/5[/{color}]")
        except Exception:
            console.print(f"\n[bold]Spam Rating:[/bold] {rating}")
        findings["spam_rating"] = rating

    # No API key guidance
    if not numverify_key and not abstract_key:
        console.print("\n[dim]Tip: set numverify_api_key or abstract_api_key for carrier/line-type data[/dim]")
        console.print("[dim]     omega config set numverify_api_key KEY[/dim]")

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", e164)
    out = os.path.join(out_dir, f"phoneosint_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
