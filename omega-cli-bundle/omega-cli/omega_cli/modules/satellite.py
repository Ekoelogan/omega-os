"""omega satellite — Aircraft (ADS-B), vessel (AIS), amateur radio, and space asset OSINT."""
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


def _adsb_aircraft(query: str) -> dict[str, Any]:
    """Query OpenSky Network for live/recent ADS-B data."""
    result: dict[str, Any] = {}
    # ICAO hex lookup
    icao = query.upper() if re.match(r'^[0-9A-Fa-f]{6}$', query) else None
    callsign = query.upper().strip() if not icao else None

    try:
        if icao:
            url = f"https://opensky-network.org/api/states/all?icao24={icao.lower()}"
        else:
            url = "https://opensky-network.org/api/states/all"
        r = httpx.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            states = data.get("states", []) or []
            if callsign:
                states = [s for s in states if s[1] and s[1].strip().upper() == callsign]
            aircraft = []
            for s in states[:20]:
                ac = {
                    "icao24":    s[0],
                    "callsign":  (s[1] or "").strip(),
                    "origin_country": s[2],
                    "longitude": s[5],
                    "latitude":  s[6],
                    "altitude_m": s[7],
                    "velocity_ms": s[9],
                    "heading":   s[10],
                    "on_ground": s[8],
                    "squawk":    s[14],
                }
                aircraft.append(ac)
            result["aircraft"] = aircraft
            result["total"] = len(states)
    except Exception as e:
        result["error"] = str(e)

    # Also try adsbexchange public API
    if icao and not result.get("aircraft"):
        try:
            r2 = httpx.get(
                f"https://api.adsbexchange.com/api/aircraft/icao/{icao.lower()}/",
                headers={"api-auth": "public", "User-Agent": "omega-cli"},
                timeout=TIMEOUT,
            )
            if r2.status_code == 200:
                ac_list = r2.json().get("ac", [])
                result["aircraft"] = ac_list[:10]
        except Exception:
            pass

    return result


def _ais_vessel(mmsi_or_name: str) -> dict[str, Any]:
    """Query VesselFinder / MarineTraffic public data."""
    result: dict[str, Any] = {}
    # Try VesselFinder public search
    try:
        r = httpx.get(
            "https://www.vesselfinder.com/api/pub/vesselsonmap",
            params={"bbox": "-180,-90,180,90", "zoom": 1, "mmsi": mmsi_or_name},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            result["raw"] = r.json()
    except Exception:
        pass

    # MarineTraffic vessel details
    try:
        r2 = httpx.get(
            "https://www.marinetraffic.com/en/ais/details/ships/",
            params={"mmsi": mmsi_or_name},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
            follow_redirects=True,
        )
        if r2.status_code == 200:
            body = r2.text
            name_m = re.search(r'"name":\s*"([^"]+)"', body)
            flag_m = re.search(r'"flag":\s*"([^"]+)"', body)
            type_m = re.search(r'"type_name":\s*"([^"]+)"', body)
            if name_m:
                result["vessel"] = {
                    "name": name_m.group(1),
                    "flag": flag_m.group(1) if flag_m else "?",
                    "type": type_m.group(1) if type_m else "?",
                    "mmsi": mmsi_or_name,
                }
    except Exception:
        pass

    return result


def _callsign_lookup(callsign: str) -> dict[str, Any]:
    """Amateur radio callsign lookup via QRZ / HamQTH / FCC."""
    result: dict[str, Any] = {"callsign": callsign}

    # FCC ULS lookup
    try:
        r = httpx.get(
            "https://data.fcc.gov/api/license-view/basicSearch/getLicenses",
            params={"searchValue": callsign, "format": "json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            licenses = data.get("Licenses", {}).get("License", [])
            if isinstance(licenses, dict):
                licenses = [licenses]
            result["fcc_licenses"] = [
                {
                    "callsign": lic.get("callSign"),
                    "name":     lic.get("licenseeName"),
                    "status":   lic.get("statusDesc"),
                    "service":  lic.get("serviceDesc"),
                    "state":    lic.get("licAddrState"),
                    "expires":  lic.get("expiredDate"),
                    "frn":      lic.get("frn"),
                }
                for lic in licenses[:5]
            ]
    except Exception:
        pass

    # HamQTH XML (no key needed for basic info)
    try:
        r2 = httpx.get(
            f"https://www.hamqth.com/xml.php",
            params={"callsign": callsign, "u": "omega", "p": "omega"},
            timeout=TIMEOUT,
        )
        if r2.status_code == 200:
            body = r2.text
            nick = re.search(r'<nick>([^<]+)</nick>', body)
            qth = re.search(r'<qth>([^<]+)</qth>', body)
            country = re.search(r'<country>([^<]+)</country>', body)
            email = re.search(r'<email>([^<]+)</email>', body)
            if nick:
                result["hamqth"] = {
                    "nickname": nick.group(1),
                    "qth": qth.group(1) if qth else "?",
                    "country": country.group(1) if country else "?",
                    "email": email.group(1) if email else None,
                }
    except Exception:
        pass

    return result


def _satellite_tle(sat_name: str) -> dict[str, Any]:
    """Fetch TLE data from Celestrak for a satellite."""
    result: dict[str, Any] = {"satellite": sat_name}
    try:
        r = httpx.get(
            "https://celestrak.org/SOCRATES/query.php",
            params={"NAME": sat_name, "FORMAT": "json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200 and r.text.strip():
            result["tle_raw"] = r.text[:500]
    except Exception:
        pass

    # CelesTrak catalog search
    try:
        r2 = httpx.get(
            "https://celestrak.org/SATCAT/records.php",
            params={"NAME": sat_name, "FORMAT": "json"},
            timeout=TIMEOUT,
        )
        if r2.status_code == 200:
            cats = r2.json()
            if cats:
                result["catalog"] = cats[:5]
    except Exception:
        pass

    return result


def _classify_query(query: str) -> str:
    if re.match(r'^\d{7,9}$', query):
        return "vessel_mmsi"
    if re.match(r'^[0-9A-Fa-f]{6}$', query):
        return "aircraft_icao"
    if re.match(r'^[A-Z]{1,2}[0-9][A-Z]{2,3}$', query.upper()):
        return "callsign"
    if re.match(r'^[A-Z]{3}\d{1,4}$', query.upper()):
        return "aircraft_callsign"
    return "search"


def run(target: str, mode: str = "auto"):
    console.print(Panel(
        f"[bold #ff2d78]🛰  Satellite & Radio OSINT[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    findings: dict[str, Any] = {"target": target}

    qtype = mode if mode != "auto" else _classify_query(target)
    findings["detected_type"] = qtype
    console.print(f"[dim]Detected query type: [cyan]{qtype}[/cyan][/dim]\n")

    if qtype in ("aircraft_icao", "aircraft_callsign"):
        with console.status("[cyan]Querying ADS-B feeds (OpenSky Network)…"):
            adsb = _adsb_aircraft(target)
        findings["adsb"] = adsb
        aircraft = adsb.get("aircraft", [])
        if aircraft:
            t = Table("ICAO24", "Callsign", "Country", "Lat", "Lon", "Alt (m)", "Speed (m/s)", "On Ground",
                      title=f"[bold green]✈  {len(aircraft)} Aircraft[/bold green]",
                      box=box.SIMPLE_HEAD, header_style="bold green")
            for ac in aircraft:
                t.add_row(
                    ac.get("icao24", "?"),
                    ac.get("callsign", "?"),
                    ac.get("origin_country", "?"),
                    str(ac.get("latitude") or "?"),
                    str(ac.get("longitude") or "?"),
                    str(ac.get("altitude_m") or "?"),
                    str(ac.get("velocity_ms") or "?"),
                    "Yes" if ac.get("on_ground") else "No",
                )
            console.print(t)
        else:
            console.print("[yellow]No live ADS-B data for this aircraft.[/yellow]")

    elif qtype == "vessel_mmsi":
        with console.status("[cyan]Querying AIS vessel data…"):
            ais = _ais_vessel(target)
        findings["ais"] = ais
        if ais.get("vessel"):
            v = ais["vessel"]
            console.print(f"[bold]Vessel:[/bold] [cyan]{v.get('name')}[/cyan]")
            console.print(f"  Flag: {v.get('flag')}  Type: {v.get('type')}  MMSI: {v.get('mmsi')}")
        else:
            console.print("[yellow]No AIS vessel data found for this MMSI.[/yellow]")

    elif qtype == "callsign":
        with console.status("[cyan]Looking up amateur radio callsign…"):
            cs = _callsign_lookup(target)
        findings["callsign"] = cs

        licenses = cs.get("fcc_licenses", [])
        if licenses:
            t2 = Table("Callsign", "Name", "Service", "State", "Status", "Expires",
                       title="[bold cyan]📻  FCC License Records[/bold cyan]",
                       box=box.SIMPLE_HEAD, header_style="bold cyan")
            for lic in licenses:
                t2.add_row(
                    lic.get("callsign", "?"),
                    lic.get("name", "?"),
                    lic.get("service", "?"),
                    lic.get("state", "?"),
                    lic.get("status", "?"),
                    lic.get("expires", "?"),
                )
            console.print(t2)
        else:
            console.print("[yellow]No FCC license records found.[/yellow]")

        if cs.get("hamqth"):
            h = cs["hamqth"]
            console.print(f"\n[bold]HamQTH:[/bold] {h.get('nickname')} — {h.get('qth')}, {h.get('country')}")
            if h.get("email"):
                console.print(f"  Email: [cyan]{h['email']}[/cyan]")

    else:
        # Generic search — try aircraft callsign
        with console.status("[cyan]Searching ADS-B by callsign…"):
            adsb = _adsb_aircraft(target)
        findings["adsb"] = adsb
        aircraft = adsb.get("aircraft", [])
        if aircraft:
            console.print(f"[green]Found {len(aircraft)} aircraft matching callsign.[/green]")

        # Also try as satellite
        with console.status("[cyan]Searching satellite catalog…"):
            sat = _satellite_tle(target)
        findings["satellite"] = sat
        if sat.get("catalog"):
            console.print(f"\n[bold]Satellite catalog:[/bold]")
            for s in sat["catalog"][:3]:
                console.print(f"  [cyan]{s}[/cyan]")

    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"satellite_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
