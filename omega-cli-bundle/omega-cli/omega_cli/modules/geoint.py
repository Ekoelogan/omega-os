"""omega geoint — Geo-intelligence: IP geolocation, EXIF GPS, timezone mapping."""
from __future__ import annotations
import ipaddress
import json
import re
from pathlib import Path
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

IP_GEO_API   = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
IPINFO_API   = "https://ipinfo.io/{ip}/json"
BULK_GEO_API = "http://ip-api.com/batch"


def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def _geoip(ip: str) -> dict:
    try:
        r = requests.get(IP_GEO_API.format(ip=ip), timeout=8)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        console.print(f"[yellow]GeoIP error:[/yellow] {exc}")
        return {}


def _display_geoip(data: dict) -> None:
    if data.get("status") != "success":
        console.print(f"[red]Lookup failed:[/red] {data.get('message','unknown')}")
        return
    tbl = Table(show_header=False, box=None, padding=(0, 2))
    tbl.add_column("Key",   style="bold #ff2d78")
    tbl.add_column("Value", style="white")
    tbl.add_row("IP",           data.get("query", "—"))
    tbl.add_row("Country",      data.get("country", "—"))
    tbl.add_row("Region",       data.get("regionName", "—"))
    tbl.add_row("City",         data.get("city", "—"))
    tbl.add_row("ZIP",          data.get("zip", "—"))
    lat = data.get("lat")
    lon = data.get("lon")
    if lat and lon:
        tbl.add_row("Coordinates",  f"{lat}, {lon}")
        tbl.add_row("Maps",         f"https://maps.google.com/?q={lat},{lon}")
    tbl.add_row("Timezone",     data.get("timezone", "—"))
    tbl.add_row("ISP",          data.get("isp", "—"))
    tbl.add_row("Org",          data.get("org", "—"))
    tbl.add_row("ASN",          data.get("as", "—"))
    console.print(tbl)


def _exif_gps(image_path: str) -> None:
    """Extract GPS coordinates from image EXIF data."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        console.print("[yellow]Pillow not installed.[/yellow] Install: [bold]pipx inject omega-cli Pillow[/bold]")
        return

    p = Path(image_path)
    if not p.exists():
        console.print(f"[red]File not found:[/red] {image_path}")
        return

    try:
        img  = Image.open(p)
        info = img._getexif()
        if not info:
            console.print("[yellow]No EXIF data found in image.[/yellow]")
            return

        exif = {TAGS.get(k, k): v for k, v in info.items()}
        gps_info_raw = exif.get("GPSInfo")
        if not gps_info_raw:
            console.print("[yellow]No GPS data in EXIF.[/yellow]")
            return

        gps = {GPSTAGS.get(k, k): v for k, v in gps_info_raw.items()}

        def dms_to_dd(dms, ref):
            d, m, s = dms
            dd = float(d) + float(m) / 60 + float(s) / 3600
            if ref in ("S", "W"):
                dd = -dd
            return dd

        lat = dms_to_dd(gps["GPSLatitude"],  gps.get("GPSLatitudeRef",  "N"))
        lon = dms_to_dd(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))

        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column("Key",   style="bold #ff2d78")
        tbl.add_column("Value", style="white")
        tbl.add_row("Image",       p.name)
        tbl.add_row("GPS Lat",     f"{lat:.6f}°")
        tbl.add_row("GPS Lon",     f"{lon:.6f}°")
        tbl.add_row("Coordinates", f"{lat:.6f}, {lon:.6f}")
        tbl.add_row("Maps",        f"https://maps.google.com/?q={lat:.6f},{lon:.6f}")
        alt = gps.get("GPSAltitude")
        if alt:
            tbl.add_row("Altitude", f"{float(alt):.1f}m")
        ts = gps.get("GPSTimeStamp")
        if ts:
            h, m, s = ts
            tbl.add_row("GPS Time (UTC)", f"{int(h):02d}:{int(m):02d}:{int(float(s)):02d}")
        console.print(tbl)

        # Also geolocate the coordinates
        console.print("\n[dim]Reverse geocoding…[/dim]")
        try:
            r = requests.get(
                f"https://nominatim.openstreetmap.org/reverse",
                params={"lat": lat, "lon": lon, "format": "json"},
                headers={"User-Agent": "omega-cli/0.8.0"},
                timeout=8,
            )
            r.raise_for_status()
            addr = r.json().get("display_name", "")
            if addr:
                console.print(f"[bold]Address:[/bold] {addr}")
        except Exception:
            pass

    except Exception as exc:
        console.print(f"[red]EXIF error:[/red] {exc}")


def run(target: str, image: str = "") -> None:
    console.print(Panel(
        f"[bold #ff2d78]🌍  Geo-Intelligence[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    if image:
        console.print(f"\n[bold]📸 EXIF GPS extraction:[/bold] {image}")
        _exif_gps(image)

    if _is_ip(target):
        console.print(f"\n[bold]📍 IP Geolocation:[/bold] {target}")
        data = _geoip(target)
        _display_geoip(data)
    else:
        # Try to resolve domain to IP first
        console.print(f"\n[dim]Resolving {target} to IP…[/dim]")
        try:
            import dns.resolver
            answers = dns.resolver.resolve(target, "A", lifetime=4)
            for rr in answers:
                ip = str(rr)
                console.print(f"  [dim]→[/dim] [cyan]{ip}[/cyan]")
                data = _geoip(ip)
                _display_geoip(data)
        except Exception as exc:
            console.print(f"[yellow]DNS resolve failed:[/yellow] {exc}")
