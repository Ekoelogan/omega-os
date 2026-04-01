"""omega imgosint — Image OSINT: EXIF metadata extraction, GPS coordinates,
reverse image search links, embedded secrets scan, steganography hints."""
from __future__ import annotations
import json, os, re, struct, datetime, io
from typing import Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# EXIF tag IDs we care about
EXIF_TAGS = {
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x0213: "YCbCrPositioning",
    0x8769: "ExifIFD",
    0x8825: "GPSIFD",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9286: "UserComment",
    0xA420: "ImageUniqueID",
    0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber",
    0xA432: "LensSpecification",
    0xA434: "LensModel",
}

GPS_TAGS = {
    0: "GPSVersionID",
    1: "GPSLatitudeRef",
    2: "GPSLatitude",
    3: "GPSLongitudeRef",
    4: "GPSLongitude",
    5: "GPSAltitudeRef",
    6: "GPSAltitude",
    7: "GPSTimeStamp",
    12: "GPSSpeedRef",
    13: "GPSSpeed",
    16: "GPSImgDirectionRef",
    17: "GPSImgDirection",
    29: "GPSDateStamp",
}


def _rational_to_float(data: bytes, offset: int, byte_order: str) -> float:
    fmt = ">II" if byte_order == "big" else "<II"
    num, den = struct.unpack_from(fmt, data, offset)
    return num / den if den else 0.0


def _read_ifd(data: bytes, offset: int, byte_order: str, tag_map: dict) -> dict:
    """Read IFD entries."""
    result = {}
    endian = ">" if byte_order == "big" else "<"
    try:
        count = struct.unpack_from(f"{endian}H", data, offset)[0]
        offset += 2
        for _ in range(count):
            tag_id, type_id, n_vals = struct.unpack_from(f"{endian}HHI", data, offset)
            val_offset = offset + 8
            tag_name = tag_map.get(tag_id, f"0x{tag_id:04X}")
            try:
                if type_id == 2:  # ASCII
                    if n_vals <= 4:
                        raw = data[val_offset:val_offset + n_vals]
                    else:
                        ptr = struct.unpack_from(f"{endian}I", data, val_offset)[0]
                        raw = data[ptr:ptr + n_vals]
                    result[tag_name] = raw.decode("ascii", errors="ignore").strip("\x00")
                elif type_id == 3:  # SHORT
                    val = struct.unpack_from(f"{endian}H", data, val_offset)[0]
                    result[tag_name] = val
                elif type_id == 4:  # LONG
                    val = struct.unpack_from(f"{endian}I", data, val_offset)[0]
                    result[tag_name] = val
                elif type_id == 5:  # RATIONAL
                    if n_vals <= 1:
                        ptr = struct.unpack_from(f"{endian}I", data, val_offset)[0]
                        result[tag_name] = _rational_to_float(data, ptr, byte_order)
                    else:
                        ptr = struct.unpack_from(f"{endian}I", data, val_offset)[0]
                        vals = [_rational_to_float(data, ptr + i*8, byte_order) for i in range(min(n_vals, 3))]
                        result[tag_name] = vals
            except Exception:
                pass
            offset += 12
    except Exception:
        pass
    return result


def _parse_exif_jpeg(data: bytes) -> dict:
    """Parse EXIF from JPEG bytes without Pillow."""
    result = {}
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        return result

    i = 2
    while i < len(data) - 1:
        if data[i] != 0xff:
            break
        marker = data[i+1]
        if marker in (0xd8, 0xd9):
            i += 2
            continue
        if i + 4 > len(data):
            break
        length = struct.unpack_from(">H", data, i+2)[0]
        segment = data[i+2:i+2+length]

        if marker == 0xe1 and segment[2:6] == b"Exif":
            tiff = segment[8:]
            if tiff[:2] == b"II":
                byte_order = "little"
                endian = "<"
            elif tiff[:2] == b"MM":
                byte_order = "big"
                endian = ">"
            else:
                i += 2 + length
                continue
            ifd0_offset = struct.unpack_from(f"{endian}I", tiff, 4)[0]
            ifd0 = _read_ifd(tiff, ifd0_offset, byte_order, EXIF_TAGS)
            result.update(ifd0)

            # GPS IFD
            if "GPSIFD" in ifd0:
                gps_data = _read_ifd(tiff, ifd0["GPSIFD"], byte_order, GPS_TAGS)
                result["GPS"] = gps_data

        i += 2 + length
    return result


def _exif_gps_to_decimal(exif: dict) -> tuple[float | None, float | None]:
    gps = exif.get("GPS", {})
    lat_vals = gps.get("GPSLatitude")
    lon_vals = gps.get("GPSLongitude")
    lat_ref  = gps.get("GPSLatitudeRef", "N")
    lon_ref  = gps.get("GPSLongitudeRef", "E")

    if not lat_vals or not lon_vals:
        return None, None

    def dms_to_dd(vals, ref):
        if isinstance(vals, list) and len(vals) >= 3:
            dd = vals[0] + vals[1]/60 + vals[2]/3600
        elif isinstance(vals, (int, float)):
            dd = float(vals)
        else:
            return None
        if ref in ("S", "W"):
            dd = -dd
        return round(dd, 7)

    lat = dms_to_dd(lat_vals, lat_ref)
    lon = dms_to_dd(lon_vals, lon_ref)
    return lat, lon


def _try_pillow_exif(path: str) -> dict:
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        img = Image.open(path)
        raw = img._getexif() or {}
        result = {}
        for tag_id, val in raw.items():
            tag = TAGS.get(tag_id, str(tag_id))
            if tag == "GPSInfo" and isinstance(val, dict):
                gps = {GPSTAGS.get(k, k): v for k, v in val.items()}
                result["GPS_Pillow"] = gps
            else:
                if isinstance(val, bytes):
                    val = val.decode("utf-8", errors="ignore")
                result[tag] = str(val)[:120]
        return result
    except Exception:
        return {}


def _reverse_search_urls(filename: str) -> list[dict]:
    """Generate reverse image search URLs."""
    enc_name = filename.replace(" ", "%20")
    return [
        {"engine": "Google Images",  "url": f"https://lens.google.com/uploadbyurl?url="},
        {"engine": "TinEye",         "url": "https://tineye.com/search/"},
        {"engine": "Bing Visual",    "url": "https://www.bing.com/visualsearch"},
        {"engine": "Yandex Images",  "url": "https://yandex.com/images/"},
    ]


def _scan_for_secrets(data: bytes) -> list[str]:
    """Scan raw image bytes for embedded secrets/strings."""
    secrets = []
    text = data.decode("latin-1", errors="ignore")
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"[a-zA-Z0-9_-]{40}", "Possible API token (40 chars)"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub token"),
        (r"-----BEGIN [A-Z ]+PRIVATE KEY-----", "Private key"),
        (r"password[=:]\s*\S+", "Password string"),
    ]
    for pat, label in patterns:
        matches = re.findall(pat, text, re.I)
        if matches:
            secrets.append(f"{label}: {matches[0][:40]}")
    return secrets[:5]


def _steg_hints(data: bytes, ext: str) -> list[str]:
    hints = []
    if ext in (".jpg", ".jpeg"):
        # Check for appended data after JPEG EOI
        eoi = data.rfind(b"\xff\xd9")
        if eoi != -1 and eoi < len(data) - 2:
            extra = len(data) - eoi - 2
            hints.append(f"{extra} bytes appended after JPEG EOI marker — possible steganography")
    # Check for large file size vs dimensions ratio
    size_kb = len(data) / 1024
    if size_kb > 500 and ext in (".png", ".bmp"):
        hints.append(f"Large file size ({size_kb:.0f}KB) for format — possible data hiding")
    return hints


def run(image_path: str, show_raw: bool = False):
    if not os.path.exists(image_path):
        console.print(f"[red]File not found: {image_path}[/red]")
        return

    fname = os.path.basename(image_path)
    ext   = os.path.splitext(fname)[1].lower()
    size  = os.path.getsize(image_path)

    console.print(Panel(
        f"[bold #ff2d78]🖼  Image OSINT[/bold #ff2d78] — [cyan]{fname}[/cyan]",
        box=box.ROUNDED
    ))

    with open(image_path, "rb") as f:
        raw = f.read()

    findings: dict[str, Any] = {
        "file": image_path,
        "size_bytes": size,
        "extension": ext,
    }

    # EXIF extraction
    exif: dict = {}
    if ext in (".jpg", ".jpeg"):
        exif = _parse_exif_jpeg(raw)
        if not exif:
            exif = _try_pillow_exif(image_path)
    else:
        exif = _try_pillow_exif(image_path)

    findings["exif"] = exif

    # Display EXIF
    console.print(f"\n[bold]File:[/bold] {fname}  [dim]({size:,} bytes, {ext})[/dim]")

    interesting_keys = ["Make", "Model", "DateTime", "DateTimeOriginal", "Artist",
                        "CameraOwnerName", "BodySerialNumber", "LensModel",
                        "Software", "ImageDescription", "Copyright", "UserComment"]
    found_meta = {k: v for k, v in exif.items() if k in interesting_keys and v}

    if found_meta:
        console.print("\n[bold]EXIF Metadata:[/bold]")
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        t.add_column("Field", style="bold #ff2d78", width=22)
        t.add_column("Value", style="cyan")
        for k, v in found_meta.items():
            t.add_row(k, str(v)[:80])
        console.print(t)
    else:
        console.print("[dim]No identifying EXIF metadata found[/dim]")

    # GPS
    lat, lon = _exif_gps_to_decimal(exif)
    if lat is not None and lon is not None:
        console.print(f"\n[bold red]📍 GPS Coordinates Found![/bold red]")
        console.print(f"  Latitude:  [yellow]{lat}[/yellow]")
        console.print(f"  Longitude: [yellow]{lon}[/yellow]")
        console.print(f"  Maps:      [cyan]https://maps.google.com/?q={lat},{lon}[/cyan]")
        console.print(f"  OSM:       [cyan]https://www.openstreetmap.org/?mlat={lat}&mlon={lon}[/cyan]")
        findings["gps"] = {"lat": lat, "lon": lon,
                            "google_maps": f"https://maps.google.com/?q={lat},{lon}"}
    else:
        console.print("[dim]No GPS data in EXIF[/dim]")

    # Reverse image search links
    console.print("\n[bold]Reverse Image Search:[/bold]")
    for eng in _reverse_search_urls(fname):
        console.print(f"  [cyan]•[/cyan] {eng['engine']}: {eng['url']}")

    # Secret scan
    secrets = _scan_for_secrets(raw)
    if secrets:
        console.print(f"\n[bold red]⚠  Embedded strings found:[/bold red]")
        for s in secrets:
            console.print(f"  [red]•[/red] {s}")
        findings["embedded_secrets"] = secrets

    # Steganography hints
    steg = _steg_hints(raw, ext)
    if steg:
        console.print(f"\n[bold yellow]⚠  Steganography hints:[/bold yellow]")
        for h in steg:
            console.print(f"  [yellow]•[/yellow] {h}")
        findings["steg_hints"] = steg

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.]", "_", fname)
    out = os.path.join(out_dir, f"imgosint_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
