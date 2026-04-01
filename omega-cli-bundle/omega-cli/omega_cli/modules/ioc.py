"""omega ioc — Extract Indicators of Compromise from any text, file, or URL."""
from __future__ import annotations
import re
import sys
from pathlib import Path
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ── Regex patterns ────────────────────────────────────────────────────────────
PATTERNS: dict[str, re.Pattern] = {
    "IPv4":         re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "IPv6":         re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ),
    "Domain":       re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|gov|edu|uk|de|ru|cn|onion|xyz|info|biz|co|me|app|dev)\b",
        re.I,
    ),
    "URL":          re.compile(r"https?://[^\s\"'<>]{6,}", re.I),
    "Email":        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "MD5":          re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "SHA1":         re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "SHA256":       re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "CVE":          re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    "BTC":          re.compile(r"\b(1|3|bc1)[A-Za-z0-9]{25,62}\b"),
    "ETH":          re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
    "Onion":        re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.I),
    "Registry Key": re.compile(r"\b(HKEY_[A-Z_]+(?:\\[^\s\"'\\]+)+)", re.I),
    "File Path":    re.compile(r"\b[A-Za-z]:\\(?:[^\\\s\"'<>/:*?|]+\\)*[^\\\s\"'<>/:*?|]*"),
}

PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^0\.0\.0\.0$"),
]


def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)


def _fetch_text(source: str) -> str:
    """Fetch text from a URL, file path, or stdin dash."""
    if source == "-":
        return sys.stdin.read()
    p = Path(source)
    if p.exists():
        return p.read_text(errors="replace")
    if source.startswith("http://") or source.startswith("https://"):
        try:
            r = requests.get(source, timeout=12,
                             headers={"User-Agent": "omega-cli/0.8.0"})
            r.raise_for_status()
            return r.text
        except Exception as exc:
            console.print(f"[red]Failed to fetch URL:[/red] {exc}")
            return ""
    # Treat as raw text input
    return source


def run(source: str, no_private: bool = True, defang: bool = False,
        types: str = "") -> dict[str, list[str]]:
    """Extract IOCs from text/file/URL and display a table."""
    console.print(Panel(
        f"[bold #ff2d78]🔍  IOC Extractor[/bold #ff2d78]  →  [cyan]{source[:60]}[/cyan]",
        expand=False,
    ))

    text = _fetch_text(source)
    if not text:
        console.print("[yellow]No input text found.[/yellow]")
        return {}

    # Defang before parsing (e.g., 1[.]2[.]3[.]4 → 1.2.3.4)
    text = text.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http")

    filter_types = {t.strip() for t in types.split(",")} if types else set()

    found: dict[str, list[str]] = {}
    for ioc_type, pattern in PATTERNS.items():
        if filter_types and ioc_type.lower() not in {t.lower() for t in filter_types}:
            continue
        matches = list(dict.fromkeys(pattern.findall(text)))
        if ioc_type == "IPv4" and no_private:
            matches = [m for m in matches if not _is_private_ip(m)]
        if matches:
            found[ioc_type] = matches

    if not found:
        console.print("[yellow]No IOCs found.[/yellow]")
        return {}

    # Summary table
    summary = Table(title="IOC Summary", show_lines=True)
    summary.add_column("Type",  style="bold #ff2d78")
    summary.add_column("Count", justify="right")
    summary.add_column("Samples", style="cyan", max_width=60)
    for ioc_type, items in sorted(found.items()):
        samples = "  ".join(items[:3]) + ("  …" if len(items) > 3 else "")
        if defang:
            samples = samples.replace(".", "[.]").replace("http", "hxxp")
        summary.add_row(ioc_type, str(len(items)), samples)
    console.print(summary)

    # Detail tables for each type
    for ioc_type, items in sorted(found.items()):
        if len(items) <= 3:
            continue
        tbl = Table(title=f"All {ioc_type}", show_lines=False)
        tbl.add_column(ioc_type, style="cyan")
        for item in items:
            disp = item.replace(".", "[.]").replace("http", "hxxp") if defang else item
            tbl.add_row(disp)
        console.print(tbl)

    total = sum(len(v) for v in found.values())
    console.print(f"\n[bold]Total:[/bold] {total} IOCs across {len(found)} types extracted.")
    return found
