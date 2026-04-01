"""Typosquatting / lookalike domain detector — generate and probe permutations."""
import itertools
import socket
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

KEYBOARD_ADJACENT = {
    'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'erfcxs', 'e': 'wrds',
    'f': 'rtgvcd', 'g': 'tyhbvf', 'h': 'yunjbg', 'i': 'uojk', 'j': 'uiknh',
    'k': 'iolmj', 'l': 'opk', 'm': 'njk', 'n': 'bhjm', 'o': 'iklp',
    'p': 'ol', 'q': 'wa', 'r': 'etdf', 's': 'wedxza', 't': 'ryfge',
    'u': 'yihj', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tugh',
    'z': 'asx',
}

HOMOGLYPHS = {
    'a': ['à','á','â','ã','ä','å','α','а'],
    'e': ['è','é','ê','ë','е','ё'],
    'i': ['í','ì','î','ï','і'],
    'o': ['ó','ò','ô','õ','ö','ο','о'],
    'u': ['ú','ù','û','ü'],
    'c': ['ç','с'],
    'n': ['ñ','η'],
    'l': ['1', 'I'],
    '0': ['o', 'O'],
}

COMMON_TLDS = [".com", ".net", ".org", ".io", ".co", ".info", ".biz", ".us", ".xyz", ".online"]


def _parse_domain(domain: str) -> tuple:
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return parts[0], f".{parts[1]}"
    return domain, ".com"


def _typo_addition(name: str) -> list:
    """Add an extra character."""
    perms = []
    for i in range(len(name) + 1):
        for c in "abcdefghijklmnopqrstuvwxyz0123456789-":
            perms.append(name[:i] + c + name[i:])
    return perms


def _typo_deletion(name: str) -> list:
    return [name[:i] + name[i+1:] for i in range(len(name))]


def _typo_substitution(name: str) -> list:
    perms = []
    for i, ch in enumerate(name):
        for adj in KEYBOARD_ADJACENT.get(ch.lower(), ""):
            perms.append(name[:i] + adj + name[i+1:])
    return perms


def _typo_transposition(name: str) -> list:
    return [name[:i] + name[i+1] + name[i] + name[i+2:]
            for i in range(len(name) - 1)]


def _typo_tld_swap(name: str, tld: str) -> list:
    return [f"{name}{t}" for t in COMMON_TLDS if t != tld]


def _typo_homoglyph(name: str, tld: str) -> list:
    perms = []
    for i, ch in enumerate(name):
        for g in HOMOGLYPHS.get(ch.lower(), []):
            perms.append(name[:i] + g + name[i+1:] + tld)
    return perms


def _typo_hyphen(name: str, tld: str) -> list:
    perms = []
    for i in range(1, len(name)):
        perms.append(name[:i] + "-" + name[i:] + tld)
    perms.append(name.replace("-", "") + tld)
    return perms


def _typo_repetition(name: str) -> list:
    return [name[:i] + name[i] + name[i:] for i in range(len(name))]


def _typo_common_words(name: str, tld: str) -> list:
    affixes = ["my", "get", "the", "use", "app", "web", "online", "best",
               "official", "real", "login", "signin", "secure", "support"]
    variants = []
    for a in affixes:
        variants.append(f"{a}{name}{tld}")
        variants.append(f"{name}{a}{tld}")
        variants.append(f"{name}-{a}{tld}")
        variants.append(f"{a}-{name}{tld}")
    return variants


def _resolve(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def _check_http(domain: str) -> int:
    try:
        r = requests.head(f"http://{domain}", timeout=4, allow_redirects=True)
        return r.status_code
    except Exception:
        return 0


def generate_permutations(domain: str) -> list:
    name, tld = _parse_domain(domain)
    perms = set()

    for p in _typo_deletion(name):
        if len(p) >= 2:
            perms.add(p + tld)

    for p in _typo_substitution(name):
        perms.add(p + tld)

    for p in _typo_transposition(name):
        perms.add(p + tld)

    for p in _typo_repetition(name):
        perms.add(p + tld)

    perms.update(_typo_tld_swap(name, tld))
    perms.update(_typo_hyphen(name, tld))
    perms.update(_typo_common_words(name, tld))
    perms.update(_typo_homoglyph(name, tld))

    # Remove original
    perms.discard(domain)
    return sorted(perms)


def run(domain: str, probe: bool = True, limit: int = 200):
    """Generate typosquatting permutations and probe which ones are live."""
    console.print(Panel(
        f"[bold #ff2d78]🎭 Typosquatting Detector[/]\n[dim]Domain:[/] [cyan]{domain}[/]",
        border_style="#ff85b3",
    ))

    perms = generate_permutations(domain)
    perms = perms[:limit]
    console.print(f"[dim]  Generated {len(perms)} permutations[/]")

    if not probe:
        tbl = Table(title=f"Permutations ({len(perms)})", box=box.SIMPLE)
        tbl.add_column("Domain")
        for p in perms:
            tbl.add_row(p)
        console.print(tbl)
        return {"domain": domain, "permutations": perms, "live": []}

    console.print("[dim]  Probing DNS resolution...[/]")
    live = []
    for perm in perms:
        ip = _resolve(perm)
        if ip:
            status = _check_http(perm)
            live.append({"domain": perm, "ip": ip, "http_status": status})

    if not live:
        console.print(f"[green]✓[/] No registered lookalike domains found (checked {len(perms)})")
        return {"domain": domain, "permutations": perms, "live": []}

    tbl = Table(
        title=f"[bold red]⚠  Live Lookalike Domains ({len(live)})[/]",
        box=box.ROUNDED, border_style="red",
    )
    tbl.add_column("Domain", style="cyan")
    tbl.add_column("IP", style="yellow")
    tbl.add_column("HTTP", width=6)
    tbl.add_column("Risk")

    for d in live:
        status = d["http_status"]
        status_color = "green" if status in (200, 301, 302) else "yellow" if status else "dim"
        risk = "HIGH" if status in (200, 301, 302) else "MEDIUM" if status else "LOW"
        risk_color = "red" if risk == "HIGH" else "yellow" if risk == "MEDIUM" else "dim"
        tbl.add_row(
            d["domain"],
            d["ip"],
            f"[{status_color}]{status or '-'}[/]",
            f"[{risk_color}]{risk}[/]",
        )
    console.print(tbl)

    console.print(f"\n[bold]Total permutations:[/] {len(perms)}  "
                  f"[bold red]Live lookalikes:[/] {len(live)}")
    return {"domain": domain, "permutations": perms, "live": live}
