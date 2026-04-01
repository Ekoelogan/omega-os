"""Target-specific wordlist generator — builds custom wordlists from OSINT data."""
import re
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from pathlib import Path

console = Console()

STOP_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "her",
    "was", "one", "our", "out", "day", "get", "has", "him", "his", "how",
    "its", "may", "new", "now", "old", "see", "two", "way", "who", "did",
    "www", "com", "net", "org", "http", "https", "html", "css", "php",
    "asp", "jsp", "this", "that", "with", "from", "have", "will", "your",
    "more", "also", "into", "than", "then", "over", "when", "they",
}

LEET_MAP = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7'],
    'l': ['1'],
}

COMMON_SUFFIXES = [
    "2024", "2025", "2023", "1", "12", "123", "1234", "12345",
    "!", "@", "#", "!!", "123!", "2024!", "@123",
    "admin", "pass", "password", "pw", "login",
]

COMMON_PREFIXES = ["", "admin", "root", "user", "test", "guest"]


def _scrape_words(url: str) -> list:
    words = []
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(r.text, "lxml")
        # Remove scripts and styles
        for tag in soup(["script", "style", "nav", "footer"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
        raw = re.findall(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}", text)
        words = [w.lower() for w in raw if w.lower() not in STOP_WORDS and len(w) >= 4]
    except Exception:
        pass
    return words


def _get_employee_names(domain: str) -> list:
    """Extract potential employee names from LinkedIn-style searches (web scrape)."""
    names = []
    try:
        r = requests.get(
            f"https://www.google.com/search?q=site:linkedin.com+{domain}+employee",
            headers={"User-Agent": "Mozilla/5.0"}, timeout=10,
        )
        # Extract name patterns from results
        found = re.findall(r"([A-Z][a-z]+ [A-Z][a-z]+)", r.text)
        names = list(set(found))[:30]
    except Exception:
        pass
    return names


def _get_meta_words(domain: str) -> list:
    words = []
    for url in [f"https://{domain}", f"https://www.{domain}"]:
        try:
            r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
            soup = BeautifulSoup(r.text, "lxml")
            for tag in soup.find_all("meta"):
                content = tag.get("content", "")
                kw = tag.get("keywords", "")
                for text in [content, kw]:
                    words.extend(re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", text))
            title = soup.title.string if soup.title else ""
            words.extend(re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", title))
        except Exception:
            pass
    return [w.lower() for w in words if w.lower() not in STOP_WORDS and len(w) >= 4]


def _apply_rules(words: list) -> list:
    """Apply password mutation rules to expand wordlist."""
    mutations = set(words)

    for word in words[:200]:  # Limit base for explosion control
        # Capitalize
        mutations.add(word.capitalize())
        mutations.add(word.upper())

        # Common suffixes
        for sfx in COMMON_SUFFIXES:
            mutations.add(f"{word}{sfx}")
            mutations.add(f"{word.capitalize()}{sfx}")

        # Leet speak (single substitution)
        for i, ch in enumerate(word):
            for leet in LEET_MAP.get(ch, []):
                mutations.add(word[:i] + leet + word[i+1:])

    return sorted(mutations)


def _gen_email_formats(names: list, domain: str) -> list:
    """Generate common corporate email formats from names."""
    emails = []
    for name in names[:20]:
        parts = name.lower().split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            for fmt in [
                f"{first}.{last}@{domain}",
                f"{first}{last}@{domain}",
                f"{first[0]}{last}@{domain}",
                f"{first}.{last[0]}@{domain}",
                f"{last}.{first}@{domain}",
                f"{first}@{domain}",
            ]:
                emails.append(fmt)
    return emails


def run(domain: str, output: str = "", rules: bool = False, emails: bool = False):
    """Generate a target-specific wordlist from OSINT data."""
    console.print(Panel(
        f"[bold #ff2d78]📝 Wordlist Generator[/]\n[dim]Domain:[/] [cyan]{domain}[/]",
        border_style="#ff85b3",
    ))

    all_words = set()
    sources_used = {}

    # Domain parts
    parts = domain.replace("-", " ").replace(".", " ").split()
    all_words.update(p.lower() for p in parts if len(p) >= 3)
    sources_used["domain_parts"] = len(parts)

    # Web scrape
    console.print("[dim]  Scraping web content...[/]")
    pages = [
        f"https://{domain}", f"https://www.{domain}",
        f"https://{domain}/about", f"https://{domain}/team",
        f"https://{domain}/contact",
    ]
    web_words = []
    for url in pages:
        web_words.extend(_scrape_words(url))
    # Frequency-sort and take top words
    from collections import Counter
    freq = Counter(web_words)
    top_web = [w for w, _ in freq.most_common(150) if len(w) >= 4]
    all_words.update(top_web)
    sources_used["web_scrape"] = len(top_web)

    # Meta keywords
    console.print("[dim]  Extracting meta keywords...[/]")
    meta = _get_meta_words(domain)
    from collections import Counter
    meta_top = [w for w, _ in Counter(meta).most_common(50)]
    all_words.update(meta_top)
    sources_used["meta_keywords"] = len(meta_top)

    base_words = sorted(all_words)

    # Employee names → email formats
    name_list = []
    email_list = []
    if emails:
        console.print("[dim]  Extracting employee names for email generation...[/]")
        name_list = _get_employee_names(domain)
        email_list = _gen_email_formats(name_list, domain)
        sources_used["employee_names"] = len(name_list)
        sources_used["email_formats"] = len(email_list)

    # Apply mutation rules
    final_words = base_words
    if rules:
        console.print("[dim]  Applying password mutation rules...[/]")
        final_words = _apply_rules(base_words)
        sources_used["after_rules"] = len(final_words)

    # Display sample
    tbl = Table(title=f"Sample Words (top 30 of {len(final_words)})", box=box.SIMPLE)
    tbl.add_column("Word", style="cyan")
    tbl.add_column("Word", style="cyan")
    tbl.add_column("Word", style="cyan")
    sample = final_words[:90]
    for i in range(0, min(30, len(sample)), 1):
        row = [sample[i*3] if i*3 < len(sample) else "",
               sample[i*3+1] if i*3+1 < len(sample) else "",
               sample[i*3+2] if i*3+2 < len(sample) else ""]
        tbl.add_row(*row)
    console.print(tbl)

    if email_list:
        etbl = Table(title=f"Generated Email Formats ({len(email_list)})", box=box.SIMPLE)
        etbl.add_column("Email", style="cyan")
        for e in email_list[:20]:
            etbl.add_row(e)
        console.print(etbl)

    # Save
    output_dir = Path.home() / "omega-reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    safe = domain.replace(".", "_")

    wordlist_path = output or str(output_dir / f"wordlist_{safe}.txt")
    Path(wordlist_path).write_text("\n".join(final_words))
    console.print(f"\n[green]✓[/] Wordlist saved: [cyan]{wordlist_path}[/]  ({len(final_words)} words)")

    if email_list:
        email_path = str(output_dir / f"emails_{safe}.txt")
        Path(email_path).write_text("\n".join(email_list))
        console.print(f"[green]✓[/] Email list saved: [cyan]{email_path}[/]  ({len(email_list)} addresses)")

    console.print("\n[bold]Sources:[/] " + "  ".join(f"[cyan]{k}[/]:[yellow]{v}[/]" for k, v in sources_used.items()))

    return {"domain": domain, "words": final_words, "emails": email_list, "path": wordlist_path}
