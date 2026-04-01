"""Email spoofing audit — SPF, DKIM, DMARC analysis."""
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

DKIM_SELECTORS = [
    "default", "google", "mail", "email", "dkim", "k1", "k2",
    "selector1", "selector2", "s1", "s2", "smtp", "mimecast",
    "proofpoint", "mailchimp", "sendgrid", "ses", "amazonses",
    "mandrill", "mailgun", "postmark", "zoho", "outlook",
]


def _txt_records(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=3)
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def _check_spf(domain: str) -> dict:
    records = [r for r in _txt_records(domain) if r.startswith("v=spf1")]
    if not records:
        return {"found": False, "record": None, "risk": "HIGH — No SPF record. Domain spoofable."}
    spf = records[0]
    risk = "OK"
    if "+all" in spf:
        risk = "CRITICAL — '+all' allows anyone to send as this domain"
    elif "?all" in spf:
        risk = "HIGH — '?all' neutral policy, still spoofable"
    elif "~all" in spf:
        risk = "MEDIUM — '~all' softfail, not enforced by all receivers"
    elif "-all" in spf:
        risk = "LOW — '-all' hard fail, good configuration"
    return {"found": True, "record": spf[:120], "risk": risk}


def _check_dmarc(domain: str) -> dict:
    records = _txt_records(f"_dmarc.{domain}")
    dmarc = next((r for r in records if r.startswith("v=DMARC1")), None)
    if not dmarc:
        return {"found": False, "record": None, "risk": "HIGH — No DMARC record. No policy enforcement."}
    policy = "none"
    for part in dmarc.split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part[2:]
    risk_map = {
        "none":       "HIGH — p=none only monitors, does not reject spoofed email",
        "quarantine": "MEDIUM — p=quarantine sends suspicious mail to spam",
        "reject":     "LOW — p=reject blocks spoofed email",
    }
    return {"found": True, "record": dmarc[:120], "policy": policy,
            "risk": risk_map.get(policy, f"UNKNOWN policy: {policy}")}


def _check_dkim(domain: str) -> dict:
    found = []
    for sel in DKIM_SELECTORS:
        records = _txt_records(f"{sel}._domainkey.{domain}")
        if any("v=DKIM1" in r or "k=rsa" in r for r in records):
            found.append(sel)
    return {"selectors_found": found}


def run(target: str):
    """Audit SPF, DKIM, and DMARC for email spoofing risk."""
    console.print(f"\n[bold cyan][ EMAIL SPOOF AUDIT ] {target}[/bold cyan]\n")

    spf   = _check_spf(target)
    dmarc = _check_dmarc(target)
    dkim  = _check_dkim(target)

    table = Table(show_header=True)
    table.add_column("Protocol", style="bold yellow")
    table.add_column("Status",   style="white")
    table.add_column("Record",   style="dim", max_width=60)
    table.add_column("Risk",     style="white")

    def risk_color(risk: str) -> str:
        if risk.startswith("CRITICAL"): return f"[bold red]{risk}[/bold red]"
        if risk.startswith("HIGH"):     return f"[red]{risk}[/red]"
        if risk.startswith("MEDIUM"):   return f"[yellow]{risk}[/yellow]"
        if risk.startswith("LOW"):      return f"[green]{risk}[/green]"
        return risk

    spf_status = "[green]✓ Found[/green]" if spf["found"] else "[red]✗ Missing[/red]"
    table.add_row("SPF", spf_status, spf.get("record") or "", risk_color(spf["risk"]))

    dmarc_status = "[green]✓ Found[/green]" if dmarc["found"] else "[red]✗ Missing[/red]"
    table.add_row("DMARC", dmarc_status, dmarc.get("record") or "", risk_color(dmarc["risk"]))

    dkim_found = dkim["selectors_found"]
    dkim_status = f"[green]✓ {len(dkim_found)} selector(s)[/green]" if dkim_found else "[red]✗ Not found[/red]"
    dkim_record = ", ".join(dkim_found) if dkim_found else f"Checked {len(DKIM_SELECTORS)} selectors"
    dkim_risk = "LOW — DKIM signing configured" if dkim_found else "MEDIUM — No DKIM selectors found (checked common selectors)"
    table.add_row("DKIM", dkim_status, dkim_record, risk_color(dkim_risk))

    console.print(table)

    # Spoofable verdict
    spoofable = not spf["found"] or "+all" in (spf.get("record") or "") or \
                not dmarc["found"] or dmarc.get("policy") == "none"
    if spoofable:
        console.print(Panel(
            "[bold red]⚠  DOMAIN IS LIKELY SPOOFABLE[/bold red]\n"
            "[dim]An attacker may be able to send email appearing to come from this domain.[/dim]",
            border_style="red"
        ))
    else:
        console.print(Panel("[bold green]✓  Email spoofing protection looks solid[/bold green]",
                            border_style="green"))

    return {"spf": spf, "dmarc": dmarc, "dkim": dkim}
