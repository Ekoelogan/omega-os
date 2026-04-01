"""CORS misconfiguration tester — wildcard, reflected origin, credentials bypass."""
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{target}.evil.com",
    "https://evil{target}",
    "https://{tld_stripped}.evil.com",
    "http://{target}",           # HTTP downgrade
    "https://evil.com.{target}", # suffix bypass
    "https://{target}%60.evil.com",  # encoded backtick
    "https://{target}_.evil.com",
]

ENDPOINTS = [
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/rest",
    "/v1",
    "/user",
    "/users",
    "/profile",
    "/account",
    "/admin",
    "/health",
    "/status",
    "/me",
]


def _make_origins(target: str) -> list:
    domain = target.rstrip("/").replace("https://", "").replace("http://", "").split("/")[0]
    tld_stripped = ".".join(domain.split(".")[:-1]) if "." in domain else domain
    origins = []
    for tpl in TEST_ORIGINS:
        o = tpl.replace("{target}", domain).replace("{tld_stripped}", tld_stripped)
        origins.append(o)
    return origins


def _test_cors(url: str, origin: str, session: requests.Session) -> dict:
    result = {"url": url, "origin": origin, "vulnerable": False, "details": []}
    try:
        r = session.get(
            url, headers={"Origin": origin},
            timeout=8, allow_redirects=True,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            result["vulnerable"] = True
            result["severity"] = "MEDIUM"
            result["details"].append(f"ACAO: * (wildcard)")

        elif acao == origin:
            if acac == "true":
                result["vulnerable"] = True
                result["severity"] = "CRITICAL"
                result["details"].append(f"ACAO reflects origin + ACAC: true → credentials theft possible")
            else:
                result["vulnerable"] = True
                result["severity"] = "HIGH"
                result["details"].append(f"ACAO reflects origin: {origin}")

        elif origin == "null" and acao == "null":
            result["vulnerable"] = True
            result["severity"] = "HIGH"
            result["details"].append("ACAO: null — sandbox iframe bypass")

        result["status"] = r.status_code
        result["acao"] = acao
        result["acac"] = acac
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


def run(target: str, endpoints: bool = False):
    """Test a target for CORS misconfigurations."""
    if not target.startswith("http"):
        target = f"https://{target}"

    console.print(Panel(
        f"[bold #ff2d78]🔓 CORS Misconfiguration Tester[/]\n[dim]Target:[/] [cyan]{target}[/]",
        border_style="#ff85b3",
    ))

    origins = _make_origins(target)
    urls = [target]
    if endpoints:
        base = target.rstrip("/")
        urls += [f"{base}{ep}" for ep in ENDPOINTS]

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    vulns = []
    tested = 0

    for url in urls:
        for origin in origins:
            result = _test_cors(url, origin, session)
            tested += 1
            if result.get("vulnerable"):
                vulns.append(result)

    if not vulns:
        console.print(f"[green]✓[/] No CORS misconfigurations found  ({tested} tests across {len(urls)} URLs)")
        return {"target": target, "vulnerable": False, "findings": []}

    tbl = Table(
        title=f"[bold red]⚠  CORS Vulnerabilities Found ({len(vulns)})[/]",
        box=box.ROUNDED, border_style="red", show_lines=True,
    )
    tbl.add_column("Severity", width=10)
    tbl.add_column("URL", style="cyan")
    tbl.add_column("Origin Tested", style="yellow")
    tbl.add_column("Detail")

    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(sev, "white")
        tbl.add_row(
            f"[{color}]{sev}[/]",
            v["url"][:60],
            v["origin"][:50],
            "\n".join(v.get("details", []))[:100],
        )
    console.print(tbl)

    # PoC
    critical = [v for v in vulns if v.get("severity") == "CRITICAL"]
    if critical:
        c = critical[0]
        console.print(Panel(
            f"[bold red]PoC — Credentials Theft[/]\n\n"
            f'[dim]fetch("[cyan]{c["url"]}[/dim]", {{\n'
            f'  credentials: "include",\n'
            f'  headers: {{ "Origin": "{c["origin"]}" }}\n'
            f'}})[/dim]\n\n'
            f'[yellow]→ Server responds with ACAO: {c["origin"]}  +  ACAC: true[/]',
            border_style="red",
        ))

    return {"target": target, "vulnerable": True, "findings": vulns}
