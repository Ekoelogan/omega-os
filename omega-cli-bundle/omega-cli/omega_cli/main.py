"""omega-cli: OSINT and passive recon toolkit — main entry point."""
import click
from rich.console import Console

console = Console()

# Pink gradient colors top → bottom
_PINK_GRADIENT = [
    "#ff2d78", "#ff3d80", "#ff4d88",
    "#ff5e90", "#ff6e99", "#ff85b3",
]
_BANNER_LINES = [
    "  ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ ",
    " ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗",
    " ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║",
    " ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║",
    " ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║",
    "  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝",
]

def print_banner():
    """Print the pink gradient OMEGA-CLI banner."""
    console.print()
    for line, color in zip(_BANNER_LINES, _PINK_GRADIENT):
        console.print(f"[bold {color}]{line}[/bold {color}]")
    console.print(
        "  [bold #ff85b3]OMEGA-CLI[/bold #ff85b3] "
        "[dim #cc6688]v1.8.0 — OSINT & Passive Recon Toolkit[/dim #cc6688]"
    )
    console.print()

BANNER = "[bold #ff2d78]OMEGA-CLI[/bold #ff2d78] [dim]v1.8.0[/dim]"


@click.group(invoke_without_command=True)
@click.version_option("1.8.0", prog_name="omega")
@click.pass_context
def cli(ctx):
    """omega — OSINT and passive recon toolkit."""
    print_banner()
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ── Core recon ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
def whois(target):
    """WHOIS lookup for a domain or IP."""
    from omega_cli.modules import whois_lookup
    whois_lookup.run(target)


@cli.command()
@click.argument("target")
@click.option("--type", "record_type", default="ALL", help="Record type or ALL")
def dns(target, record_type):
    """DNS record enumeration."""
    from omega_cli.modules import dns_lookup
    dns_lookup.run(target, record_type)


@cli.command()
@click.argument("target")
@click.option("--wordlist", "-w", default=None, help="Custom subdomain wordlist")
def subdomains(target, wordlist):
    """Subdomain enumeration via DNS brute-force."""
    from omega_cli.modules import subdomain
    subdomain.run(target, wordlist)


@cli.command()
@click.argument("target")
def crtsh(target):
    """Passive subdomain discovery via Certificate Transparency logs."""
    from omega_cli.modules import crtsh as _crtsh
    _crtsh.run(target)


@cli.command()
@click.argument("target")
def ipinfo(target):
    """IP geolocation, ASN, and RDAP info."""
    from omega_cli.modules import ipinfo as _ipinfo
    _ipinfo.run(target)


@cli.command()
@click.argument("target")
def email(target):
    """Email OSINT: validation, MX, disposable/breach check."""
    from omega_cli.modules import email_osint
    email_osint.run(target)


@cli.command()
@click.argument("target")
def headers(target):
    """HTTP response headers analysis and security audit."""
    from omega_cli.modules import headers as _headers
    _headers.run(target)


@cli.command()
@click.argument("target")
def ssl(target):
    """SSL/TLS certificate inspection."""
    from omega_cli.modules import ssl_check
    ssl_check.run(target)


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="common", help="'common', '80,443', or '1-1024'")
def ports(target, ports):
    """TCP port scan (connect scan)."""
    from omega_cli.modules import portscan
    portscan.run(target, ports)


@cli.command()
@click.argument("target")
@click.option("--dork", "-d", default="all", help="Category or 'all'")
def dorks(target, dork):
    """Generate Google dork queries for a target."""
    from omega_cli.modules import dorks as _dorks
    _dorks.run(target, dork)


# ── Intelligence modules ─────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--limit", "-l", default=500, show_default=True, help="Max archived URLs")
def wayback(target, limit):
    """Wayback Machine — archived URLs and exposed endpoints."""
    from omega_cli.modules import wayback as _wayback
    _wayback.run(target, limit=limit)


@cli.command()
@click.argument("target")
def tech(target):
    """Technology fingerprinting — CMS, frameworks, WAF, analytics."""
    from omega_cli.modules import techfp
    techfp.run(target)


@cli.command()
@click.argument("target")
def threat(target):
    """Threat intelligence — URLhaus, AbuseIPDB."""
    from omega_cli.modules import threatintel
    threatintel.run(target)


@cli.command()
@click.argument("username")
def user(username):
    """Username OSINT — check handle across 20+ platforms."""
    from omega_cli.modules import username as _username
    _username.run(username)


# ── New v0.3.0 commands ──────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
def spoof(target):
    """Email spoofing audit — SPF, DKIM, DMARC analysis."""
    from omega_cli.modules import spoofcheck
    spoofcheck.run(target)


@cli.command()
@click.argument("target")
def revip(target):
    """Reverse IP — find co-hosted domains on the same server."""
    from omega_cli.modules import reverseip
    reverseip.run(target)


@cli.command()
@click.argument("target")
def js(target):
    """JavaScript scanner — extract endpoints and secrets from JS files."""
    from omega_cli.modules import jscan
    jscan.run(target)


@cli.command()
@click.argument("target")
def robots(target):
    """robots.txt and sitemap.xml content discovery."""
    from omega_cli.modules import crawl
    crawl.run(target)


@cli.command()
@click.argument("target")
def buckets(target):
    """Cloud bucket finder — open S3, GCS, Azure, DO Spaces."""
    from omega_cli.modules import buckets as _buckets
    _buckets.run(target)


@cli.command()
@click.argument("target")
def cve(target):
    """CVE mapper — match detected technologies to known vulnerabilities."""
    from omega_cli.modules import techfp, cvemap
    tech_result = techfp.run(target)
    cvemap.run(tech_detections=tech_result)


@cli.command()
@click.argument("target")
@click.option("--modules", "-m", default=None,
              help="Comma-separated modules to run (default: all)")
@click.option("--report", "-r", is_flag=True, help="Export HTML + JSON report")
@click.option("--output", "-o", default=None, help="Report output directory")
def scan(target, modules, report, output):
    """⚡ Live TUI dashboard — all modules run in parallel with real-time output."""
    mod_list = [m.strip() for m in modules.split(",")] if modules else None
    from omega_cli.modules import dashboard
    dashboard.run(target, modules=mod_list, report=report, output_dir=output)


# ── Recon (sequential, verbose) ──────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--report", "-r", is_flag=True, help="Export HTML + JSON report")
@click.option("--output", "-o", default=None, help="Report output directory")
def recon(target, report, output):
    """Full sequential recon — all modules, verbose output."""
    from omega_cli.modules import recon as _recon
    _recon.run(target, report=report, output_dir=output)


# ── Config ───────────────────────────────────────────────────────────────────

@cli.group()
def config():
    """Manage configuration and API keys."""
    pass


@config.command("show")
def config_show():
    """Show current configuration."""
    from omega_cli.config import show
    show()


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a config value  (e.g. omega config set abuseipdb_api_key KEY)."""
    from omega_cli import config as cfg_mod
    cfg = cfg_mod.load()
    if key not in cfg:
        console.print(f"[red]Unknown key:[/red] {key}. Valid: {', '.join(cfg.keys())}")
        return
    cfg[key] = value
    cfg_mod.save(cfg)
    console.print(f"[green]✓[/green] {key} updated.")


@cli.command()
def banner():
    """Print the omega banner."""
    print_banner()


# ── v0.4.0 — Elite capabilities ───────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--provider", default="ollama", show_default=True,
              type=click.Choice(["ollama", "openai"]),
              help="AI provider: ollama (local) or openai")
@click.option("--model", default="", help="Model name override (e.g. gpt-4o, llama3)")
@click.option("--scan", is_flag=True, help="Run a quick recon scan first, then analyse")
def ai(target, provider, model, scan):
    """🤖  AI-powered attack surface analysis (Ollama/OpenAI)."""
    from omega_cli.modules import ai_analyst
    from omega_cli.config import load
    cfg = load()
    api_key = cfg.get("openai_api_key", "")
    findings = {}
    if scan:
        console.print("[dim]Running quick scan before AI analysis...[/]")
        try:
            from omega_cli.modules import whois_lookup, dns_lookup, headers as hdr, ssl_check, techfp
            findings["whois"] = whois_lookup.run(target)
            findings["dns"] = dns_lookup.run(target)
            findings["headers"] = hdr.run(f"https://{target}")
            findings["ssl"] = ssl_check.run(target)
            findings["tech"] = techfp.run(f"https://{target}")
        except Exception as e:
            console.print(f"[yellow]Scan error:[/] {e}")
    else:
        findings = {"target": target, "note": "No scan performed — pass --scan to include live data"}
    ai_analyst.run(target, findings, provider=provider, api_key=api_key, model=model)


@cli.command("map")
@click.argument("target")
@click.option("--deep", is_flag=True, help="Probe open ports on each discovered IP")
def asset_map(target, deep):
    """🗺   Network asset map — domains, subdomains, IPs, ports as a live tree."""
    from omega_cli.modules import assetmap
    assetmap.run(target, deep=deep)


@cli.group()
def monitor():
    """👁   Continuous target monitoring with change detection."""
    pass


@monitor.command("watch")
@click.argument("target")
@click.option("--interval", default=300, show_default=True, help="Check interval in seconds")
@click.option("--webhook", default="", help="Webhook URL for change alerts")
def monitor_watch(target, interval, webhook):
    """Watch a target continuously and alert on changes."""
    from omega_cli.modules.monitor import watch
    watch(target, interval=interval, webhook=webhook)


@monitor.command("status")
@click.argument("target")
def monitor_status(target):
    """Show the last saved snapshot for a target."""
    from omega_cli.modules.monitor import status
    status(target)


@monitor.command("list")
def monitor_list():
    """List all monitored targets."""
    from omega_cli.modules.monitor import list_targets
    list_targets()


@cli.command()
@click.option("--provider", required=True,
              type=click.Choice(["discord", "slack", "telegram", "custom"]),
              help="Notification provider")
@click.option("--url", default="", help="Webhook URL")
@click.option("--target", default="", help="Target label for the alert")
@click.option("--message", default="", help="Custom message")
@click.option("--test", is_flag=True, help="Send a test notification")
@click.option("--tg-token", default="", help="Telegram bot token")
@click.option("--tg-chat", default="", help="Telegram chat ID")
def notify(provider, url, target, message, test, tg_token, tg_chat):
    """🔔  Send notifications via Discord, Slack, Telegram, or custom webhook."""
    from omega_cli.modules import notifier
    if not url and provider != "telegram":
        from omega_cli.config import load
        cfg = load()
        key = f"{provider}_webhook"
        url = cfg.get(key, "")
    if not url and not (tg_token and tg_chat):
        console.print(f"[red]No webhook URL.[/] Set with: [cyan]omega config set {provider}_webhook URL[/]")
        return
    notifier.run(provider, url, target=target, message=message, test=test,
                 telegram_token=tg_token, telegram_chat=tg_chat)


@cli.command()
@click.argument("keyword")
@click.option("--limit", default=10, show_default=True, help="Max results")
@click.option("--min-score", default=0.0, show_default=True, help="Minimum CVSS score filter")
def cve(keyword, limit, min_score):
    """🔍  Real-time CVE lookup from NIST NVD API v2."""
    from omega_cli.modules import nvd_cve
    from omega_cli.config import load
    cfg = load()
    nvd_cve.run(keyword, limit=limit, min_score=min_score,
                api_key=cfg.get("nvd_api_key", ""))


@cli.command("shell")
def omega_shell():
    """💻  Interactive OMEGA REPL with autocomplete and history."""
    from omega_cli.modules import shell_repl
    shell_repl.run()


# ── v0.5.0 — Next level ───────────────────────────────────────────────────────

@cli.command()
@click.argument("domain")
@click.option("--deep", is_flag=True, help="Also search Bing and GitHub for emails")
@click.option("--github-token", default="", envvar="GITHUB_TOKEN", help="GitHub PAT for higher rate limits")
def harvest(domain, deep, github_token):
    """📧  Email harvester — scrape addresses from web, crt.sh, GitHub."""
    from omega_cli.modules import harvester
    from omega_cli.config import load
    cfg = load()
    token = github_token or cfg.get("github_token", "")
    harvester.run(domain, github_token=token, deep=deep)


@cli.command()
@click.argument("target")
def asn(target):
    """🌐  ASN / BGP recon — netblocks, prefixes, peers, org info.

    TARGET can be an ASN (AS12345 or 12345) or an IP address.
    """
    from omega_cli.modules import asnrecon
    asnrecon.run(target)


@cli.command()
@click.argument("target")
@click.option("--deep", is_flag=True, help="Scan file contents for actual secret values")
@click.option("--token", default="", envvar="GITHUB_TOKEN", help="GitHub PAT")
def git(target, deep, token):
    """🐙  GitHub OSINT — repos, exposed secrets, org recon."""
    from omega_cli.modules import gitrecon
    from omega_cli.config import load
    cfg = load()
    tok = token or cfg.get("github_token", "")
    gitrecon.run(target, token=tok, deep=deep)


@cli.command()
@click.argument("target")
@click.option("--endpoints", is_flag=True, help="Test common API endpoints too")
def cors(target, endpoints):
    """🔓  CORS misconfiguration tester — wildcard, reflected origin, credentials bypass."""
    from omega_cli.modules import corscheck
    corscheck.run(target, endpoints=endpoints)


@cli.command()
@click.argument("domain")
@click.option("--no-probe", is_flag=True, help="Skip DNS probing, just list permutations")
@click.option("--limit", default=200, show_default=True, help="Max permutations to check")
def typo(domain, no_probe, limit):
    """🎭  Typosquatting detector — lookalike domains, keyboard swaps, homoglyphs."""
    from omega_cli.modules import typosquat
    typosquat.run(domain, probe=not no_probe, limit=limit)


@cli.command()
@click.argument("target")
@click.option("--output", default="", help="Output path (.pdf or .html)")
@click.option("--scan", is_flag=True, help="Run quick recon first then generate report")
def pdf(target, output, scan):
    """📄  Export findings as a styled PDF report."""
    from omega_cli.modules import pdfreport
    findings = {}
    if scan:
        console.print("[dim]Running quick scan for report data...[/]")
        try:
            from omega_cli.modules import whois_lookup, dns_lookup, headers as hdr, ssl_check, techfp, crtsh
            findings["whois"] = whois_lookup.run(target) or {}
            findings["dns"] = dns_lookup.run(target) or {}
            findings["headers"] = hdr.run(f"https://{target}") or {}
            findings["ssl"] = ssl_check.run(target) or {}
            findings["tech"] = techfp.run(f"https://{target}") or {}
            findings["crtsh"] = crtsh.run(target) or {}
        except Exception as e:
            console.print(f"[yellow]Scan error:[/] {e}")
    pdfreport.run(target, findings=findings or None, output=output)


# ── v0.6.0 — Elite tier ──────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--search", is_flag=True, help="Use target as a Shodan search query instead of host")
def shodan(target, search):
    """👁  Shodan.io — exposed services, banners, CVEs, open ports."""
    from omega_cli.modules import shodan_lookup
    from omega_cli.config import load
    cfg = load()
    shodan_lookup.run(target, api_key=cfg.get("shodan_api_key", ""), search=search)


@cli.command()
@click.argument("target")
@click.option("--password", is_flag=True, help="Check a password instead of email/domain")
def breach(target, password):
    """💀  Data breach checker — HIBP email/domain/password lookup."""
    from omega_cli.modules import breachcheck
    from omega_cli.config import load
    cfg = load()
    breachcheck.run(target, hibp_key=cfg.get("hibp_api_key", ""), password=password)


@cli.command()
@click.argument("target")
@click.option("--live", is_flag=True, help="Submit for a live URLScan.io scan (slower)")
def phish(target, live):
    """🎣  Phishing detection — URLScan.io, PhishTank, Google Safe Browsing."""
    from omega_cli.modules import phishcheck
    from omega_cli.config import load
    cfg = load()
    phishcheck.run(
        target,
        api_key=cfg.get("urlscan_api_key", ""),
        gsb_key=cfg.get("gsb_api_key", ""),
        live_scan=live,
    )


@cli.command()
@click.argument("name")
@click.option("--deep", is_flag=True, help="Show cloud metadata SSRF reference table")
def cloud(name, deep):
    """☁   Cloud asset enumeration — S3, GCS, Azure, Firebase, DO Spaces."""
    from omega_cli.modules import cloudrecon
    cloudrecon.run(name, deep=deep)


@cli.command()
@click.argument("domain")
@click.option("--rules", is_flag=True, help="Apply password mutation rules")
@click.option("--emails", is_flag=True, help="Also generate corporate email format list")
@click.option("--output", default="", help="Output file path")
def wordlist(domain, rules, emails, output):
    """📝  Target-specific wordlist generator from scraped OSINT data."""
    from omega_cli.modules import wordlist as wl
    wl.run(domain, output=output, rules=rules, emails=emails)


@cli.command()
@click.argument("target")
@click.option("--passive", is_flag=True, help="Passive-only mode (no active probing)")
@click.option("--output-dir", default="", help="Directory for PDF/JSON output")
def auto(target, passive, output_dir):
    """⚡  Full automated recon — chains ALL modules, exports PDF + JSON."""
    from omega_cli.modules import autorecon
    autorecon.run(target, passive_only=passive, output_dir=output_dir)


# ── v0.7.0 — OpSec + Intelligence ────────────────────────────────────────────

@cli.command()
@click.argument("action", type=click.Choice(["status", "test", "tor", "clear"]), default="status")
@click.option("--proxy-url", default="", help="Proxy URL to test (e.g. socks5h://127.0.0.1:9050)")
def proxy(action, proxy_url):
    """🕵  Proxy/Tor anonymity — status, test, and configure routing."""
    from omega_cli.modules import proxy as px
    px.run(action, proxy=proxy_url)


@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--width", default=1280, show_default=True, help="Viewport width")
@click.option("--no-full-page", is_flag=True, help="Capture viewport only, not full page")
@click.option("--output-dir", default="", help="Output directory for screenshots")
def screenshot(targets, width, no_full_page, output_dir):
    """📸  Headless browser screenshots via Playwright."""
    from omega_cli.modules import screenshot as ss
    urls = [t if t.startswith("http") else f"https://{t}" for t in targets]
    ss.run(urls, width=width, full_page=not no_full_page, output_dir=output_dir)


@cli.command()
@click.argument("target")
@click.option("--json-file", default="", help="Load findings from a specific JSON file")
def graph(target, json_file):
    """🕸  Entity relationship graph — maps all OSINT findings into a visual tree."""
    from omega_cli.modules import graph as gr
    gr.run(target, json_file=json_file)


@cli.command()
@click.argument("target")
@click.option("--wordlist-file", default="", help="Custom wordlist file path")
@click.option("--extensions", is_flag=True, help="Try common extensions (.php, .bak, etc.)")
@click.option("--concurrency", default=20, show_default=True, help="Concurrent requests")
@click.option("--codes", default="200,201,301,302,401,403", show_default=True, help="Status codes to show")
def fuzz(target, wordlist_file, extensions, concurrency, codes):
    """💥  Directory/file fuzzer — finds hidden paths and sensitive files."""
    from omega_cli.modules import fuzzer as fz
    fz.run(target, wordlist_file=wordlist_file, extensions=extensions,
           concurrency=concurrency, codes=codes)


@cli.command()
@click.argument("target")
@click.option("--deep", is_flag=True, help="Also search GitHub commits")
@click.option("--token", default="", envvar="GITHUB_TOKEN", help="GitHub PAT")
def social(target, deep, token):
    """📱  Social media OSINT — Reddit, HackerNews, Pastebin, Twitter/X."""
    from omega_cli.modules import social as sc
    from omega_cli.config import load
    cfg = load()
    sc.run(target, token=token or cfg.get("github_token", ""), deep=deep)


@cli.command()
@click.argument("target")
@click.option("--json-file", default="", help="Load findings from a specific JSON file")
def timeline(target, json_file):
    """📅  Intelligence timeline — chronological narrative from all OSINT sources."""
    from omega_cli.modules import timeline as tl
    tl.run(target, json_file=json_file)


# ── v0.8.0 — Threat Intelligence + Dark Web ──────────────────────────────────

@cli.command()
@click.argument("query")
@click.option("--limit", default=20, show_default=True, help="Max results from Ahmia")
@click.option("--extract", is_flag=True, help="Extract .onion addresses from raw text/URL")
def dark(query, limit, extract):
    """🌑  Dark web recon — Ahmia search + .onion address extraction."""
    from omega_cli.modules import dark as dk
    dk.run(query, limit=limit, extract_only=extract)


@cli.command()
@click.argument("address")
@click.option("--eth-key", default="", envvar="ETHERSCAN_API_KEY", help="Etherscan API key")
def crypto(address, eth_key):
    """₿   Blockchain OSINT — BTC/ETH address balance, transactions, abuse reports."""
    from omega_cli.modules import crypto as cr
    from omega_cli.config import load
    cfg = load()
    cr.run(address, eth_api_key=eth_key or cfg.get("etherscan_api_key", ""))


@cli.command()
@click.argument("ioc_value")
@click.option("--vt-key", default="", envvar="VT_API_KEY", help="VirusTotal API key")
@click.option("--no-mb", is_flag=True, help="Skip MalwareBazaar lookup")
def malware(ioc_value, vt_key, no_mb):
    """🦠  Malware / threat analysis — VirusTotal + MalwareBazaar for hashes, URLs, domains."""
    from omega_cli.modules import malware as mw
    from omega_cli.config import load
    cfg = load()
    mw.run(ioc_value, api_key=vt_key or cfg.get("vt_api_key", ""), no_mb=no_mb)


@cli.command()
@click.argument("source")
@click.option("--include-private", is_flag=True, help="Include RFC1918 private IPs")
@click.option("--defang", is_flag=True, help="Defang output (1[.]2[.]3[.]4, hxxp://)")
@click.option("--types", default="", help="Filter types: IPv4,Domain,SHA256,CVE,…")
def ioc(source, include_private, defang, types):
    """🔍  IOC extractor — parse text/file/URL for IPs, hashes, domains, CVEs, BTC."""
    from omega_cli.modules import ioc as ic
    ic.run(source, no_private=not include_private, defang=defang, types=types)


@cli.command()
@click.argument("target")
@click.option("--image", default="", help="Image file to extract EXIF GPS from")
def geoint(target, image):
    """🌍  Geo-intelligence — IP geolocation, EXIF GPS extraction, reverse geocoding."""
    from omega_cli.modules import geoint as gi
    gi.run(target, image=image)


@cli.command()
@click.argument("target")
@click.option("--otx-key",        default="", envvar="OTX_API_KEY",       help="AlienVault OTX key")
@click.option("--abuseipdb-key",  default="", envvar="ABUSEIPDB_API_KEY", help="AbuseIPDB key")
@click.option("--greynoise-key",  default="", envvar="GREYNOISE_API_KEY", help="GreyNoise key")
def intel(target, otx_key, abuseipdb_key, greynoise_key):
    """🛡   Threat intel — AlienVault OTX + AbuseIPDB + GreyNoise aggregator."""
    from omega_cli.modules import intel as ti
    from omega_cli.config import load
    cfg = load()
    ti.run(target,
           otx_key=otx_key or cfg.get("otx_api_key", ""),
           abuseipdb_key=abuseipdb_key or cfg.get("abuseipdb_api_key", ""),
           greynoise_key=greynoise_key or cfg.get("greynoise_api_key", ""))


# ── v0.9.0 — Active Recon + Threat Hunting ───────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--max-pages",   default=50, show_default=True, help="Max pages to crawl")
@click.option("--depth",       default=3,  show_default=True, help="Crawl depth")
@click.option("--concurrency", default=8,  show_default=True, help="Concurrent requests")
def spider(target, max_pages, depth, concurrency):
    """🕷  Recursive web spider — pages, links, forms, JS endpoints, secret scan."""
    from omega_cli.modules import spider as sp
    sp.run(target, max_pages=max_pages, depth=depth, concurrency=concurrency)


@cli.command()
@click.argument("target")
@click.option("--ports",  default="", help="Ports to probe (default: 50050,8443,8080,443,80)")
@click.option("--deep",   is_flag=True, help="Cross-check against C2 intel feeds")
def c2(target, ports, deep):
    """☠  C2 detection — Cobalt Strike, Sliver, Metasploit fingerprinting + intel feeds."""
    from omega_cli.modules import c2 as c2mod
    c2mod.run(target, ports_str=ports, deep=deep)


@cli.command()
@click.argument("target")
@click.option("--token",      default="", envvar="GITHUB_TOKEN", help="GitHub PAT")
@click.option("--no-github",  is_flag=True, help="Skip GitHub search")
@click.option("--no-paste",   is_flag=True, help="Skip Pastebin search")
def creds(target, token, no_github, no_paste):
    """🔐  Credential exposure — GitHub secret scan + Pastebin + leak site search."""
    from omega_cli.modules import creds as cr
    from omega_cli.config import load
    cfg = load()
    cr.run(target, token=token or cfg.get("github_token", ""),
           no_github=no_github, no_paste=no_paste)


@cli.command()
@click.argument("target_ip", default="", required=False)
def opsec(target_ip):
    """🛡  OpSec audit — anonymity check, DNS leak, Tor status, OPSEC score."""
    from omega_cli.modules import opsec as op
    op.run(target_ip=target_ip)


@cli.command()
@click.argument("target")
@click.option("--json-file", default="", help="Path to omega auto recon JSON")
@click.option("--playbook",  default="all", help="Playbook filter (all)")
def hunt(target, json_file, playbook):
    """🎯  Threat hunt — map findings to MITRE ATT&CK TTPs, compute risk score."""
    from omega_cli.modules import hunt as ht
    ht.run(target, json_file=json_file, playbook=playbook)


@cli.command("compare")
@click.argument("target")
@click.option("--old", "old_file", default="", help="Older recon JSON file")
@click.option("--new", "new_file", default="", help="Newer recon JSON file")
def compare_cmd(target, old_file, new_file):
    """📊  Recon diff — compare two omega recon runs, surface new/changed/removed findings."""
    from omega_cli.modules import compare as cmp
    cmp.run(target, old_file=old_file, new_file=new_file)


# ── v1.0.0 — Platform: API + Pipelines + ML + AI ────────────────────────────

@cli.command("api")
@click.option("--host",     default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port",     default=6660,         show_default=True, help="Listen port")
@click.option("--show-key", is_flag=True,         help="Print API key and exit")
@click.option("--new-key",  is_flag=True,         help="Rotate to a new API key")
def api_server(host, port, show_key, new_key):
    """🌐  REST API server — expose all omega commands over HTTP with API key auth."""
    from omega_cli.modules import apiserver
    apiserver.run(host=host, port=port, show_key=show_key, new_key=new_key)


@cli.command("chain")
@click.argument("action", type=click.Choice(["list", "run", "new", "show"]), default="list")
@click.argument("name", default="")
@click.option("--target",  default="", help="Target to pass into chain steps")
@click.option("--dry-run", is_flag=True, help="Print steps without executing")
def chain_cmd(action, name, target, dry_run):
    """⛓  Workflow pipeline — run named multi-step recon chains (built-in + custom)."""
    from omega_cli.modules import chain as ch
    ch.run(action=action, name=name, target=target, dry_run=dry_run)


@cli.command("plugin")
@click.argument("action", type=click.Choice(["list", "new", "run", "install"]), default="list")
@click.argument("name", default="")
@click.option("--target",      default="", help="Target to pass to plugin run")
@click.option("--description", default="", help="Description for new plugin")
@click.option("--source",      default="", help="URL or GitHub user/repo for install")
def plugin_cmd(action, name, target, description, source):
    """🔌  Plugin system — create, list, run, and install custom omega modules."""
    from omega_cli.modules import plugin as pl
    pl.run(action=action, name=name, target=target,
           description=description, source=source)


@cli.command("ml")
@click.argument("target")
@click.option("--action",    default="detect",
              type=click.Choice(["baseline", "detect", "status"]),
              show_default=True, help="baseline=record scan | detect=find anomalies | status=show baseline")
@click.option("--json-file", default="", help="Path to recon JSON")
@click.option("--threshold", default=2.0, show_default=True, help="Z-score anomaly threshold")
def ml_cmd(target, action, json_file, threshold):
    """🤖  ML anomaly detection — baseline target, detect deviations across scans."""
    from omega_cli.modules import mldetect
    mldetect.run(target, json_file=json_file, action=action, threshold=threshold)


@cli.command()
@click.argument("target")
@click.option("--json-file", default="",          help="Path to omega auto recon JSON")
@click.option("--api-key",   default="",          envvar="OPENAI_API_KEY", help="OpenAI API key")
@click.option("--model",     default="gpt-3.5-turbo", show_default=True,  help="OpenAI model")
@click.option("--no-ai",     is_flag=True,        help="Skip AI narrative, show risk table only")
def executive(target, json_file, api_key, model, no_ai):
    """📋  Executive report — AI narrative + per-finding risk ratings + remediation plan."""
    from omega_cli.modules import executive as ex
    from omega_cli.config import load
    cfg = load()
    ex.run(target, json_file=json_file,
           api_key=api_key or cfg.get("openai_api_key", ""),
           model=model, no_ai=no_ai)


@cli.command("live")
@click.argument("target")
@click.option("--duration", default=120, show_default=True, help="Dashboard run time in seconds")
def live_cmd(target, duration):
    """⚡  Live dashboard — full-screen multi-panel TUI with simultaneous module outputs."""
    from omega_cli.modules import livedash
    livedash.run(target, duration=duration)


# ── v1.1.0 — Intelligence + Red Team ─────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--passive",    is_flag=True, default=True, show_default=True,
              help="Passive-only (skip port scan and active probing)")
@click.option("--output-dir", default="", help="Directory for output files")
def dossier(target, passive, output_dir):
    """🗂  Full OSINT dossier — structured intelligence profile: DNS+SSL+subdomains+tech+ASN+PDF."""
    from omega_cli.modules import dossier as ds
    ds.run(target, passive_only=passive, output_dir=output_dir)


@cli.command("network")
@click.argument("target")
@click.option("--no-trace", is_flag=True, help="Skip traceroute")
def network_cmd(target, no_trace):
    """🌐  Network topology — traceroute, BGP/ASN, CDN/WAF fingerprint, DNS propagation."""
    from omega_cli.modules import network as nw
    nw.run(target, no_trace=no_trace)


@cli.command("secrets")
@click.argument("target")
@click.option("--token",     default="", envvar="GITHUB_TOKEN", help="GitHub PAT")
@click.option("--scan-type", default="auto",
              type=click.Choice(["auto", "github", "npm", "pypi", "docker"]),
              show_default=True, help="Source to scan")
def secrets_cmd(target, token, scan_type):
    """🔑  Secret scanner — GitHub commits, npm, PyPI, Docker Hub for exposed credentials."""
    from omega_cli.modules import secrets as sc
    from omega_cli.config import load
    cfg = load()
    sc.run(target, token=token or cfg.get("github_token", ""), scan_type=scan_type)


@cli.command("watcher")
@click.argument("action",
                type=click.Choice(["add", "remove", "list", "daemon", "stop", "log"]),
                default="list")
@click.argument("target", default="")
@click.option("--interval", default=3600,            show_default=True, help="Check interval (seconds)")
@click.option("--chain",    default="quick-recon",   show_default=True, help="Chain to run on each check")
@click.option("--webhook",  default="",              help="Webhook URL for change alerts")
def watcher_cmd(action, target, interval, chain, webhook):
    """👁  Persistent watcher — cron daemon that re-runs chains and alerts on changes."""
    from omega_cli.modules import watcher as wt
    wt.run(action=action, target=target, interval=interval, chain=chain, webhook=webhook)


@cli.command("viz")
@click.argument("target")
@click.option("--json-file", default="", help="Path to recon JSON")
@click.option("--format",    default="tree",
              type=click.Choice(["tree", "ascii", "both"]),
              show_default=True, help="Output format")
def viz_cmd(target, json_file, format):
    """📊  Attack surface visualizer — Rich tree + ASCII topology graph of all findings."""
    from omega_cli.modules import viz as vz
    vz.run(target, json_file=json_file, format=format)


@cli.command("redteam")
@click.argument("target")
@click.option("--json-file",  default="", help="Path to recon JSON")
@click.option("--gen-script", is_flag=True, help="Output Metasploit .rc script")
def redteam_cmd(target, json_file, gen_script):
    """🔴  Red team surface — CVE→exploit mapping, port attack vectors, MSF module suggestions."""
    from omega_cli.modules import redteam as rt
    rt.run(target, json_file=json_file, generate_commands=gen_script)


# ── v1.2.0 — Supply Chain + Identity + Blue Team ─────────────────────────────

@cli.command("supply")
@click.argument("target")
@click.option("--ecosystem", default="auto",
              type=click.Choice(["auto", "npm", "pypi"]),
              show_default=True, help="Package ecosystem")
@click.option("--no-typos", is_flag=True, help="Skip typosquat checks")
def supply_cmd(target, ecosystem, no_typos):
    """⛓  Supply chain — dependency tree, OSV vulns, typosquatted packages."""
    from omega_cli.modules import supply as sc
    sc.run(target, ecosystem=ecosystem, check_typos=not no_typos)


@cli.command("identity")
@click.argument("target")
@click.option("--deep", is_flag=True, help="Check all 50+ platforms (slower)")
@click.option("--email-pivot", is_flag=True, help="Derive usernames from email and check all variants")
def identity_cmd(target, deep, email_pivot):
    """🪪  Identity correlation — cross-platform username/email presence across 50+ sites."""
    from omega_cli.modules import identity as id_mod
    id_mod.run(target, deep=deep, email_pivot=email_pivot)


@cli.command("leaked")
@click.argument("target")
@click.option("--password", "check_password", is_flag=True, help="Treat target as a password (k-anon check)")
@click.option("--hibp-key",       default="", envvar="HIBP_API_KEY",      help="HaveIBeenPwned API key")
@click.option("--github-token",   default="", envvar="GITHUB_TOKEN",      help="GitHub PAT")
@click.option("--intelx-key",     default="", envvar="INTELX_API_KEY",    help="IntelligenceX API key")
@click.option("--dehashed-email", default="", help="Dehashed account email")
@click.option("--dehashed-key",   default="", envvar="DEHASHED_API_KEY",  help="Dehashed API key")
def leaked_cmd(target, check_password, hibp_key, github_token, intelx_key, dehashed_email, dehashed_key):
    """💧  Leaked data — HIBP breaches, paste search, GitHub leaks, IntelX, Dehashed."""
    from omega_cli.modules import leaked as lk
    from omega_cli.config import load
    cfg = load()
    lk.run(
        target,
        check_password=check_password,
        hibp_key=hibp_key or cfg.get("hibp_api_key", ""),
        github_token=github_token or cfg.get("github_token", ""),
        intelx_key=intelx_key or cfg.get("intelx_api_key", ""),
        dehashed_email=dehashed_email or cfg.get("dehashed_email", ""),
        dehashed_key=dehashed_key or cfg.get("dehashed_api_key", ""),
    )


@cli.command("deception")
@click.argument("action",
                type=click.Choice(["create", "list", "show", "delete", "alert"]),
                default="list")
@click.option("--label",  default="", help="Description for this canary")
@click.option("--type",   "canary_type", default="dns",
              type=click.Choice(["dns", "http", "aws", "ssh", "email", "document"]),
              show_default=True, help="Canary token type")
@click.option("--domain", default="", help="Domain for DNS/email canaries")
@click.option("--port",   default=8080, show_default=True, help="Port for HTTP canary")
@click.option("--token",  "token_id", default="", help="Token prefix for show/delete/alert")
def deception_cmd(action, label, canary_type, domain, port, token_id):
    """🍯  Canary tokens — generate DNS/HTTP/AWS/SSH/email honeypot tripwires."""
    from omega_cli.modules import deception as dc
    dc.run(action=action, label=label, canary_type=canary_type, domain=domain, port=port, token_id=token_id)


@cli.command("infra")
@click.argument("target")
@click.option("--no-cdn", is_flag=True, help="Skip CDN/WAF fingerprinting")
@click.option("--deep",   is_flag=True, help="Include subdomain pivot")
def infra_cmd(target, no_cdn, deep):
    """🏗  Infrastructure archaeology — IP history, WHOIS, CDN/WAF, cloud provider, shared hosting."""
    from omega_cli.modules import infra as inf
    inf.run(target, no_cdn=no_cdn, deep=deep)


@cli.command("report")
@click.argument("target")
@click.option("--json-file", default="",  help="Specific JSON file to include")
@click.option("--output",    default="",  help="Output HTML file path")
@click.option("--open",      "open_browser", is_flag=True, help="Open report in browser after generation")
def report_cmd(target, json_file, output, open_browser):
    """📊  Interactive HTML report — D3.js force graph + full findings dashboard."""
    from omega_cli.modules import reporthtml as rh
    rh.run(target, json_file=json_file, output=output, open_browser=open_browser)


# ── v1.3.0 — Mobile + Satellite + AI + Pivot + Archive + Org ─────────────────

@cli.command("mobile")
@click.argument("target")
@click.option("--apk",          default="",  help="Path to local APK file for static analysis")
@click.option("--no-store",     is_flag=True, help="Skip app store lookup")
def mobile_cmd(target, apk, no_store):
    """📱  Mobile OSINT — APK static analysis, permissions, trackers, hardcoded secrets, app store."""
    from omega_cli.modules import mobile as mob
    mob.run(target, apk_file=apk, store_lookup=not no_store)


@cli.command("satellite")
@click.argument("target")
@click.option("--mode", default="auto",
              type=click.Choice(["auto", "aircraft_icao", "aircraft_callsign", "vessel_mmsi", "callsign"]),
              show_default=True, help="Query type override")
def satellite_cmd(target, mode):
    """🛰  Satellite/radio OSINT — ADS-B aircraft, AIS vessels, amateur radio callsign lookup."""
    from omega_cli.modules import satellite as sat
    sat.run(target, mode=mode)


@cli.command("aiassist")
@click.argument("target")
@click.option("--json-file",    default="",  help="Specific JSON file to analyze")
@click.option("--provider",     default="auto",
              type=click.Choice(["auto", "openai", "ollama", "local"]),
              show_default=True, help="AI provider")
@click.option("--model",        default="",  help="Model override (e.g. gpt-4o, llama3.2)")
@click.option("--focus",        default="general",
              type=click.Choice(["general", "threat", "executive", "remediation", "recon"]),
              show_default=True, help="Analysis focus")
@click.option("--ollama-host",  default="http://localhost:11434", show_default=True)
def aiassist_cmd(target, json_file, provider, model, focus, ollama_host):
    """🤖  AI analyst — feed recon data to GPT/Ollama for threat narrative + next steps."""
    from omega_cli.modules import aiassist as ai
    ai.run(target, json_file=json_file, provider=provider, model=model, focus=focus, ollama_host=ollama_host)


@cli.command("pivot")
@click.argument("target")
@click.option("--depth",     default=2,  show_default=True, help="Pivot depth (1-3)")
@click.option("--max-nodes", default=50, show_default=True, help="Max nodes to explore")
def pivot_cmd(target, depth, max_nodes):
    """🔗  IOC pivot engine — expand any IP/domain/hash/email to all related observables."""
    from omega_cli.modules import pivot as pv
    pv.run(target, depth=depth, max_nodes=max_nodes)


@cli.command("archive")
@click.argument("target")
@click.option("--limit",      default=100, show_default=True, help="Max CDX URLs to fetch")
@click.option("--snapshots",  is_flag=True, help="Show full snapshot history")
@click.option("--diff",       is_flag=True, help="Diff oldest vs newest snapshot")
@click.option("--interesting",is_flag=True, help="Show only interesting URLs")
def archive_cmd(target, limit, snapshots, diff, interesting):
    """🗄  Deep archive mining — Wayback CDX, CommonCrawl, interesting URL extraction."""
    from omega_cli.modules import archive as ar
    ar.run(target, limit=limit, diff=diff, interesting_only=interesting, show_snapshots=snapshots)


@cli.command("org")
@click.argument("target")
@click.option("--domain",      default="",  help="Primary domain for DNS inference")
@click.option("--github-org",  default="",  help="GitHub org slug override")
def org_cmd(target, domain, github_org):
    """🏢  Organization OSINT — GitHub org, Crunchbase, job postings → tech stack inference."""
    from omega_cli.modules import org as og
    og.run(target, domain=domain, github_org=github_org)


# ── v1.4.0 — Finance + Dark Web + OSINT DB + STIX + Firmware + Timeline ──────

@cli.command("finance")
@click.argument("target")
@click.option("--ticker",  default="",   help="Stock ticker override (e.g. AAPL)")
@click.option("--deep",    is_flag=True, help="Deep mode: insider trades + funding rounds")
def finance_cmd(target, ticker, deep):
    """💰  Financial OSINT — SEC EDGAR, OpenCorporates, Crunchbase, insider trading."""
    from omega_cli.modules import finance as fn
    fn.run(target, ticker=ticker, deep=deep)


@cli.command("deepweb")
@click.argument("query")
@click.option("--check-onion",     default="",  help="Check if a specific .onion URL is live")
@click.option("--monitor-domain",  default="",  help="Check ransomware group victim lists for domain")
def deepweb_cmd(query, check_onion, monitor_domain):
    """🧅  Deep/dark web recon — ransomware feeds, Ahmia, LeakIX, onion availability."""
    from omega_cli.modules import deepweb as dw
    dw.run(query, check_onion=check_onion, monitor_domain=monitor_domain)


@cli.command("osintdb")
@click.argument("action",
                type=click.Choice(["ingest", "search", "stats", "targets", "graph", "export", "clear"]),
                default="stats")
@click.option("--query",  default="", help="Search query (search action)")
@click.option("--target", default="", help="Filter by target")
@click.option("--type",   "ioc_type", default="", help="Filter by IOC type")
@click.option("--format", "fmt", default="table",
              type=click.Choice(["table", "csv", "stix"]),
              show_default=True, help="Export format")
@click.option("--json-file", default="", help="JSON file to ingest")
def osintdb_cmd(action, query, target, ioc_type, fmt, json_file):
    """🗄  OSINT database — SQLite intel store: ingest/search/graph/export all findings."""
    from omega_cli.modules import osintdb as odb
    odb.run(action=action, query=query, target=target,
            ioc_type=ioc_type, export_format=fmt, ingest_file=json_file)


@cli.command("stix")
@click.argument("target")
@click.option("--json-file", default="",      help="Path to omega recon JSON to convert")
@click.option("--output",    default="",      help="Output STIX bundle file path")
@click.option("--tlp",       default="white",
              type=click.Choice(["white", "green", "amber", "red"]),
              show_default=True, help="TLP marking level")
@click.option("--no-indicators", is_flag=True, help="Omit indicator objects (observables only)")
def stix_cmd(target, json_file, output, tlp, no_indicators):
    """📦  STIX 2.1 export — convert omega findings to threat intel bundle (MISP/OpenCTI/TheHive)."""
    from omega_cli.modules import stix as sx
    sx.run(target, json_file=json_file, output=output,
           tlp=tlp, include_indicators=not no_indicators)


@cli.command("firmware")
@click.argument("target")
@click.option("--type", "device_type", default="auto",
              type=click.Choice(["auto", "router", "camera", "plc", "printer", "nas", "switch"]),
              show_default=True, help="Device type for default cred lookup")
@click.option("--api-key", default="", envvar="SHODAN_API_KEY", help="Shodan API key")
@click.option("--query",   default="", help="Custom Shodan search query")
def firmware_cmd(target, device_type, api_key, query):
    """📡  Firmware/IoT OSINT — Shodan device search, default creds DB, CVE mapping."""
    from omega_cli.modules import firmware as fw
    from omega_cli.config import load
    cfg = load()
    fw.run(target, query=query, api_key=api_key or cfg.get("shodan_api_key", ""))


@cli.command("timeline3d")
@click.argument("target")
@click.option("--output",    default="", help="Output HTML file path")
@click.option("--open",      "open_browser", is_flag=True, help="Open in browser after generation")
@click.option("--json-file", default="", help="Load from a specific JSON file")
def timeline3d_cmd(target, output, open_browser, json_file):
    """⏱  3D intelligence timeline — interactive D3.js chronological event graph."""
    from omega_cli.modules import timeline3d as t3
    t3.run(target, output=output, open_browser=open_browser, json_file=json_file)


# ── v1.5.0 — Risk + Exfil + Persona + Cloud + Code + Threat Feeds ────────────

@cli.command("riskcore")
@click.argument("target")
@click.option("--json-file",    default="", help="Specific JSON file to analyse")
@click.option("--report-dir",   default="", help="Directory of omega JSON reports")
def riskcore_cmd(target, json_file, report_dir):
    """🎯  Risk scoring engine — weighted CVSS-like risk matrix from all omega findings."""
    from omega_cli.modules import riskcore as rc
    rc.run(target, report_dir=report_dir, json_file=json_file)


@cli.command("exfil")
@click.argument("target")
@click.option("--no-live",       is_flag=True, help="Skip live DNS tunnel checks")
@click.option("--no-subdomains", is_flag=True, help="Skip passive DNS subdomain fetch")
def exfil_cmd(target, no_live, no_subdomains):
    """🕵  Exfiltration & C2 detection — DNS tunnel entropy, DGA detection, URLhaus check."""
    from omega_cli.modules import exfil as ex
    ex.run(target, live=not no_live, subdomain_check=not no_subdomains)


@cli.command("persona")
@click.option("--seed",    default="",      help="Deterministic seed for reproducible persona")
@click.option("--gender",  default="random",
              type=click.Choice(["random", "m", "f"]),
              show_default=True, help="Gender")
@click.option("--country", default="",      help="Country code (US, GB, DE, CA, AU, NL, FR, SE)")
@click.option("--count",   default=1,       show_default=True, help="Number of personas to generate")
@click.option("--export",  is_flag=True,    help="Save to ~/.omega/reports/")
def persona_cmd(seed, gender, country, count, export):
    """🎭  OpSec persona builder — generate realistic fictitious identity for red team / OSINT."""
    from omega_cli.modules import persona as pe
    pe.run(action="new", seed=seed, gender=gender, country=country,
           count=count, export=export)


@cli.command("cloud2")
@click.argument("target")
@click.option("--deep",          is_flag=True, help="Extended bucket permutation list + metadata endpoints")
@click.option("--github-token",  default="", envvar="GITHUB_TOKEN", help="GitHub PAT")
@click.option("--skip-buckets",  is_flag=True, help="Skip cloud storage enumeration")
def cloud2_cmd(target, deep, github_token, skip_buckets):
    """☁  Deep cloud recon — S3/GCS/Azure blob enum, GitHub Actions workflows, cloud detection."""
    from omega_cli.modules import cloud2 as cl
    cl.run(target, deep=deep, github_token=github_token, skip_buckets=skip_buckets)


@cli.command("codetrace")
@click.argument("target")
@click.option("--token",  default="", envvar="GITHUB_TOKEN", help="GitHub PAT")
@click.option("--repo",   default="",  help="Specific repo to analyse (default: most-starred)")
@click.option("--deep",   is_flag=True, help="Fetch 100 commits instead of 50")
def codetrace_cmd(target, token, repo, deep):
    """🔍  Code attribution — commit timezone analysis, language fingerprint, geography inference."""
    from omega_cli.modules import codetrace as ct
    ct.run(target, token=token, repo=repo, deep=deep)


@cli.command("threatfeed")
@click.argument("action",
                type=click.Choice(["list", "fetch", "search"]),
                default="list")
@click.option("--feed",   default="", help="Feed(s) to fetch: feodo,urlhaus,threatfox,sslbl,bazaar")
@click.option("--query",  default="", help="IOC to search across feeds")
@click.option("--limit",  default=20, show_default=True, help="Results per feed")
@click.option("--export", default="", help="Export results to JSON file path")
def threatfeed_cmd(action, feed, query, limit, export):
    """📡  Threat feed manager — Feodo C2, URLhaus, ThreatFox, SSLBL, MalwareBazaar."""
    from omega_cli.modules import threatfeed as tf
    tf.run(action=action, feed=feed, query=query, limit=limit, export=export)


# ── v1.6.0 — Phone + Image + Doc + Autocorr + Briefing + Vuln2 ───────────────

@cli.command("phoneosint")
@click.argument("number")
@click.option("--api-key",      default="", envvar="NUMVERIFY_API_KEY", help="NumVerify API key")
@click.option("--abstract-key", default="", envvar="ABSTRACT_API_KEY",  help="Abstract phone API key")
def phoneosint_cmd(number, api_key, abstract_key):
    """📞  Phone OSINT — carrier, line type, region, CNAM caller ID, spam score."""
    from omega_cli.modules import phoneosint as ph
    ph.run(number, api_key=api_key, abstract_key=abstract_key)


@cli.command("imgosint")
@click.argument("image_path")
@click.option("--raw", is_flag=True, help="Show all raw EXIF tags")
def imgosint_cmd(image_path, raw):
    """🖼  Image OSINT — EXIF metadata, GPS extraction, reverse search links, steganography hints."""
    from omega_cli.modules import imgosint as ig
    ig.run(image_path, show_raw=raw)


@cli.command("docosint")
@click.argument("file_path")
@click.option("--no-urls",    is_flag=True, help="Skip embedded URL extraction")
@click.option("--no-secrets", is_flag=True, help="Skip secret pattern scan")
def docosint_cmd(file_path, no_urls, no_secrets):
    """📄  Document OSINT — PDF/Office metadata, author, embedded URLs, secrets, revision history."""
    from omega_cli.modules import docosint as dc
    dc.run(file_path, show_urls=not no_urls, show_secrets=not no_secrets)


@cli.command("autocorr")
@click.argument("target")
@click.option("--min-modules", default=2, show_default=True, help="Min modules an IOC must appear in")
@click.option("--graph",       is_flag=True, help="Show Rich tree graph of correlations")
@click.option("--report-dir",  default="", help="Directory of omega JSON reports")
def autocorr_cmd(target, min_modules, graph, report_dir):
    """🔗  Auto-correlation — cross-reference all omega findings, surface shared IOCs across modules."""
    from omega_cli.modules import autocorr as ac
    ac.run(target, report_dir=report_dir, min_modules=min_modules, show_graph=graph)


@cli.command("briefing")
@click.argument("target")
@click.option("--hours",       default=168, show_default=True, help="Look back N hours for reports")
@click.option("--format", "fmt", default="html",
              type=click.Choice(["html", "md", "both"]),
              show_default=True, help="Output format")
@click.option("--output",      default="", help="Output file path")
@click.option("--open",        "open_browser", is_flag=True, help="Open HTML in browser")
@click.option("--report-dir",  default="", help="Directory of omega JSON reports")
def briefing_cmd(target, hours, fmt, output, open_browser, report_dir):
    """📋  Intelligence briefing — auto-compile HTML/Markdown brief from all omega findings."""
    from omega_cli.modules import briefing as br
    br.run(target, report_dir=report_dir, output=output,
           hours=hours, fmt=fmt, open_browser=open_browser)


@cli.command("vuln2")
@click.argument("target")
@click.option("--api-key",      default="", envvar="NVD_API_KEY",    help="NVD API key (higher rate limit)")
@click.option("--github-token", default="", envvar="GITHUB_TOKEN",   help="GitHub PAT for PoC search")
@click.option("--no-kev",       is_flag=True, help="Skip CISA KEV check")
@click.option("--no-epss",      is_flag=True, help="Skip EPSS exploit probability")
def vuln2_cmd(target, api_key, github_token, no_kev, no_epss):
    """🔴  Advanced vuln intel — NVD CPE search, EPSS exploit probability, CISA KEV, PoC finder."""
    from omega_cli.modules import vuln2 as v2
    v2.run(target, api_key=api_key, github_token=github_token,
           check_kev=not no_kev, epss=not no_epss)


# ── v1.7.0 — WebCrawl + IP Dossier + API OSINT + SocMINT + Crypto + ReportGen ──

@cli.command("webcrawl")
@click.argument("target")
@click.option("--depth",       default=1,  show_default=True, help="Crawl depth")
@click.option("--max-pages",   default=30, show_default=True, help="Max pages to crawl")
@click.option("--no-secrets",  is_flag=True, help="Skip secret pattern scan")
@click.option("--export",      default="", help="Export JSON to path")
def webcrawl_cmd(target, depth, max_pages, no_secrets, export):
    """🕷  Smart web crawler — forms, JS endpoints, comments, robots/sitemap, secret detection."""
    from omega_cli.modules import webcrawl as wc
    wc.run(target, depth=depth, max_pages=max_pages, show_secrets=not no_secrets, export=export)


@cli.command("ipdossier")
@click.argument("target")
@click.option("--api-key", default="", envvar="ABUSEIPDB_KEY", help="AbuseIPDB API key")
@click.option("--export",  default="", help="Export JSON to path")
def ipdossier_cmd(target, api_key, export):
    """🌐  IP dossier — PTR, ASN, BGP peers, Shodan, abuse contacts, 8-DNSBL blacklist check."""
    from omega_cli.modules import ipdossier as ipd
    ipd.run(target, api_key=api_key, export=export)


@cli.command("apiosint")
@click.argument("target")
@click.option("--deep",   is_flag=True, help="Deep JS source mining")
@click.option("--export", default="", help="Export JSON to path")
def apiosint_cmd(target, deep, export):
    """⚙  API OSINT — Swagger/OpenAPI discovery, GraphQL introspection, REST endpoint finder."""
    from omega_cli.modules import apiosint as api
    api.run(target, deep=deep, export=export)


@cli.command("socmint")
@click.argument("username")
@click.option("--email",  default="", help="Email address for breach checks")
@click.option("--deep",   is_flag=True, help="Deep profile scraping")
@click.option("--export", default="", help="Export JSON to path")
def socmint_cmd(username, email, deep, export):
    """👤  Social OSINT — 25-platform username search, GitHub/Reddit/HN profile aggregation."""
    from omega_cli.modules import socmint as sm
    sm.run(username, email=email, deep=deep, export=export)


@cli.command("cryptoosint")
@click.argument("address")
@click.option("--chain",   default="auto", type=click.Choice(["auto","btc","eth"]), show_default=True)
@click.option("--api-key", default="", envvar="ETHERSCAN_API_KEY", help="Etherscan API key")
@click.option("--export",  default="", help="Export JSON to path")
def cryptoosint_cmd(address, chain, api_key, export):
    """₿  Blockchain OSINT — BTC/ETH tx history, mixing detection, sanctions, exchange ID."""
    from omega_cli.modules import cryptoosint as co
    co.run(address, chain=chain, api_key=api_key, export=export)


@cli.command("reportgen")
@click.argument("target")
@click.option("--hours",      default=0,   show_default=True, help="Limit to reports from last N hours (0=all)")
@click.option("--format", "fmt", default="html", type=click.Choice(["html","md","pdf","both"]), show_default=True)
@click.option("--output",     default="",  help="Output base path (no extension)")
@click.option("--open",       "open_browser", is_flag=True, help="Open HTML report in browser")
@click.option("--report-dir", default="",  help="Directory of omega JSON reports")
def reportgen_cmd(target, hours, fmt, output, open_browser, report_dir):
    """📊  Master report — aggregate ALL omega findings into a professional HTML/Markdown/PDF report."""
    from omega_cli.modules import reportgen as rg
    rg.run(target, report_dir=report_dir, output=output, hours=hours, fmt=fmt, open_browser=open_browser)


# ── v1.8.0 — AI Summary + ATT&CK + DNS Brute + PasteWatch + Tor + CVSSRank ──

@cli.command("aisummary")
@click.argument("target")
@click.option("--hours",        default=0,        show_default=True, help="Limit to last N hours of reports (0=all)")
@click.option("--ollama-model", default="llama3",  show_default=True, help="Ollama model name")
@click.option("--openai-key",   default="",        envvar="OPENAI_API_KEY", help="OpenAI API key fallback")
@click.option("--report-dir",   default="",        help="Directory of omega JSON reports")
@click.option("--export",       default="",        help="Export JSON to path")
def aisummary_cmd(target, hours, ollama_model, openai_key, report_dir, export):
    """🤖  AI findings summarizer — Ollama (local) or OpenAI to generate threat intel brief from all omega findings."""
    from omega_cli.modules import aisummary as ai
    ai.run(target, report_dir=report_dir, hours=hours,
           openai_key=openai_key, ollama_model=ollama_model, export=export)


@cli.command("attackmap")
@click.argument("target")
@click.option("--heatmap",    is_flag=True, help="Generate ATT&CK heatmap HTML")
@click.option("--report-dir", default="",  help="Directory of omega JSON reports")
@click.option("--export",     default="",  help="Export JSON to path")
def attackmap_cmd(target, heatmap, report_dir, export):
    """⚔  MITRE ATT&CK mapper — map omega findings to ATT&CK techniques and tactics."""
    from omega_cli.modules import attackmap as am
    am.run(target, report_dir=report_dir, export=export, heatmap=heatmap)


@cli.command("dnsbrute")
@click.argument("domain")
@click.option("--wordlist",    default="",  help="Path to custom subdomain wordlist")
@click.option("--threads",     default=50,  show_default=True, help="Concurrent threads")
@click.option("--no-axfr",     is_flag=True, help="Skip zone transfer attempt")
@click.option("--export",      default="",  help="Export JSON to path")
def dnsbrute_cmd(domain, wordlist, threads, no_axfr, export):
    """💥  DNS bruteforce — subdomain enum with wildcard detection and zone transfer attempt."""
    from omega_cli.modules import dnsbrute as db
    db.run(domain, wordlist_file=wordlist, threads=threads, zone_xfr=not no_axfr, export=export)


@cli.command("pastewatch")
@click.argument("target")
@click.option("--github-token", default="", envvar="GITHUB_TOKEN", help="GitHub PAT for higher API limits")
@click.option("--deep",         is_flag=True, help="Fetch pastes and check for sensitive content")
@click.option("--export",       default="",  help="Export JSON to path")
def pastewatch_cmd(target, github_token, deep, export):
    """📋  Paste watcher — search GitHub Gists, pastebin, grep.app for target data leaks."""
    from omega_cli.modules import pastewatch as pw
    pw.run(target, github_token=github_token, deep=deep, export=export)


@cli.command("torcheck")
@click.argument("target")
@click.option("--probe",       is_flag=True, help="Probe .onion via Tor2Web gateways")
@click.option("--no-relay",    is_flag=True, help="Skip Tor exit node check")
@click.option("--no-darknet",  is_flag=True, help="Skip Ahmia darknet search")
@click.option("--export",      default="",   help="Export JSON to path")
def torcheck_cmd(target, probe, no_relay, no_darknet, export):
    """🧅  Tor intelligence — exit node check, .onion probe, Onionoo relay lookup, Ahmia darknet search."""
    from omega_cli.modules import torcheck as tc
    tc.run(target, check_relay=not no_relay, probe_onion=probe,
           search_darknet=not no_darknet, export=export)


@cli.command("cvssrank")
@click.argument("cves", default="")
@click.option("--file",    default="",  help="File containing CVE IDs (one per line or free text)")
@click.option("--top",     default=0,   show_default=True, help="Show only top N results (0=all)")
@click.option("--api-key", default="",  envvar="NVD_API_KEY", help="NVD API key (higher rate limit)")
@click.option("--export",  default="",  help="Export JSON to path")
def cvssrank_cmd(cves, file, top, api_key, export):
    """📊  Bulk CVE ranker — rank by CVSS + EPSS exploit probability + CISA KEV for triage prioritization."""
    from omega_cli.modules import cvssrank as cr
    cr.run(cves, api_key=api_key, file=file, top=top, export=export)


if __name__ == "__main__":
    cli()
