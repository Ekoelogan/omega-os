"""omega-cli: OSINT and passive recon toolkit — main entry point."""
import click
from rich.console import Console

console = Console()

BANNER = """[bold magenta]
  ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
[/bold magenta][dim]OSINT & Passive Recon Toolkit v0.3.0[/dim]
"""


@click.group()
@click.version_option("0.3.0", prog_name="omega")
def cli():
    """omega — OSINT and passive recon toolkit."""
    pass


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
    console.print(BANNER)
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
    console.print(BANNER)
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
    console.print(BANNER)


if __name__ == "__main__":
    cli()
