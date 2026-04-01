"""Technology fingerprinting — detect CMS, frameworks, WAFs, analytics."""
import httpx
import re
from rich.console import Console
from rich.table import Table

console = Console()

# (pattern_source, regex_or_string, tech_name, category)
SIGNATURES = [
    # CMS
    ("header", "x-powered-by", r"WordPress", "WordPress", "CMS"),
    ("body",   None, r'wp-content|wp-includes|/wp-json/', "WordPress", "CMS"),
    ("body",   None, r'Joomla|joomla', "Joomla", "CMS"),
    ("body",   None, r'Drupal.settings|drupal\.js|Drupal', "Drupal", "CMS"),
    ("body",   None, r'shopify|cdn\.shopify\.com', "Shopify", "CMS"),
    ("body",   None, r'ghost\.org|ghost-theme', "Ghost", "CMS"),
    ("body",   None, r'squarespace\.com|static1\.squarespace', "Squarespace", "CMS"),
    ("body",   None, r'wix\.com|X-Wix-', "Wix", "CMS"),
    ("header", "x-powered-by", r"PHP", "PHP", "Language"),
    ("header", "x-powered-by", r"ASP\.NET", "ASP.NET", "Framework"),
    ("header", "x-aspnet-version", None, "ASP.NET", "Framework"),
    # JS Frameworks
    ("body",   None, r'react(?:\.min)?\.js|__REACT|data-reactroot', "React", "JS Framework"),
    ("body",   None, r'vue(?:\.min)?\.js|__vue__|Vue\.config', "Vue.js", "JS Framework"),
    ("body",   None, r'angular(?:\.min)?\.js|ng-version|ng-app', "Angular", "JS Framework"),
    ("body",   None, r'jquery(?:\.min)?\.js|jQuery v', "jQuery", "JS Library"),
    ("body",   None, r'next(?:\.js)?|__NEXT_DATA__', "Next.js", "JS Framework"),
    ("body",   None, r'nuxt|__NUXT__', "Nuxt.js", "JS Framework"),
    # CDN / Hosting
    ("header", "server", r"cloudflare", "Cloudflare", "CDN/WAF"),
    ("header", "server", r"AmazonS3", "Amazon S3", "Hosting"),
    ("header", "server", r"nginx", "nginx", "Web Server"),
    ("header", "server", r"Apache", "Apache", "Web Server"),
    ("header", "server", r"Microsoft-IIS", "IIS", "Web Server"),
    ("header", "server", r"LiteSpeed", "LiteSpeed", "Web Server"),
    ("header", "x-cache", r"cloudfront", "CloudFront", "CDN"),
    ("header", "via",    r"varnish", "Varnish", "Cache"),
    ("header", "x-varnish", None, "Varnish", "Cache"),
    # WAF
    ("header", "x-sucuri-id", None, "Sucuri WAF", "WAF"),
    ("header", "x-fw-hash", None, "Fortinet WAF", "WAF"),
    ("header", "x-waf-", None, "WAF Detected", "WAF"),
    ("cookie", "incap_ses|visid_incap", None, "Imperva/Incapsula", "WAF"),
    ("cookie", "__cfduid|cf_clearance", None, "Cloudflare", "CDN/WAF"),
    # Analytics / Marketing
    ("body",   None, r'google-analytics\.com|gtag\(|ga\(', "Google Analytics", "Analytics"),
    ("body",   None, r'googletagmanager\.com', "Google Tag Manager", "Analytics"),
    ("body",   None, r'connect\.facebook\.net', "Facebook Pixel", "Analytics"),
    ("body",   None, r'hotjar\.com', "Hotjar", "Analytics"),
    ("body",   None, r'segment\.com/analytics', "Segment", "Analytics"),
    # Security
    ("header", "strict-transport-security", None, "HSTS Enabled", "Security"),
    ("header", "content-security-policy", None, "CSP Enabled", "Security"),
]


def run(target: str):
    """Detect technologies used by a web target."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    console.print(f"\n[bold cyan][ TECH FINGERPRINT ] {target}[/bold cyan]\n")

    try:
        with httpx.Client(follow_redirects=True, timeout=10,
                          headers={"User-Agent": "Mozilla/5.0 (omega-cli)"}) as client:
            r = client.get(target)

        body = r.text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        cookies = " ".join(r.cookies.keys()).lower()

        detected = {}

        for source, key, pattern, tech, category in SIGNATURES:
            if tech in detected:
                continue
            match = False
            if source == "body":
                match = bool(re.search(pattern, body, re.I)) if pattern else False
            elif source == "header":
                hval = headers_lower.get(key, "")
                match = bool(re.search(pattern, hval, re.I)) if pattern else bool(hval)
            elif source == "cookie":
                match = bool(re.search(key, cookies, re.I)) if key else False

            if match:
                detected[tech] = category

        if detected:
            by_category = {}
            for tech, cat in detected.items():
                by_category.setdefault(cat, []).append(tech)

            table = Table(title="Detected Technologies", show_header=True)
            table.add_column("Category", style="bold yellow")
            table.add_column("Technology", style="cyan")
            for cat in sorted(by_category):
                table.add_row(cat, ", ".join(by_category[cat]))
            console.print(table)
        else:
            console.print("[yellow]No technologies fingerprinted.[/yellow]")

        return detected

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        return {}
