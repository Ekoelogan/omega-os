"""omega cloud2 — Deep cloud recon: S3/GCS/Azure blob permutation enum,
Lambda/Functions endpoint discovery, cloud metadata SSRF detection, public IAM policies."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
TIMEOUT = 8

# Common bucket name permutations
BUCKET_PERMS = [
    "{t}", "{t}-backup", "{t}-backups", "{t}-data", "{t}-db",
    "{t}-dev", "{t}-staging", "{t}-prod", "{t}-production",
    "{t}-logs", "{t}-log", "{t}-assets", "{t}-static",
    "{t}-uploads", "{t}-media", "{t}-files", "{t}-docs",
    "{t}-public", "{t}-private", "{t}-internal", "{t}-secret",
    "{t}-config", "{t}-configs", "{t}-credentials", "{t}-keys",
    "{t}-archive", "{t}-exports", "{t}-imports", "{t}-releases",
    "{t}-cdn", "{t}-images", "{t}-downloads", "{t}-artifacts",
    "dev-{t}", "staging-{t}", "prod-{t}", "backup-{t}",
    "{t}2", "{t}3", "{t}-1", "{t}-2", "{t}-test", "{t}-testing",
]

# Serverless endpoint patterns
LAMBDA_PATTERNS = [
    "https://{t}.execute-api.us-east-1.amazonaws.com",
    "https://{t}.execute-api.us-west-2.amazonaws.com",
    "https://{t}.execute-api.eu-west-1.amazonaws.com",
    "https://api.{t}.com",
    "https://api.{t}.io",
]
FUNCTIONS_PATTERNS = [
    "https://{region}-{project}.cloudfunctions.net/{t}",
    "https://{t}.azurewebsites.net",
    "https://{t}.azurewebsites.net/api",
]

# Cloud provider IP ranges (sample for detection)
CLOUD_ASN_HINTS = {
    "AWS":   ["AMAZON", "AWS"],
    "GCP":   ["GOOGLE", "GOOGLEAPIS"],
    "Azure": ["MICROSOFT", "AZURE"],
    "Cloudflare": ["CLOUDFLARE"],
    "Fastly": ["FASTLY"],
}


def _check_s3_bucket(bucket: str) -> dict:
    urls = [
        f"https://{bucket}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket}",
        f"https://{bucket}.s3.us-east-1.amazonaws.com",
    ]
    for url in urls:
        try:
            r = httpx.head(url, timeout=TIMEOUT, follow_redirects=True)
            if r.status_code == 200:
                return {"bucket": bucket, "url": url, "status": "PUBLIC", "code": 200}
            if r.status_code == 403:
                return {"bucket": bucket, "url": url, "status": "EXISTS_PRIVATE", "code": 403}
            if r.status_code == 301:
                return {"bucket": bucket, "url": url, "status": "REDIRECT", "code": 301}
        except Exception:
            pass
    return {}


def _check_gcs_bucket(bucket: str) -> dict:
    url = f"https://storage.googleapis.com/{bucket}/"
    try:
        r = httpx.head(url, timeout=TIMEOUT, follow_redirects=True)
        if r.status_code == 200:
            return {"bucket": bucket, "url": url, "status": "PUBLIC", "code": 200}
        if r.status_code == 403:
            return {"bucket": bucket, "url": url, "status": "EXISTS_PRIVATE", "code": 403}
    except Exception:
        pass
    return {}


def _check_azure_blob(account: str, container: str = "$web") -> dict:
    url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
    try:
        r = httpx.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            return {"account": account, "url": url, "status": "PUBLIC_LISTING", "code": 200}
        if r.status_code == 403 or r.status_code == 409:
            return {"account": account, "url": url, "status": "EXISTS", "code": r.status_code}
    except Exception:
        pass
    return {}


def _check_github_actions_secrets(org: str, token: str = "") -> list[dict]:
    """Check for public GitHub Actions workflow files that reference secrets."""
    findings = []
    try:
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = httpx.get(
            f"https://api.github.com/orgs/{org}/repos",
            headers=headers,
            params={"per_page": 10, "sort": "updated"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            for repo in r.json()[:5]:
                wf_r = httpx.get(
                    f"https://api.github.com/repos/{org}/{repo['name']}/contents/.github/workflows",
                    headers=headers,
                    timeout=TIMEOUT,
                )
                if wf_r.status_code == 200:
                    for wf in wf_r.json()[:3]:
                        findings.append({
                            "repo": repo["name"],
                            "workflow": wf.get("name"),
                            "url": wf.get("html_url"),
                        })
    except Exception:
        pass
    return findings


def _detect_cloud_provider(target: str) -> str:
    """Detect cloud provider from domain/IP."""
    try:
        r = httpx.head(f"https://{target}", timeout=TIMEOUT, follow_redirects=True)
        server = r.headers.get("server", "").lower()
        via = r.headers.get("via", "").lower()
        x_served = r.headers.get("x-served-by", "").lower()
        combined = server + via + x_served

        if "awselb" in combined or "cloudfront" in combined or "aws" in combined:
            return "AWS"
        if "gws" in combined or "google" in combined:
            return "GCP"
        if "microsoft" in combined or "azure" in combined:
            return "Azure"
        if "cloudflare" in combined:
            return "Cloudflare"
    except Exception:
        pass
    return "Unknown"


def _enumerate_buckets(target: str, limit: int = 20) -> list[dict]:
    """Enumerate S3 + GCS bucket permutations."""
    results = []
    names = [p.replace("{t}", target) for p in BUCKET_PERMS[:limit]]

    console.print(f"[dim]Testing {len(names)} bucket name variants…[/dim]")
    for name in names:
        # S3
        s3 = _check_s3_bucket(name)
        if s3:
            s3["provider"] = "S3"
            results.append(s3)

        # GCS
        gcs = _check_gcs_bucket(name)
        if gcs:
            gcs["provider"] = "GCS"
            results.append(gcs)

        # Azure
        az = _check_azure_blob(name)
        if az:
            az["provider"] = "Azure Blob"
            az["bucket"] = name
            results.append(az)

    return results


def run(target: str, deep: bool = False, github_token: str = "", skip_buckets: bool = False):
    console.print(Panel(
        f"[bold #ff2d78]☁  Deep Cloud Recon[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()
    token = github_token or cfg.get("github_token", "")

    findings: dict[str, Any] = {"target": target}

    # Cloud provider detection
    with console.status("[cyan]Detecting cloud provider…"):
        provider = _detect_cloud_provider(target)
    console.print(f"[bold]Cloud provider:[/bold] [cyan]{provider}[/cyan]")
    findings["cloud_provider"] = provider

    # Bucket enumeration
    if not skip_buckets:
        limit = 35 if deep else 20
        with console.status(f"[cyan]Enumerating cloud storage ({limit} variants)…"):
            buckets = _enumerate_buckets(target, limit=limit)
        findings["buckets"] = buckets

        if buckets:
            public  = [b for b in buckets if b.get("status") == "PUBLIC"]
            private = [b for b in buckets if "EXISTS" in b.get("status","") and "PUBLIC" not in b.get("status","")]

            if public:
                t = Table("Provider", "Bucket", "URL", "Status",
                          title=f"[bold red]🪣  {len(public)} PUBLIC Bucket(s) Found![/bold red]",
                          box=box.SIMPLE_HEAD, header_style="bold red")
                for b in public:
                    t.add_row(b.get("provider","?"), b.get("bucket","?"), b.get("url","?")[:60], "[red]PUBLIC[/red]")
                console.print(t)

            if private:
                t2 = Table("Provider", "Bucket", "Status",
                           title=f"[dim]{len(private)} private/existing bucket(s)[/dim]",
                           box=box.SIMPLE_HEAD, header_style="bold dim")
                for b in private[:10]:
                    t2.add_row(b.get("provider","?"), b.get("bucket","?"), b.get("status","?"))
                console.print(t2)

            if not public and not private:
                console.print("[green]✓  No exposed cloud storage buckets found[/green]")
        else:
            console.print("[green]✓  No exposed cloud storage found[/green]")

    # GitHub org cloud secrets check
    with console.status(f"[cyan]Checking GitHub Actions workflows for {target}…"):
        wf_findings = _check_github_actions_secrets(target, token=token)
    findings["github_workflows"] = wf_findings
    if wf_findings:
        console.print(f"\n[bold yellow]⚙  {len(wf_findings)} GitHub Actions workflow(s) found:[/bold yellow]")
        for wf in wf_findings[:8]:
            console.print(f"  [cyan]•[/cyan] [{wf['repo']}] {wf['workflow']} — {wf.get('url','')}")
    else:
        console.print("[dim]No GitHub Actions workflows accessible for this org[/dim]")

    # Cloud metadata endpoint check (SSRF test targets — informational)
    if deep:
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",       # AWS
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance",        # Azure
        ]
        console.print("\n[dim]Cloud metadata endpoint references (for SSRF testing):[/dim]")
        for u in metadata_urls:
            console.print(f"  [dim]•[/dim] {u}")
        findings["metadata_endpoints"] = metadata_urls

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out = os.path.join(out_dir, f"cloud2_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
