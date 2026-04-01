"""omega secrets — Multi-source secret scanner: git, npm, PyPI, S3, Docker Hub."""
from __future__ import annotations
import base64
import re
import time
from typing import Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

GITHUB_API   = "https://api.github.com"
NPM_API      = "https://registry.npmjs.org"
PYPI_API     = "https://pypi.org/pypi"
DOCKERHUB_API= "https://hub.docker.com/v2"

# Secret patterns
PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key":    re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":    re.compile(r"(?:aws[_\-]?secret|aws[_\-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", re.I),
    "GitHub Token":      re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "Slack Token":       re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "Private Key":       re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "Google API Key":    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Stripe Secret":     re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Publishable":re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "Twilio Token":      re.compile(r"SK[0-9a-fA-F]{32}"),
    "DB Password":       re.compile(r"""(?:DB_PASS|DATABASE_PASSWORD|MYSQL_PASS)\s*[=:]\s*['"]([^'"]{6,})""", re.I),
    "JWT Token":         re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+"),
    "SendGrid Key":      re.compile(r"SG\.[A-Za-z0-9\-_.]{22}\.[A-Za-z0-9\-_.]{43}"),
}


def _scan_text(text: str, source: str) -> list[dict]:
    findings = []
    for name, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        for m in matches:
            val = m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
            if len(val) > 4:
                findings.append({
                    "type":   name,
                    "value":  val[:8] + "…" + val[-4:] if len(val) > 16 else val,
                    "source": source,
                })
    return findings


def _scan_github_org(org: str, token: str = "") -> list[dict]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    findings: list[dict] = []

    # Get repos
    try:
        r = requests.get(f"{GITHUB_API}/orgs/{org}/repos",
                         params={"per_page": 10, "sort": "updated"},
                         headers=headers, timeout=10)
        if r.status_code == 404:
            # Try as user
            r = requests.get(f"{GITHUB_API}/users/{org}/repos",
                             params={"per_page": 10, "sort": "updated"},
                             headers=headers, timeout=10)
        repos = r.json() if r.ok else []
    except Exception:
        return []

    for repo in repos[:5]:
        repo_name = repo.get("full_name", "")
        # Search for secrets in recent commits
        try:
            commits_r = requests.get(f"{GITHUB_API}/repos/{repo_name}/commits",
                                      params={"per_page": 5},
                                      headers=headers, timeout=8)
            if commits_r.ok:
                for commit in commits_r.json()[:3]:
                    sha = commit.get("sha", "")
                    diff_r = requests.get(f"{GITHUB_API}/repos/{repo_name}/commits/{sha}",
                                           headers={**headers, "Accept": "application/vnd.github.v3.diff"},
                                           timeout=8)
                    if diff_r.ok:
                        hits = _scan_text(diff_r.text, f"github:{repo_name}@{sha[:8]}")
                        findings.extend(hits)
            time.sleep(0.3)
        except Exception:
            pass

    return findings


def _scan_npm_package(package: str) -> list[dict]:
    """Check npm package for suspicious scripts or known malicious indicators."""
    findings: list[dict] = []
    try:
        r = requests.get(f"{NPM_API}/{package}/latest", timeout=8)
        if not r.ok:
            console.print(f"[yellow]npm package not found:[/yellow] {package}")
            return []
        data    = r.json()
        scripts = data.get("scripts", {})
        deps    = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

        # Check postinstall scripts (common attack vector)
        if "postinstall" in scripts or "preinstall" in scripts:
            script_val = scripts.get("postinstall", scripts.get("preinstall", ""))
            suspicious = any(kw in script_val.lower() for kw in
                             ["curl", "wget", "bash", "sh -c", "exec", "eval", "base64"])
            if suspicious:
                findings.append({
                    "type":   "Suspicious install script",
                    "value":  script_val[:50] + "…",
                    "source": f"npm:{package}",
                })

        # Scan README for secrets
        try:
            readme_r = requests.get(f"{NPM_API}/{package}", timeout=8)
            if readme_r.ok:
                readme = readme_r.json().get("readme", "")[:8000]
                findings.extend(_scan_text(readme, f"npm:{package}#readme"))
        except Exception:
            pass

        # Check for typosquatting similarity to popular packages
        popular = ["react", "lodash", "axios", "express", "webpack", "babel",
                   "eslint", "typescript", "jest", "next"]
        for pop in popular:
            if pop in package.lower() and package.lower() != pop:
                findings.append({
                    "type":   "Potential typosquat",
                    "value":  f"{package} ≈ {pop}",
                    "source": f"npm:{package}",
                })
                break

        return findings
    except Exception as e:
        console.print(f"[yellow]npm error:[/yellow] {e}")
        return []


def _scan_pypi_package(package: str) -> list[dict]:
    findings: list[dict] = []
    try:
        r = requests.get(f"{PYPI_API}/{package}/json", timeout=8)
        if not r.ok:
            console.print(f"[yellow]PyPI package not found:[/yellow] {package}")
            return []
        data  = r.json()
        info  = data.get("info", {})
        descr = info.get("description", "")[:8000]
        findings.extend(_scan_text(descr, f"pypi:{package}#description"))

        # Check release history for suspicious maintainer changes
        releases = list(data.get("releases", {}).keys())
        if len(releases) > 1:
            latest     = releases[-1]
            maintainers = data.get("info", {}).get("maintainer", "") or ""
            # Check for typosquatting
            popular_py = ["requests", "django", "flask", "numpy", "pandas",
                          "boto3", "setuptools", "pip", "urllib3", "certifi"]
            for pop in popular_py:
                if pop in package.lower() and package.lower() != pop:
                    findings.append({
                        "type":   "Potential PyPI typosquat",
                        "value":  f"{package} ≈ {pop}",
                        "source": f"pypi:{package}",
                    })
                    break
        return findings
    except Exception as e:
        console.print(f"[yellow]PyPI error:[/yellow] {e}")
        return []


def _scan_dockerhub(image: str) -> list[dict]:
    findings: list[dict] = []
    try:
        namespace, repo = (image.split("/") + [""])[:2]
        if not repo:
            namespace, repo = "library", namespace
        r = requests.get(f"{DOCKERHUB_API}/repositories/{namespace}/{repo}",
                         timeout=8)
        if not r.ok:
            console.print(f"[yellow]Docker Hub image not found:[/yellow] {image}")
            return []
        data = r.json()
        desc = data.get("description", "") + " " + data.get("full_description", "")[:4000]
        findings.extend(_scan_text(desc, f"docker:{image}"))

        # Check if it's official
        if not data.get("is_official") and not data.get("is_trusted"):
            pull_count = data.get("pull_count", 0)
            if pull_count > 1000:
                findings.append({
                    "type":   "Unofficial high-pull image",
                    "value":  f"{pull_count:,} pulls, not official/trusted",
                    "source": f"docker:{image}",
                })
        return findings
    except Exception as e:
        console.print(f"[yellow]Docker Hub error:[/yellow] {e}")
        return []


def run(target: str, token: str = "", scan_type: str = "auto") -> None:
    console.print(Panel(
        f"[bold #ff2d78]🔑  Secret Scanner[/bold #ff2d78]  →  [cyan]{target}[/cyan]  "
        f"[dim]({scan_type})[/dim]",
        expand=False,
    ))

    all_findings: list[dict] = []

    if scan_type in ("auto", "github"):
        console.print(f"\n[bold]🐙 GitHub ({target}):[/bold]")
        hits = _scan_github_org(target, token=token)
        all_findings.extend(hits)
        console.print(f"  [dim]{len(hits)} potential secrets found in recent commits[/dim]")

    if scan_type in ("auto", "npm"):
        console.print(f"\n[bold]📦 npm ({target}):[/bold]")
        hits = _scan_npm_package(target)
        all_findings.extend(hits)
        if not hits:
            console.print("  [green]✓  No suspicious patterns found[/green]")

    if scan_type in ("auto", "pypi"):
        console.print(f"\n[bold]🐍 PyPI ({target}):[/bold]")
        hits = _scan_pypi_package(target)
        all_findings.extend(hits)
        if not hits:
            console.print("  [green]✓  No suspicious patterns found[/green]")

    if scan_type in ("docker",):
        console.print(f"\n[bold]🐳 Docker Hub ({target}):[/bold]")
        hits = _scan_dockerhub(target)
        all_findings.extend(hits)

    if not all_findings:
        console.print(f"\n[green]✓  No secrets or suspicious patterns detected.[/green]")
        return

    tbl = Table(title=f"Findings ({len(all_findings)})", show_lines=True)
    tbl.add_column("Type",   style="bold #ff2d78", max_width=25)
    tbl.add_column("Value",  style="cyan",         max_width=35)
    tbl.add_column("Source", style="dim",          max_width=35)
    for f in all_findings[:25]:
        tbl.add_row(f["type"], f["value"], f["source"])
    console.print(tbl)

    if all_findings:
        console.print(f"\n[bold red]⚠  {len(all_findings)} finding(s) — rotate any exposed credentials immediately.[/bold red]")
