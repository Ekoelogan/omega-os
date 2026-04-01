"""omega org — Organization OSINT: job postings → tech stack, Crunchbase, org structure inference."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.tree import Tree

console = Console()
TIMEOUT = 10

# Job posting tech stack patterns
TECH_PATTERNS = {
    "Languages": {
        "Python": r"\bpython\b",
        "Go":     r"\bgolang\b|\bgo lang\b|\b\.go\b",
        "Rust":   r"\brust\b",
        "Java":   r"\bjava\b(?!script)",
        "Kotlin": r"\bkotlin\b",
        "Swift":  r"\bswift\b",
        "C++":    r"\bc\+\+\b|\bcpp\b",
        "C#":     r"\bc#\b|\bdotnet\b|\.net",
        "Ruby":   r"\bruby\b|\brails\b",
        "PHP":    r"\bphp\b",
        "Scala":  r"\bscala\b",
        "JavaScript": r"\bjavascript\b|\bnode\.?js\b|\bnodejs\b",
        "TypeScript": r"\btypescript\b",
        "Elixir": r"\belixir\b",
    },
    "Frameworks": {
        "React":      r"\breact\b|\breact\.js\b",
        "Vue":        r"\bvue\b|\bvuejs\b",
        "Angular":    r"\bangular\b",
        "Django":     r"\bdjango\b",
        "FastAPI":    r"\bfastapi\b",
        "Spring":     r"\bspring\b(?!\s+cleaning)",
        "Rails":      r"\bruby on rails\b|\brails\b",
        "Laravel":    r"\blaravel\b",
        "Express":    r"\bexpress\.?js\b",
        "Next.js":    r"\bnext\.?js\b",
        "GraphQL":    r"\bgraphql\b",
    },
    "Databases": {
        "PostgreSQL": r"\bpostgres(?:ql)?\b",
        "MySQL":      r"\bmysql\b",
        "MongoDB":    r"\bmongodb\b|\bmongo\b",
        "Redis":      r"\bredis\b",
        "Elasticsearch": r"\belasticsearch\b|\belastic\b",
        "Cassandra":  r"\bcassandra\b",
        "DynamoDB":   r"\bdynamodb\b",
        "ClickHouse": r"\bclickhouse\b",
        "Snowflake":  r"\bsnowflake\b",
        "BigQuery":   r"\bbigquery\b",
    },
    "Cloud": {
        "AWS":        r"\baws\b|\bamazon web services\b",
        "GCP":        r"\bgcp\b|\bgoogle cloud\b",
        "Azure":      r"\bazure\b|\bmicrosoft azure\b",
        "Kubernetes": r"\bkubernetes\b|\bk8s\b",
        "Docker":     r"\bdocker\b",
        "Terraform":  r"\bterraform\b",
        "Helm":       r"\bhelm\b",
        "Ansible":    r"\bansible\b",
        "GitLab CI":  r"\bgitlab\s*ci\b",
        "GitHub Actions": r"\bgithub\s*actions\b",
    },
    "Security": {
        "SIEM":       r"\bsiem\b",
        "SOC":        r"\bsoc\b",
        "SAST":       r"\bsast\b",
        "DAST":       r"\bdast\b",
        "Splunk":     r"\bsplunk\b",
        "CrowdStrike":r"\bcrowdstrike\b",
        "Okta":       r"\bokta\b",
        "Zero Trust": r"\bzero.?trust\b",
        "Bug Bounty": r"\bbug.?bounty\b",
    },
}


def _search_jobs(company: str) -> list[dict]:
    """Search for job postings via public APIs."""
    results = []

    # Search GitHub Jobs (via alternative source)
    try:
        r = httpx.get(
            "https://remoteok.com/api",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            jobs = r.json()
            company_lower = company.lower()
            for job in jobs:
                if isinstance(job, dict) and company_lower in (job.get("company", "") or "").lower():
                    results.append({
                        "title": job.get("position", "?"),
                        "company": job.get("company", "?"),
                        "tags": job.get("tags", []),
                        "description": (job.get("description") or "")[:300],
                        "url": job.get("url", ""),
                        "date": job.get("date", ""),
                    })
    except Exception:
        pass

    # HackerNews "Who is hiring?" thread search
    try:
        r2 = httpx.get(
            "https://hn.algolia.com/api/v1/search",
            params={
                "query": company,
                "tags": "ask_hn",
                "restrictSearchableAttributes": "comment_text",
                "hitsPerPage": 5,
            },
            timeout=TIMEOUT,
        )
        if r2.status_code == 200:
            for hit in r2.json().get("hits", [])[:5]:
                text = hit.get("comment_text") or hit.get("story_text") or ""
                if company.lower() in text.lower():
                    results.append({
                        "title": "HN Hiring",
                        "company": company,
                        "description": text[:400],
                        "url": f"https://news.ycombinator.com/item?id={hit.get('objectID')}",
                        "tags": [],
                    })
    except Exception:
        pass

    return results[:20]


def _extract_tech_from_text(text: str) -> dict[str, list[str]]:
    """Extract tech stack from job posting text."""
    text_lower = text.lower()
    found: dict[str, list[str]] = {}
    for category, techs in TECH_PATTERNS.items():
        for tech, pattern in techs.items():
            if re.search(pattern, text_lower, re.IGNORECASE):
                found.setdefault(category, []).append(tech)
    return found


def _crunchbase_search(company: str) -> dict:
    """Basic Crunchbase public data via web scraping."""
    result: dict[str, Any] = {}
    try:
        slug = company.lower().replace(" ", "-").replace(".", "")
        r = httpx.get(
            f"https://www.crunchbase.com/organization/{slug}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
            follow_redirects=True,
        )
        if r.status_code == 200:
            body = r.text
            # Extract LD+JSON
            ld_m = re.search(r'<script type="application/ld\+json">(.*?)</script>', body, re.DOTALL)
            if ld_m:
                try:
                    ld = json.loads(ld_m.group(1))
                    result["crunchbase"] = {
                        "name": ld.get("name"),
                        "description": (ld.get("description") or "")[:200],
                        "founded": ld.get("foundingDate"),
                        "employees": ld.get("numberOfEmployees"),
                        "url": ld.get("url"),
                        "linkedin": ld.get("sameAs", [None])[0] if ld.get("sameAs") else None,
                    }
                except Exception:
                    pass
            # Try meta tags
            desc_m = re.search(r'<meta name="description" content="([^"]+)"', body)
            if desc_m and not result.get("crunchbase"):
                result["crunchbase"] = {"description": desc_m.group(1)[:200]}
    except Exception:
        pass
    return result


def _dns_based_tech(domain: str) -> dict[str, list]:
    """Infer tech from DNS records (MX→email provider, TXT→services)."""
    tech: dict[str, list] = {}
    try:
        r = httpx.get(f"https://api.hackertarget.com/dnslookup/?q={domain}", timeout=TIMEOUT)
        if r.status_code == 200 and "error" not in r.text[:30].lower():
            text = r.text
            # MX records → email provider
            if "google" in text.lower() or "googlemail" in text.lower():
                tech.setdefault("Email", []).append("Google Workspace")
            if "outlook" in text.lower() or "microsoft" in text.lower():
                tech.setdefault("Email", []).append("Microsoft 365")
            if "mailgun" in text.lower():
                tech.setdefault("Email", []).append("Mailgun")
            if "sendgrid" in text.lower():
                tech.setdefault("Email", []).append("SendGrid")
            # TXT records → services
            if "v=spf1" in text:
                tech.setdefault("Auth", []).append("SPF configured")
            if "v=DMARC1" in text.lower():
                tech.setdefault("Auth", []).append("DMARC configured")
            if "atlassian" in text.lower():
                tech.setdefault("DevTools", []).append("Atlassian (Jira/Confluence)")
            if "salesforce" in text.lower():
                tech.setdefault("CRM", []).append("Salesforce")
            if "stripe" in text.lower():
                tech.setdefault("Payments", []).append("Stripe")
            if "zendesk" in text.lower():
                tech.setdefault("Support", []).append("Zendesk")
            if "intercom" in text.lower():
                tech.setdefault("Support", []).append("Intercom")
            if "hubspot" in text.lower():
                tech.setdefault("CRM", []).append("HubSpot")
            if "docusign" in text.lower():
                tech.setdefault("Legal", []).append("DocuSign")
            if "okta" in text.lower():
                tech.setdefault("IAM", []).append("Okta")
    except Exception:
        pass
    return tech


def _github_org_info(org: str) -> dict:
    """Fetch public GitHub org info."""
    result: dict[str, Any] = {}
    try:
        r = httpx.get(
            f"https://api.github.com/orgs/{org}",
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            result["github"] = {
                "login": d.get("login"),
                "name": d.get("name"),
                "description": d.get("description"),
                "public_repos": d.get("public_repos"),
                "members_url": d.get("members_url"),
                "blog": d.get("blog"),
                "email": d.get("email"),
                "twitter": d.get("twitter_username"),
                "location": d.get("location"),
                "created_at": d.get("created_at"),
                "followers": d.get("followers"),
            }
    except Exception:
        pass
    return result


def run(target: str, domain: str = "", github_org: str = ""):
    console.print(Panel(
        f"[bold #ff2d78]🏢  Organization OSINT[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    findings: dict[str, Any] = {"target": target}

    # GitHub org info
    gh_slug = github_org or target.lower().replace(" ", "").replace(".", "")
    with console.status("[cyan]Fetching GitHub organization…"):
        gh = _github_org_info(gh_slug)
    findings.update(gh)
    if gh.get("github"):
        g = gh["github"]
        console.print(f"\n[bold]GitHub Org:[/bold] [cyan]{g.get('login')}[/cyan] — "
                      f"{g.get('public_repos')} public repos, {g.get('followers')} followers")
        if g.get("description"):
            console.print(f"  [dim]{g.get('description')}[/dim]")
        if g.get("blog"):
            console.print(f"  🌐 {g.get('blog')}")
        if g.get("twitter"):
            console.print(f"  🐦 @{g.get('twitter')}")
        if g.get("email"):
            console.print(f"  📧 {g.get('email')}")

    # Crunchbase
    with console.status("[cyan]Searching Crunchbase…"):
        cb = _crunchbase_search(target)
    findings.update(cb)
    if cb.get("crunchbase"):
        c = cb["crunchbase"]
        console.print(f"\n[bold]Crunchbase:[/bold]")
        if c.get("name"):
            console.print(f"  {c.get('name')}")
        if c.get("description"):
            console.print(f"  [dim]{c.get('description')[:150]}[/dim]")
        if c.get("founded"):
            console.print(f"  Founded: {c.get('founded')}")

    # DNS-based tech inference
    if domain:
        with console.status("[cyan]DNS-based technology inference…"):
            dns_tech = _dns_based_tech(domain)
        findings["dns_tech"] = dns_tech
        if dns_tech:
            console.print("\n[bold]Inferred Tech (DNS):[/bold]")
            t = Table("Category", "Technology", box=box.SIMPLE_HEAD, header_style="bold cyan")
            for cat, items in dns_tech.items():
                for item in items:
                    t.add_row(cat, item)
            console.print(t)

    # Job posting analysis
    with console.status("[cyan]Searching job postings for tech stack…"):
        jobs = _search_jobs(target)
    findings["jobs"] = jobs
    findings["job_count"] = len(jobs)

    if jobs:
        console.print(f"\n[bold]Job Postings:[/bold] {len(jobs)} found")
        # Aggregate tech across all jobs
        all_tech: dict[str, dict[str, int]] = {}
        for job in jobs:
            desc = job.get("description", "") + " ".join(job.get("tags", []))
            job_tech = _extract_tech_from_text(desc)
            for cat, items in job_tech.items():
                for item in items:
                    all_tech.setdefault(cat, {})[item] = all_tech.get(cat, {}).get(item, 0) + 1

        if all_tech:
            findings["inferred_tech"] = {cat: list(items.keys()) for cat, items in all_tech.items()}
            tree = Tree("[bold yellow]🔧 Tech Stack (inferred from job postings)[/bold yellow]")
            for cat, items in sorted(all_tech.items()):
                branch = tree.add(f"[bold]{cat}[/bold]")
                for tech, count in sorted(items.items(), key=lambda x: -x[1]):
                    branch.add(f"[cyan]{tech}[/cyan] [dim]×{count}[/dim]")
            console.print(tree)

        # Show recent jobs
        t2 = Table("Title", "Company", "Tags",
                   title=f"[bold]Recent Job Postings[/bold]",
                   box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
        for job in jobs[:8]:
            tags = ", ".join(str(tag) for tag in (job.get("tags") or [])[:5])
            t2.add_row(job.get("title", "?")[:40], job.get("company", "?")[:30], tags[:50])
        console.print(t2)
    else:
        console.print("[dim]No job postings found in public sources.[/dim]")

    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"org_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
