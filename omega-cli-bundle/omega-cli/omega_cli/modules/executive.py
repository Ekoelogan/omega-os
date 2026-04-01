"""omega executive — AI-powered executive report: narrative summary + risk ratings + remediation."""
from __future__ import annotations
import json
import os
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

RISK_WEIGHTS: dict[str, int] = {
    "breach":          9,
    "password":        9,
    "phish":           8,
    "malware":         8,
    "c2":              10,
    "cve":             7,
    "vuln":            7,
    "cors":            6,
    "cloud":           6,
    "secret":          8,
    "credential":      8,
    "shodan":          5,
    "subdomain":       3,
    "port":            4,
    "typo":            5,
    "dns":             2,
    "wayback":         1,
}

REMEDIATION: dict[str, str] = {
    "breach":      "Force password resets; enable MFA; notify affected users",
    "password":    "Rotate exposed credentials; enforce strong password policy",
    "phish":       "Deploy DMARC/SPF/DKIM; user awareness training",
    "malware":     "Isolate systems; run endpoint detection; forensic investigation",
    "c2":          "Block C2 IPs/domains at firewall; incident response",
    "cve":         "Patch immediately; apply vendor mitigations",
    "vuln":        "Remediate findings per CVSS score; retest after fix",
    "cors":        "Restrict CORS origins; remove wildcard Access-Control-Allow-Origin",
    "cloud":       "Audit S3/GCS/Azure ACLs; enforce bucket/blob private access",
    "secret":      "Rotate all exposed secrets; audit git history; use secret scanner CI/CD",
    "shodan":      "Reduce public attack surface; restrict unnecessary service exposure",
    "typo":        "Register defensive typosquat domains; monitor for abuse",
    "subdomain":   "Review subdomain inventory; remove stale/unused DNS records",
}


def _score_findings(findings: dict) -> list[dict]:
    """Score findings by severity based on keys present."""
    text = json.dumps(findings).lower()
    scored: list[dict] = []

    for keyword, weight in RISK_WEIGHTS.items():
        if keyword in text:
            count = text.count(keyword)
            scored.append({
                "finding":     keyword,
                "weight":      weight,
                "occurrences": count,
                "risk":        min(weight + (count // 5), 10),
                "remediation": REMEDIATION.get(keyword, "Review and address per security policy"),
            })

    return sorted(scored, key=lambda x: x["risk"], reverse=True)


def _overall_risk(scored: list[dict]) -> tuple[int, str]:
    if not scored:
        return 0, "LOW"
    top_risks = [s["risk"] for s in scored[:5]]
    avg       = sum(top_risks) / len(top_risks)
    score     = min(int(avg * 10), 100)
    if score >= 75:
        return score, "CRITICAL"
    elif score >= 50:
        return score, "HIGH"
    elif score >= 30:
        return score, "MEDIUM"
    else:
        return score, "LOW"


def _ai_narrative(target: str, scored: list[dict], findings: dict,
                  api_key: str = "", model: str = "gpt-3.5-turbo") -> str:
    """Generate narrative using OpenAI or Ollama."""
    findings_summary = ", ".join(f["finding"] for f in scored[:8])
    prompt = (
        f"You are a cybersecurity analyst. Write a concise executive summary (3-4 paragraphs) "
        f"for a security assessment of '{target}'. "
        f"Key findings include: {findings_summary}. "
        f"Include: overview of exposure, top 3 risks, business impact, and immediate actions. "
        f"Use professional, non-technical language suitable for C-suite audience. "
        f"Do not use markdown headers or bullet points."
    )

    # Try OpenAI
    if api_key:
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            resp   = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500,
            )
            return resp.choices[0].message.content.strip()
        except Exception as exc:
            console.print(f"[yellow]OpenAI error:[/yellow] {exc}")

    # Try Ollama (local)
    try:
        import requests
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=30,
        )
        if r.ok:
            return r.json().get("response", "").strip()
    except Exception:
        pass

    return ""


def run(target: str, json_file: str = "", api_key: str = "",
        model: str = "gpt-3.5-turbo", no_ai: bool = False) -> None:
    console.print(Panel(
        f"[bold #ff2d78]📋  Executive Report[/bold #ff2d78]  →  [cyan]{target}[/cyan]",
        expand=False,
    ))

    # Load findings
    if not json_file:
        import glob as glob_mod
        import os as os_
        patterns = [f"omega_auto_{target}_*.json", f"*{target}*.json"]
        files    = []
        for pat in patterns:
            files += glob_mod.glob(pat) + glob_mod.glob(os_.path.expanduser(f"~/{pat}"))
        if files:
            json_file = max(files, key=os_.path.getmtime)
            console.print(f"[dim]Source:[/dim] {json_file}\n")

    findings: dict = {}
    if json_file and Path(json_file).exists():
        findings = json.loads(Path(json_file).read_text())

    scored       = _score_findings(findings) if findings else []
    risk_score, risk_level = _overall_risk(scored)

    color_map = {"CRITICAL": "#ff2d78", "HIGH": "#ff6600", "MEDIUM": "#ffaa00", "LOW": "green"}
    color     = color_map.get(risk_level, "white")

    # Header
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    console.print(f"[bold]Target:[/bold]       [cyan]{target}[/cyan]")
    console.print(f"[bold]Assessment:[/bold]   {now}")
    console.print(f"[bold]Risk Level:[/bold]   [bold {color}]{risk_level}[/bold {color}]  "
                  f"[dim]({risk_score}/100)[/dim]\n")

    # AI Narrative
    if not no_ai:
        narrative = _ai_narrative(target, scored, findings, api_key=api_key, model=model)
        if narrative:
            console.print(Panel(narrative, title="[bold]Executive Summary[/bold]", expand=False))
        else:
            console.print("[dim]AI narrative unavailable (no API key / Ollama not running).[/dim]")
            console.print("[dim]Set: omega config set openai_api_key KEY  or  run: ollama serve[/dim]\n")

    # Findings table
    if scored:
        tbl = Table(title="Risk Findings", show_lines=True)
        tbl.add_column("Finding",     style="bold white",   max_width=18)
        tbl.add_column("Risk",        justify="right",      width=5)
        tbl.add_column("Occurrences", justify="right",      width=12)
        tbl.add_column("Remediation", style="dim",          max_width=50)
        for s in scored[:12]:
            risk_color = "#ff2d78" if s["risk"] >= 8 else ("#ffaa00" if s["risk"] >= 5 else "green")
            tbl.add_row(
                s["finding"],
                f"[bold {risk_color}]{s['risk']}/10[/bold {risk_color}]",
                str(s["occurrences"]),
                s["remediation"],
            )
        console.print(tbl)

        # Priority actions
        console.print("\n[bold]🚨 Immediate Actions (Priority Order):[/bold]")
        for i, s in enumerate(scored[:5], 1):
            console.print(f"  {i}. [bold]{s['finding'].upper()}[/bold] — {s['remediation']}")
    else:
        console.print("[green]✓  No significant risk findings detected.[/green]")
        console.print("[dim]Run [bold]omega auto " + target + "[/bold] for a full assessment.[/dim]")

    console.print(f"\n[dim]Report generated:[/dim] {now}")
    console.print(f"[dim]For full PDF report:[/dim] [bold]omega pdf {target}[/bold]")
