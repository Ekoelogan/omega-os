"""omega aiassist — AI-powered auto-analyst: feed recon JSON → GPT/Ollama → threat narrative + next steps."""
from __future__ import annotations
import json, os, re, glob, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

console = Console()
TIMEOUT = 60


def _load_report(target: str, json_file: str) -> dict[str, Any]:
    if json_file and os.path.exists(json_file):
        with open(json_file) as f:
            return json.load(f)
    report_dir = os.path.expanduser("~/.omega/reports")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    pattern = os.path.join(report_dir, f"*{safe}*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    merged: dict[str, Any] = {"target": target}
    for f in files[:8]:
        try:
            with open(f) as fh:
                data = json.load(fh)
            prefix = os.path.basename(f).split("_")[0]
            merged[prefix] = data
            for k in ("ips", "subdomains", "ports", "technologies", "iocs",
                      "risk_level", "risk_score", "breaches"):
                if k in data and k not in merged:
                    merged[k] = data[k]
        except Exception:
            pass
    return merged


def _build_prompt(report: dict, focus: str) -> str:
    target = report.get("target", "unknown")
    summary_parts = []

    if report.get("ips"):
        summary_parts.append(f"IPs: {', '.join(report['ips'][:5])}")
    if report.get("subdomains"):
        summary_parts.append(f"Subdomains found: {len(report['subdomains'])}")
    if report.get("ports"):
        port_list = [str(p.get("port", p)) if isinstance(p, dict) else str(p)
                     for p in report["ports"][:10]]
        summary_parts.append(f"Open ports: {', '.join(port_list)}")
    if report.get("technologies"):
        techs = report["technologies"]
        if isinstance(techs, list):
            summary_parts.append(f"Technologies: {', '.join(str(t) for t in techs[:10])}")
    if report.get("risk_level"):
        summary_parts.append(f"Risk level: {report['risk_level']} ({report.get('risk_score', '?')}/100)")
    if report.get("breaches"):
        summary_parts.append(f"Breaches: {len(report['breaches'])}")
    if report.get("iocs"):
        iocs = report["iocs"]
        total = iocs.get("total", 0) if isinstance(iocs, dict) else len(iocs)
        if total:
            summary_parts.append(f"IOCs extracted: {total}")

    # Add raw sample data (truncated)
    raw_sample = json.dumps(report, indent=2)[:3000]

    focus_instruction = ""
    if focus == "threat":
        focus_instruction = "Focus on threat actor TTPs, MITRE ATT&CK mapping, and indicators of compromise."
    elif focus == "executive":
        focus_instruction = "Write an executive summary suitable for a CISO or board member. Use plain language, minimize jargon."
    elif focus == "remediation":
        focus_instruction = "Focus on specific remediation steps, prioritized by risk. Include concrete technical actions."
    elif focus == "recon":
        focus_instruction = "Focus on what an attacker could learn from this data and likely attack vectors."

    prompt = f"""You are an expert OSINT analyst and cybersecurity consultant. Analyze the following recon data for target: {target}

## Summary
{chr(10).join('- ' + s for s in summary_parts)}

## Raw Data Sample
```json
{raw_sample}
```

{focus_instruction}

Provide:
1. **Executive Summary** (2-3 sentences)
2. **Key Findings** (bullet points, most critical first)
3. **Risk Assessment** (CRITICAL/HIGH/MEDIUM/LOW with justification)
4. **Attack Surface Analysis** (what an adversary could exploit)
5. **Recommended Next Steps** (prioritized, actionable)
6. **Intelligence Gaps** (what additional data would improve the picture)

Be specific, actionable, and concise. Use markdown formatting."""

    return prompt


def _call_openai(prompt: str, api_key: str, model: str = "gpt-4o-mini") -> str:
    try:
        r = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2000,
                "temperature": 0.3,
            },
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        return f"OpenAI API error: {r.status_code} {r.text[:200]}"
    except Exception as e:
        return f"OpenAI error: {e}"


def _call_ollama(prompt: str, model: str = "llama3.2", host: str = "http://localhost:11434") -> str:
    try:
        r = httpx.post(
            f"{host}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("response", "")
        return f"Ollama error: {r.status_code}"
    except Exception as e:
        return f"Ollama error: {e}"


def _local_analysis(report: dict) -> str:
    """Pure-Python fallback analysis when no AI is available."""
    target = report.get("target", "unknown")
    lines = [f"# OSINT Analysis Report — {target}\n"]
    lines.append(f"*Generated: {datetime.datetime.now():%Y-%m-%d %H:%M}*\n")

    # Executive summary
    lines.append("## Executive Summary\n")
    risk = report.get("risk_level", "UNKNOWN")
    score = report.get("risk_score", 0)
    subs = len(report.get("subdomains", []))
    ports = len(report.get("ports", []))
    lines.append(f"Target **{target}** presents a **{risk}** risk profile (score: {score}/100). "
                 f"Recon identified {subs} subdomains and {ports} open ports.\n")

    # Key findings
    lines.append("## Key Findings\n")
    if report.get("ips"):
        lines.append(f"- **IP Addresses**: {', '.join(report['ips'][:5])}")
    if subs:
        lines.append(f"- **{subs} subdomains** discovered — expanded attack surface")
    if ports:
        lines.append(f"- **{ports} open ports** — potential service exposure")
    if report.get("technologies"):
        techs = report["technologies"]
        if isinstance(techs, list) and techs:
            lines.append(f"- **Technologies**: {', '.join(str(t) for t in techs[:8])}")
    if report.get("breaches"):
        lines.append(f"- ⚠️ **{len(report['breaches'])} breach(es)** found in HIBP")
    if report.get("iocs"):
        iocs = report["iocs"]
        total = iocs.get("total", 0) if isinstance(iocs, dict) else len(iocs)
        if total:
            lines.append(f"- **{total} IOCs** extracted from recon data")

    # Risk assessment
    lines.append(f"\n## Risk Assessment\n**{risk}** — Score: {score}/100\n")
    if report.get("risk_reasons"):
        for r in report["risk_reasons"]:
            lines.append(f"- {r}")

    # Attack surface
    lines.append("\n## Attack Surface Analysis\n")
    if ports:
        lines.append(f"- {ports} open services provide direct entry points")
    if subs:
        lines.append(f"- Subdomains may expose legacy/dev/staging systems")
    if report.get("technologies"):
        lines.append("- Identified technologies may have known CVEs")

    # Next steps
    lines.append("\n## Recommended Next Steps\n")
    lines.append("1. Run `omega ports` for detailed service banner grabbing")
    lines.append("2. Run `omega cve` against identified technologies")
    lines.append("3. Run `omega hunt` for MITRE ATT&CK TTP mapping")
    lines.append("4. Run `omega spider` for web application recon")
    if report.get("breaches"):
        lines.append("5. Run `omega leaked` for credential exposure analysis")

    lines.append("\n## Intelligence Gaps\n")
    lines.append("- Active scanning would reveal additional services")
    lines.append("- Social engineering vectors not assessed")
    lines.append("- Physical security posture unknown")

    return "\n".join(lines)


def run(
    target: str,
    json_file: str = "",
    provider: str = "auto",
    model: str = "",
    focus: str = "general",
    ollama_host: str = "http://localhost:11434",
):
    console.print(Panel(
        f"[bold #ff2d78]🤖  AI OSINT Analyst[/bold #ff2d78] — [cyan]{target}[/cyan] "
        f"[dim][{focus}][/dim]",
        box=box.ROUNDED
    ))

    with console.status("[cyan]Loading recon data…"):
        report = _load_report(target, json_file)

    sources = len([k for k in report if isinstance(report[k], dict)])
    console.print(f"[dim]Loaded {sources} data source(s) for {target}[/dim]\n")

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()

    prompt = _build_prompt(report, focus)
    analysis = ""

    if provider == "auto":
        # Try OpenAI first, then Ollama, then local
        openai_key = cfg.get("openai_api_key", "")
        if openai_key:
            provider = "openai"
        else:
            # Check if Ollama is running
            try:
                r = httpx.get(f"{ollama_host}/api/tags", timeout=3)
                if r.status_code == 200:
                    provider = "ollama"
                else:
                    provider = "local"
            except Exception:
                provider = "local"

    if provider == "openai":
        api_key = cfg.get("openai_api_key", "")
        if not api_key:
            console.print("[yellow]No OpenAI key. Falling back to local analysis.[/yellow]")
            provider = "local"
        else:
            mdl = model or "gpt-4o-mini"
            console.print(f"[dim]Using OpenAI ({mdl})…[/dim]")
            with console.status(f"[cyan]Analyzing with {mdl}…"):
                analysis = _call_openai(prompt, api_key, mdl)

    if provider == "ollama":
        mdl = model or "llama3.2"
        console.print(f"[dim]Using Ollama ({mdl}) at {ollama_host}…[/dim]")
        with console.status(f"[cyan]Analyzing with Ollama {mdl}…"):
            analysis = _call_ollama(prompt, mdl, ollama_host)

    if provider == "local" or not analysis:
        console.print("[dim]Using local rule-based analysis (set openai_api_key for AI analysis).[/dim]")
        analysis = _local_analysis(report)

    console.print("\n")
    console.print(Markdown(analysis))

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"aiassist_{safe}_{ts}.md")
    with open(out_file, "w") as f:
        f.write(analysis)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
