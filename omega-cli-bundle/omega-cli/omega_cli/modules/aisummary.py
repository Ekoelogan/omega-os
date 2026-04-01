"""aisummary.py — AI-powered findings summarizer using local Ollama or OpenAI fallback."""
from __future__ import annotations
import json, os, re, time
from pathlib import Path
from typing import Optional
import urllib.request, urllib.error

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.markdown import Markdown
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **kw): print(*a)
    console = Console()
    Panel = Markdown = None

BANNER = r"""
██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  OMEGA-CLI v1.8.0 — OSINT & Passive Recon Toolkit
"""

SYSTEM_PROMPT = """You are an expert OSINT analyst. You will receive JSON findings from multiple
recon modules. Produce a concise threat intelligence summary with:
1. Executive Summary (3-5 sentences)
2. Key Findings (bullet points, highest severity first)
3. Attack Surface (what's exposed)
4. Recommended Actions (prioritized)
5. Threat Score (0-100)

Be specific, cite module names, use analyst language. No fluff."""


def _load_reports(target: str, report_dir: str = "", hours: int = 0) -> list[dict]:
    search_dir = Path(report_dir) if report_dir else Path.home() / ".omega" / "reports"
    if not search_dir.exists():
        return []
    safe = re.sub(r"[^\w.-]", "_", target)
    cutoff = time.time() - hours * 3600 if hours > 0 else 0
    reports = []
    for f in sorted(search_dir.glob(f"*{safe}*.json")):
        if cutoff and f.stat().st_mtime < cutoff:
            continue
        try:
            data = json.loads(f.read_text())
            module = f.stem.split("_")[0]
            reports.append({"module": module, "data": data})
        except Exception:
            pass
    return reports


def _compact(data: dict, max_chars: int = 800) -> str:
    """Compact a findings dict to a short summary string."""
    lines = []
    for k, v in data.items():
        if k == "target":
            continue
        if isinstance(v, (str, int, float, bool)) and v:
            lines.append(f"{k}: {str(v)[:100]}")
        elif isinstance(v, list) and v:
            sample = v[:3]
            lines.append(f"{k} ({len(v)}): {str(sample)[:150]}")
        elif isinstance(v, dict) and v:
            lines.append(f"{k}: {str(v)[:150]}")
    text = "\n".join(lines)
    return text[:max_chars]


def _call_ollama(prompt: str, model: str = "llama3") -> Optional[str]:
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 800},
    }).encode()
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            resp = json.loads(r.read().decode())
            return resp.get("response", "").strip()
    except Exception:
        return None


def _call_openai(prompt: str, api_key: str, model: str = "gpt-4o-mini") -> Optional[str]:
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 800,
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read().decode())
            return resp["choices"][0]["message"]["content"].strip()
    except Exception:
        return None


def _builtin_summary(reports: list[dict], target: str) -> str:
    """Rule-based fallback when no LLM is available."""
    lines = [f"# OSINT Summary — {target}", ""]
    critical, high, findings = [], [], []

    for r in reports:
        d = r["data"]
        mod = r["module"]
        # Collect key facts
        if d.get("risk_score", 0) >= 70:
            critical.append(f"[{mod}] Risk score {d['risk_score']}/100")
        elif d.get("risk_score", 0) >= 40:
            high.append(f"[{mod}] Risk score {d['risk_score']}/100")
        for vuln in (d.get("vulns") or [])[:3]:
            critical.append(f"[{mod}] Vulnerability: {vuln}")
        if d.get("sanctions"):
            critical.append(f"[{mod}] OFAC SANCTIONED ADDRESS")
        for s in (d.get("secrets") or [])[:2]:
            critical.append(f"[{mod}] Exposed secret in source")
        ports = d.get("ports") or (d.get("shodan_internetdb") or {}).get("ports") or []
        if ports:
            findings.append(f"[{mod}] Open ports: {', '.join(str(p) for p in ports[:8])}")
        if d.get("found") and mod == "socmint":
            findings.append(f"[socmint] Found on {len(d['found'])} platforms")

    lines.append("## Critical")
    lines.extend(f"- 🔴 {c}" for c in critical) or lines.append("- None")
    lines.append("\n## High")
    lines.extend(f"- 🟠 {h}" for h in high) or lines.append("- None")
    lines.append("\n## Findings")
    lines.extend(f"- 🔵 {f}" for f in findings) or lines.append("- None")
    lines.append(f"\n**Modules run:** {', '.join(r['module'] for r in reports)}")
    return "\n".join(lines)


def run(target: str, report_dir: str = "", hours: int = 0,
        openai_key: str = "", ollama_model: str = "llama3",
        export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"🤖  AI Findings Summarizer — {target}", style="bold cyan"))

    reports = _load_reports(target, report_dir=report_dir, hours=hours)
    if not reports:
        console.print("[yellow]⚠ No omega reports found for this target.[/yellow]")
        console.print("[dim]Run some omega modules first, then re-run aisummary.[/dim]")
        return

    console.print(f"[cyan]Loaded {len(reports)} module reports[/cyan]")

    # Build context for LLM
    context_parts = []
    for r in reports:
        compact = _compact(r["data"])
        context_parts.append(f"=== {r['module'].upper()} ===\n{compact}")
    context = "\n\n".join(context_parts)

    user_prompt = (
        f"Target: {target}\n\n"
        f"OSINT Findings from {len(reports)} modules:\n\n"
        f"{context[:6000]}\n\n"
        "Provide your threat intelligence analysis:"
    )

    summary = None

    # Try Ollama first (local, free)
    console.print(f"[dim]Trying Ollama ({ollama_model})...[/dim]")
    summary = _call_ollama(user_prompt, model=ollama_model)
    if summary:
        console.print(f"[green]✓ Generated via Ollama ({ollama_model})[/green]\n")

    # Fallback to OpenAI
    if not summary and openai_key:
        console.print("[dim]Trying OpenAI gpt-4o-mini...[/dim]")
        summary = _call_openai(user_prompt, openai_key)
        if summary:
            console.print("[green]✓ Generated via OpenAI[/green]\n")

    # Final fallback: rule-based
    if not summary:
        console.print("[yellow]⚠ No LLM available — using rule-based summary[/yellow]")
        console.print("[dim]Install Ollama (ollama.ai) or set OPENAI_API_KEY for AI summaries[/dim]\n")
        summary = _builtin_summary(reports, target)

    # Display
    if Markdown:
        console.print(Markdown(summary))
    else:
        console.print(summary)

    # Save
    result = {"target": target, "modules": len(reports), "summary": summary}
    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", target)
    out_path = Path(export) if export else out_dir / f"aisummary_{safe}.json"
    out_path.write_text(json.dumps(result, indent=2))
    console.print(f"\n[dim]Saved → {out_path}[/dim]")
