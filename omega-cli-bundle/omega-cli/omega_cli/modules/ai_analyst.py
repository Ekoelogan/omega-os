"""AI-powered attack surface analysis. Works with OpenAI API or local Ollama."""
import json
import requests
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.spinner import Spinner
from rich.live import Live

console = Console()


def _call_ollama(prompt: str, model: str = "llama3") -> str:
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=120,
        )
        if r.status_code == 200:
            return r.json().get("response", "")
        return f"[Ollama error {r.status_code}]"
    except Exception as e:
        return f"[Ollama unavailable: {e}]"


def _call_openai(prompt: str, api_key: str, model: str = "gpt-4o-mini") -> str:
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": (
                    "You are an expert penetration tester and OSINT analyst. "
                    "Analyze the provided reconnaissance data and produce a structured "
                    "attack surface report with: Executive Summary, Critical Findings, "
                    "Attack Vectors, Recommended Exploits/Tests, and Remediation Priority. "
                    "Use Markdown formatting. Be technical, concise, and actionable."
                )},
                {"role": "user", "content": prompt},
            ],
            max_tokens=2000,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"[OpenAI error: {e}]"


def run_ai_analysis(target: str, findings: dict, provider: str = "ollama",
                    api_key: str = "", model: str = "") -> str:
    """Run AI analysis on aggregated OSINT findings."""
    prompt = f"""TARGET: {target}

RECON FINDINGS:
{json.dumps(findings, indent=2, default=str)[:8000]}

Analyze this OSINT data and provide a structured penetration testing attack surface report.
Identify the most critical security issues, likely attack vectors, and prioritized recommendations."""

    with Live(Spinner("dots", text="[bold #ff2d78]AI analysing attack surface...[/]"), refresh_per_second=10):
        if provider == "openai" and api_key:
            result = _call_openai(prompt, api_key, model or "gpt-4o-mini")
        else:
            result = _call_ollama(prompt, model or "llama3")

    return result


def run(target: str, findings: dict, provider: str = "ollama",
        api_key: str = "", model: str = ""):
    """Run AI-powered attack surface analysis."""
    console.print(Panel(
        f"[bold #ff2d78]🤖 AI Attack Surface Analysis[/]\n"
        f"[dim]Target:[/] [cyan]{target}[/]  [dim]Provider:[/] [yellow]{provider}[/]",
        border_style="#ff85b3",
    ))

    result = run_ai_analysis(target, findings, provider, api_key, model)

    if not result or result.startswith("["):
        console.print(f"[red]{result}[/]")
        if provider == "ollama":
            console.print("\n[yellow]Tip:[/] Install Ollama → https://ollama.ai  then run: [cyan]ollama pull llama3[/]")
            console.print("Or set OpenAI key: [cyan]omega config set openai_api_key YOUR_KEY[/]")
        return {"error": result}

    console.print(Panel(Markdown(result), title="[bold #ff2d78]AI Report[/]", border_style="#ff85b3"))
    return {"analysis": result, "target": target, "provider": provider}
