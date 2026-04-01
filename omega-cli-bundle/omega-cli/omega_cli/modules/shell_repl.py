"""Interactive OMEGA REPL shell with autocomplete, history, and inline results."""
import os
import sys
import subprocess
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

HISTORY_FILE = Path.home() / ".config" / "omega-cli" / "shell_history"
HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

COMMANDS = [
    "whois", "dns", "subdomains", "ipinfo", "email", "headers",
    "ssl", "ports", "dorks", "recon", "crtsh", "wayback", "tech",
    "threat", "user", "spoofcheck", "reverseip", "jscan", "crawl",
    "buckets", "cvemap", "dashboard", "ai", "map", "monitor", "notify",
    "config", "report", "help", "exit", "quit",
]

HELP_TEXT = {
    "whois": "whois <domain>       WHOIS lookup",
    "dns": "dns <domain>         DNS records",
    "subdomains": "subdomains <domain>  Subdomain enumeration",
    "ipinfo": "ipinfo <ip>          IP intelligence",
    "email": "email <email>        Email OSINT",
    "headers": "headers <url>        HTTP header analysis",
    "ssl": "ssl <domain>         SSL certificate analysis",
    "ports": "ports <host>         Port scanner",
    "dorks": "dorks <query>        Google dorks generator",
    "crtsh": "crtsh <domain>       Certificate transparency",
    "wayback": "wayback <domain>     Wayback Machine history",
    "tech": "tech <url>           Technology fingerprinting",
    "threat": "threat <ioc>         Threat intelligence",
    "user": "user <username>      Username across platforms",
    "spoofcheck": "spoofcheck <domain>  Email spoofing check",
    "reverseip": "reverseip <ip>       Reverse IP lookup",
    "jscan": "jscan <url>          JavaScript secrets scanner",
    "crawl": "crawl <domain>       Crawl robots.txt/sitemap",
    "buckets": "buckets <name>       Cloud bucket finder",
    "cvemap": "cvemap <tech>        CVE mapper",
    "ai": "ai <target>          AI attack surface analysis",
    "map": "map <domain>         Network asset map",
    "monitor": "monitor <domain>     Continuous monitoring",
    "notify": "notify <provider>    Send notification",
    "dashboard": "dashboard <target>   Live parallel recon",
    "recon": "recon <target>       Full sequential recon",
    "config": "config <action>      Manage configuration",
    "report": "report <target>      Export HTML/JSON report",
}


def _omega_path() -> str:
    """Find the omega executable."""
    import shutil
    path = shutil.which("omega")
    if path:
        return path
    home = os.path.expanduser("~")
    candidates = [
        f"{home}/.local/bin/omega",
        "/usr/local/bin/omega",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return "omega"


def _run_command(cmd: str):
    """Execute an omega sub-command in a subprocess and stream output."""
    omega = _omega_path()
    full_cmd = f"{omega} {cmd}"
    try:
        result = subprocess.run(
            full_cmd, shell=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        print(result.stdout, end="")
        return result.returncode
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")
        return 1


def run():
    """Launch the interactive OMEGA REPL shell."""
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.styles import Style

        style = Style.from_dict({
            "prompt": "#ff2d78 bold",
        })

        completer = WordCompleter(COMMANDS, ignore_case=True)
        session = PromptSession(
            history=FileHistory(str(HISTORY_FILE)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=completer,
        )

        has_prompt_toolkit = True
    except ImportError:
        has_prompt_toolkit = False
        session = None

    console.print(Panel(
        Text.from_markup(
            "[bold #ff2d78]OMEGA SHELL[/]\n"
            "[dim]Interactive OSINT REPL — type [/][cyan]help[/][dim] for commands, [/][yellow]exit[/][dim] to quit[/]\n"
            "[dim]Tab completion and command history enabled[/]"
        ),
        border_style="#ff85b3",
    ))

    while True:
        try:
            if has_prompt_toolkit:
                raw = session.prompt(
                    [("class:prompt", "omega> ")],
                    style=style,
                ).strip()
            else:
                raw = input("\033[1;91momega> \033[0m").strip()

            if not raw:
                continue

            if raw in ("exit", "quit", "q"):
                console.print("[bold #ff2d78]Goodbye.[/]")
                break

            if raw == "help" or raw == "?":
                tbl_text = "\n".join(f"  [cyan]{v}[/]" for v in HELP_TEXT.values())
                console.print(Panel(tbl_text, title="[bold #ff2d78]Commands[/]", border_style="#ff85b3"))
                continue

            if raw.startswith("!"):
                # Direct shell passthrough
                os.system(raw[1:])
                continue

            # Strip leading 'omega' if user typed it
            if raw.startswith("omega "):
                raw = raw[6:]

            _run_command(raw)

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — type exit to quit[/]")
            continue
        except EOFError:
            console.print("\n[bold #ff2d78]Goodbye.[/]")
            break
