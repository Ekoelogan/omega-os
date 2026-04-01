"""Config manager — API keys and user preferences."""
import json
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

CONFIG_PATH = Path.home() / ".config" / "omega-cli" / "config.json"

DEFAULTS = {
    "abuseipdb_api_key": "",
    "shodan_api_key": "",
    "hibp_api_key": "",
    "virustotal_api_key": "",
    "openai_api_key": "",
    "nvd_api_key": "",
    "github_token": "",
    "discord_webhook": "",
    "slack_webhook": "",
    "telegram_token": "",
    "telegram_chat": "",
    "urlscan_api_key": "",
    "gsb_api_key": "",
    "output_dir": str(Path.home() / "omega-reports"),
    "default_port_scan": "common",
    "subdomain_threads": 50,
    "wayback_limit": 500,
}


def load() -> dict:
    """Load config, merging with defaults."""
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    # Environment variables override config file
    env_map = {
        "ABUSEIPDB_API_KEY": "abuseipdb_api_key",
        "SHODAN_API_KEY": "shodan_api_key",
        "HIBP_API_KEY": "hibp_api_key",
        "VIRUSTOTAL_API_KEY": "virustotal_api_key",
        "OPENAI_API_KEY": "openai_api_key",
        "NVD_API_KEY": "nvd_api_key",
    }
    for env_key, cfg_key in env_map.items():
        if os.environ.get(env_key):
            cfg[cfg_key] = os.environ[env_key]
    return cfg


def save(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def show():
    """Print current config."""
    cfg = load()
    table = Table(title=f"Config — {CONFIG_PATH}", show_header=True)
    table.add_column("Key", style="bold yellow")
    table.add_column("Value", style="cyan")
    for k, v in cfg.items():
        display = ("*" * 8 + str(v)[-4:]) if ("key" in k and v) else str(v)
        table.add_row(k, display)
    console.print(table)
