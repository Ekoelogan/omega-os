"""omega deception — Canary token generator for blue team tripwires."""
from __future__ import annotations
import json, os, uuid, hashlib, socket, datetime, re
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()
STORE = os.path.expanduser("~/.omega/canaries.json")


def _load_store() -> dict:
    if os.path.exists(STORE):
        try:
            with open(STORE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"canaries": []}


def _save_store(data: dict):
    os.makedirs(os.path.dirname(STORE), exist_ok=True)
    with open(STORE, "w") as f:
        json.dump(data, f, indent=2)


def _gen_token() -> str:
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32]


def _gen_dns_canary(label: str, domain: str = "") -> dict:
    token = _gen_token()
    if not domain:
        domain = "canarytokens.org"
    fqdn = f"omega-{token[:12]}.{domain}"
    return {
        "type": "dns",
        "token": token,
        "trigger": fqdn,
        "description": label,
        "usage": f"nslookup {fqdn}  # or embed in document/URL",
        "embed_html": f'<img src="http://{fqdn}/tracking.png" width="1" height="1">',
        "embed_email": f"<!-- Track: http://{fqdn} -->",
        "detection": "Monitor DNS logs for queries to this hostname",
    }


def _gen_http_canary(label: str, port: int = 8080) -> dict:
    token = _gen_token()
    path = f"/omega-canary/{token[:16]}/beacon"
    local_ip = _get_local_ip()
    return {
        "type": "http",
        "token": token,
        "trigger": f"http://{local_ip}:{port}{path}",
        "description": label,
        "usage": f"curl http://{local_ip}:{port}{path}",
        "embed_html": f'<img src="http://{local_ip}:{port}{path}" width="1" height="1">',
        "embed_markdown": f"![tracking](http://{local_ip}:{port}{path})",
        "detection": f"Monitor port {port} access logs for requests to {path}",
    }


def _gen_aws_canary(label: str) -> dict:
    """Generate fake AWS credential canary."""
    token = _gen_token()
    fake_key_id = "AKIA" + token[:16].upper()
    fake_secret = token[16:] + "wJalrXUtnFEM"
    return {
        "type": "aws_credentials",
        "token": token,
        "description": label,
        "fake_access_key_id": fake_key_id,
        "fake_secret_access_key": fake_secret,
        "file_content": (
            f"[default]\n"
            f"aws_access_key_id = {fake_key_id}\n"
            f"aws_secret_access_key = {fake_secret}\n"
            f"region = us-east-1\n"
        ),
        "usage": "Place in ~/.aws/credentials or embed in a repo as a honeypot",
        "detection": "Any usage of these credentials will fail but may appear in CloudTrail logs if an attacker attempts to use them",
    }


def _gen_ssh_canary(label: str) -> dict:
    """Generate canary SSH config entry."""
    token = _gen_token()
    host_alias = f"omega-canary-{token[:8]}"
    return {
        "type": "ssh_config",
        "token": token,
        "description": label,
        "ssh_config_entry": (
            f"Host {host_alias}\n"
            f"    HostName 10.0.0.{int(token[:2], 16) % 254 + 1}\n"
            f"    User admin\n"
            f"    IdentityFile ~/.ssh/id_rsa\n"
        ),
        "usage": "Add to ~/.ssh/config; any connection attempt reveals credential harvesting",
        "detection": "Monitor for SSH connection attempts to the canary host alias",
    }


def _gen_email_canary(label: str, domain: str = "") -> dict:
    """Generate canary email address."""
    token = _gen_token()
    if not domain:
        domain = "example.com"
    addr = f"canary-{token[:12]}@{domain}"
    return {
        "type": "email",
        "token": token,
        "address": addr,
        "description": label,
        "usage": f"Embed {addr} in documents/configs as a fake contact",
        "detection": "Any email sent to this address indicates exfiltration or unauthorized access",
    }


def _gen_word_canary(label: str) -> dict:
    """Generate a canary token for MS Word/Excel documents."""
    token = _gen_token()
    tracking_url = f"http://omega-canary-{token[:12]}.local/track.png"
    return {
        "type": "document",
        "token": token,
        "description": label,
        "tracking_url": tracking_url,
        "embed_instruction": (
            "In Word: Insert → Picture → From URL → paste tracking URL\n"
            "In Excel: Use WEBSERVICE formula or embed as linked image"
        ),
        "xml_snippet": (
            f'<v:imagedata src="{tracking_url}" o:title=""/>'
        ),
        "detection": "Document open triggers a DNS/HTTP request to the tracking URL",
    }


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


CANARY_TYPES = {
    "dns":      _gen_dns_canary,
    "http":     _gen_http_canary,
    "aws":      _gen_aws_canary,
    "ssh":      _gen_ssh_canary,
    "email":    _gen_email_canary,
    "document": _gen_word_canary,
}


def run(
    action: str = "list",
    label: str = "",
    canary_type: str = "dns",
    domain: str = "",
    port: int = 8080,
    token_id: str = "",
):
    store = _load_store()

    if action == "list":
        _cmd_list(store)

    elif action == "create":
        _cmd_create(store, label, canary_type, domain, port)

    elif action == "show":
        _cmd_show(store, token_id)

    elif action == "delete":
        _cmd_delete(store, token_id)

    elif action == "alert":
        _cmd_simulate_alert(store, token_id)

    else:
        console.print(f"[red]Unknown action: {action}[/red]")


def _cmd_list(store: dict):
    canaries = store.get("canaries", [])
    if not canaries:
        console.print(Panel(
            "[dim]No canary tokens deployed yet.\n"
            "Create one: [cyan]omega deception create --label 'My Honeypot' --type dns[/cyan][/dim]",
            title="[bold #ff2d78]🍯  Canary Tokens[/bold #ff2d78]",
            box=box.ROUNDED
        ))
        return

    t = Table("Token ID", "Type", "Label", "Created", "Trigger",
              title=f"[bold #ff2d78]🍯  {len(canaries)} Canary Token(s)[/bold #ff2d78]",
              box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
    for c in canaries:
        trigger = c.get("trigger") or c.get("address") or c.get("fake_access_key_id", "—")
        t.add_row(
            c["token"][:12] + "…",
            c["type"],
            c.get("description", "—")[:40],
            c.get("created", "?")[:10],
            trigger[:60],
        )
    console.print(t)


def _cmd_create(store: dict, label: str, canary_type: str, domain: str, port: int):
    if canary_type not in CANARY_TYPES:
        console.print(f"[red]Unknown type. Choose from: {', '.join(CANARY_TYPES)}[/red]")
        return

    fn = CANARY_TYPES[canary_type]
    try:
        if canary_type == "http":
            canary = fn(label or f"HTTP canary {datetime.datetime.now():%Y-%m-%d}", port)
        elif canary_type in ("dns", "email"):
            canary = fn(label or f"{canary_type} canary", domain)
        else:
            canary = fn(label or f"{canary_type} canary")
    except Exception as e:
        console.print(f"[red]Error generating canary: {e}[/red]")
        return

    canary["created"] = datetime.datetime.now().isoformat()
    canary["alert_count"] = 0
    store["canaries"].append(canary)
    _save_store(store)

    console.print(Panel(
        f"[bold green]✓  Canary token created![/bold green]\n\n"
        f"[bold]Type:[/bold]  {canary['type']}\n"
        f"[bold]Token:[/bold] {canary['token']}\n"
        f"[bold]Label:[/bold] {canary.get('description', '—')}",
        title="[bold #ff2d78]🍯  New Canary Token[/bold #ff2d78]",
        box=box.ROUNDED
    ))

    # Show usage
    if "usage" in canary:
        console.print(f"\n[bold]Usage:[/bold]\n  [cyan]{canary['usage']}[/cyan]")
    if "file_content" in canary:
        console.print("\n[bold]File content (place in honeypot path):[/bold]")
        console.print(Syntax(canary["file_content"], "ini", theme="monokai"))
    if "embed_html" in canary:
        console.print(f"\n[bold]HTML embed:[/bold]\n  [dim]{canary['embed_html']}[/dim]")
    if "detection" in canary:
        console.print(f"\n[bold]Detection:[/bold] [yellow]{canary['detection']}[/yellow]")


def _cmd_show(store: dict, token_id: str):
    for c in store.get("canaries", []):
        if c["token"].startswith(token_id):
            console.print_json(json.dumps(c, indent=2))
            return
    console.print(f"[red]Token not found: {token_id}[/red]")


def _cmd_delete(store: dict, token_id: str):
    before = len(store.get("canaries", []))
    store["canaries"] = [c for c in store.get("canaries", []) if not c["token"].startswith(token_id)]
    _save_store(store)
    removed = before - len(store["canaries"])
    if removed:
        console.print(f"[green]✓  Removed {removed} canary token(s).[/green]")
    else:
        console.print(f"[yellow]No token matching: {token_id}[/yellow]")


def _cmd_simulate_alert(store: dict, token_id: str):
    for c in store.get("canaries", []):
        if c["token"].startswith(token_id):
            c["alert_count"] = c.get("alert_count", 0) + 1
            c["last_alert"] = datetime.datetime.now().isoformat()
            _save_store(store)
            console.print(Panel(
                f"[bold red]🚨  CANARY TRIPPED![/bold red]\n\n"
                f"[bold]Token:[/bold] {c['token']}\n"
                f"[bold]Type:[/bold]  {c['type']}\n"
                f"[bold]Label:[/bold] {c.get('description', '—')}\n"
                f"[bold]Alert #:[/bold] {c['alert_count']}\n"
                f"[bold]Time:[/bold]  {c['last_alert']}",
                title="[bold red]CANARY ALERT[/bold red]",
                box=box.HEAVY,
            ))
            return
    console.print(f"[red]Token not found: {token_id}[/red]")
