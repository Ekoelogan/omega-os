"""Webhook/notification integration — Discord, Slack, Telegram, custom HTTP."""
import json
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


def _discord_payload(title: str, body: str, color: int = 0xFF2D78) -> dict:
    return {
        "embeds": [{
            "title": f"🔴 OMEGA: {title}",
            "description": body[:4000],
            "color": color,
            "footer": {"text": "omega-cli OSINT toolkit"},
        }]
    }


def _slack_payload(title: str, body: str) -> dict:
    return {
        "text": f"*OMEGA: {title}*\n```{body[:3000]}```"
    }


def _telegram_payload(token: str, chat_id: str, title: str, body: str) -> tuple:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    text = f"*OMEGA: {title}*\n\n`{body[:3000]}`"
    return url, {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}


def send(provider: str, webhook_url: str, title: str, body: str,
         telegram_token: str = "", telegram_chat: str = "") -> bool:
    """Send a notification through the specified provider."""
    try:
        if provider == "discord":
            r = requests.post(webhook_url, json=_discord_payload(title, body), timeout=10)
        elif provider == "slack":
            r = requests.post(webhook_url, json=_slack_payload(title, body), timeout=10)
        elif provider == "telegram":
            url, payload = _telegram_payload(telegram_token, telegram_chat, title, body)
            r = requests.post(url, json=payload, timeout=10)
        else:
            r = requests.post(webhook_url, json={"title": title, "body": body, "source": "omega"}, timeout=10)

        if r.status_code in (200, 204):
            console.print(f"[green]✓[/] Notification sent via [cyan]{provider}[/]  (HTTP {r.status_code})")
            return True
        else:
            console.print(f"[red]✗[/] Failed: HTTP {r.status_code}  {r.text[:100]}")
            return False
    except Exception as e:
        console.print(f"[red]Error sending notification:[/] {e}")
        return False


def test_webhook(provider: str, webhook_url: str, **kwargs) -> bool:
    """Send a test notification."""
    return send(
        provider, webhook_url,
        title="Test Notification",
        body="✅ omega-cli webhook is configured correctly. You will receive alerts here.",
        **kwargs,
    )


def send_findings(target: str, findings: dict, provider: str, webhook_url: str, **kwargs) -> bool:
    """Format and send OSINT findings as a notification."""
    lines = [f"Target: {target}", ""]
    for module, data in findings.items():
        if isinstance(data, dict):
            lines.append(f"[{module.upper()}]")
            for k, v in list(data.items())[:5]:
                lines.append(f"  {k}: {str(v)[:100]}")
        elif isinstance(data, list):
            lines.append(f"[{module.upper()}] {len(data)} items")
        lines.append("")

    body = "\n".join(lines)[:3000]
    return send(provider, webhook_url, title=f"OSINT Report: {target}", body=body, **kwargs)


def run(provider: str, webhook_url: str, target: str = "", message: str = "",
        test: bool = False, telegram_token: str = "", telegram_chat: str = ""):
    """Run notification test or send a manual alert."""
    console.print(Panel(
        f"[bold #ff2d78]🔔 Notify[/]\n"
        f"[dim]Provider:[/] [cyan]{provider}[/]",
        border_style="#ff85b3",
    ))

    kwargs = {}
    if telegram_token:
        kwargs["telegram_token"] = telegram_token
    if telegram_chat:
        kwargs["telegram_chat"] = telegram_chat

    if test:
        return test_webhook(provider, webhook_url, **kwargs)

    body = message or f"OMEGA alert for target: {target}"
    return send(provider, webhook_url, title=f"Alert: {target or 'Manual'}", body=body, **kwargs)
