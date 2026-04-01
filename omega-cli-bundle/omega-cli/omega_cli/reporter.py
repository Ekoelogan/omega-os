"""Report generator — export OSINT findings to JSON and HTML."""
import json
import datetime
from pathlib import Path
from rich.console import Console

console = Console()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>omega OSINT Report — {target}</title>
<style>
  :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --accent: #8b5cf6; --text: #e6edf3; --dim: #8b949e; --green: #3fb950; --red: #f85149; --yellow: #d29922; --cyan: #39c5cf; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 2rem; margin-bottom: 0.25rem; }}
  .meta {{ color: var(--dim); font-size: 0.85rem; margin-bottom: 2rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(480px, 1fr)); gap: 1.5rem; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }}
  .card h2 {{ color: var(--cyan); font-size: 1rem; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  td {{ padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
  td:first-child {{ color: var(--yellow); white-space: nowrap; width: 35%; font-weight: 600; }}
  .tag {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.75rem; margin: 1px; }}
  .green {{ color: var(--green); }} .red {{ color: var(--red); }} .yellow {{ color: var(--yellow); }} .dim {{ color: var(--dim); }}
  .badge-green {{ background: rgba(63,185,80,0.15); color: var(--green); }}
  .badge-red {{ background: rgba(248,81,73,0.15); color: var(--red); }}
  pre {{ background: #0d1117; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; color: var(--dim); }}
  .banner {{ font-family: monospace; color: var(--accent); white-space: pre; font-size: 0.6rem; line-height: 1.1; margin-bottom: 1rem; }}
  footer {{ text-align: center; color: var(--dim); font-size: 0.75rem; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="banner">&#9608;&#9608;  &#9600;&#9600;&#9600;&#9608;&#9608;&#9608;&#9604;&#9604;&#9604;&#9608;&#9608;&#9608;&#9600;&#9600;&#9600;  &#9608;&#9608;&#9608;&#9608;&#9608;&#9608;  &#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;  &#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;&#9608;</div>
<h1>&#x1F50D; OSINT Report — {target}</h1>
<div class="meta">Generated {timestamp} &nbsp;|&nbsp; omega-cli v0.2.0</div>
<div class="grid">{sections}</div>
<footer>omega-cli &mdash; passive recon only &mdash; for authorized use</footer>
</body>
</html>"""

SECTION_TEMPLATE = """<div class="card"><h2>{title}</h2>{content}</div>"""


def _table_html(rows: list) -> str:
    if not rows:
        return "<p class='dim'>No data.</p>"
    html = "<table>"
    for k, v in rows:
        html += f"<tr><td>{k}</td><td>{v}</td></tr>"
    html += "</table>"
    return html


def _list_html(items: list) -> str:
    if not items:
        return "<p class='dim'>None found.</p>"
    return "<table>" + "".join(f"<tr><td colspan='2'>{i}</td></tr>" for i in items) + "</table>"


def generate(target: str, data: dict, output_dir: str = None) -> Path:
    """Generate HTML and JSON reports from collected OSINT data."""
    if output_dir is None:
        output_dir = Path.home() / "omega-reports"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.datetime.utcnow()
    slug = target.replace(".", "_").replace("/", "_")
    ts_str = ts.strftime("%Y%m%d_%H%M%S")

    # JSON report
    json_data = {"target": target, "timestamp": ts.isoformat(), "data": data}
    json_path = output_dir / f"omega_{slug}_{ts_str}.json"
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2, default=str)

    # HTML report
    sections = []

    if "whois" in data:
        w = data["whois"]
        rows = [(k, str(v)) for k, v in w.items() if v]
        sections.append(SECTION_TEMPLATE.format(title="WHOIS", content=_table_html(rows)))

    if "dns" in data:
        rows = [(rtype, ", ".join(vals)) for rtype, vals in data["dns"].items()]
        sections.append(SECTION_TEMPLATE.format(title="DNS Records", content=_table_html(rows)))

    if "subdomains" in data:
        subs = data["subdomains"]
        sections.append(SECTION_TEMPLATE.format(
            title=f"Subdomains ({len(subs)} found)",
            content=_list_html(subs[:50])
        ))

    if "ipinfo" in data:
        rows = [(k, str(v)) for k, v in data["ipinfo"].items() if v]
        sections.append(SECTION_TEMPLATE.format(title="IP Info", content=_table_html(rows)))

    if "ssl" in data:
        rows = [(k, str(v)) for k, v in data["ssl"].items() if v]
        sections.append(SECTION_TEMPLATE.format(title="SSL Certificate", content=_table_html(rows)))

    if "headers" in data:
        rows = [(k, v) for k, v in data["headers"].items()]
        sections.append(SECTION_TEMPLATE.format(title="HTTP Headers", content=_table_html(rows)))

    if "tech" in data:
        rows = [(cat, ", ".join(techs)) for cat, techs in data["tech"].items()]
        sections.append(SECTION_TEMPLATE.format(title="Technologies", content=_table_html(rows)))

    if "ports" in data:
        rows = [(str(p), s) for p, s in data["ports"]]
        sections.append(SECTION_TEMPLATE.format(title="Open Ports", content=_table_html(rows)))

    if "wayback" in data:
        wb = data["wayback"]
        rows = [(k, str(v)) for k, v in wb.items()]
        sections.append(SECTION_TEMPLATE.format(title="Wayback Machine", content=_table_html(rows)))

    if "threat" in data:
        rows = [(k, str(v)) for k, v in data["threat"].items() if v]
        sections.append(SECTION_TEMPLATE.format(title="Threat Intel", content=_table_html(rows)))

    if "dorks" in data:
        sections.append(SECTION_TEMPLATE.format(
            title="Google Dorks",
            content=_list_html(data["dorks"])
        ))

    html = HTML_TEMPLATE.format(
        target=target,
        timestamp=ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
        sections="".join(sections),
    )

    html_path = output_dir / f"omega_{slug}_{ts_str}.html"
    with open(html_path, "w") as f:
        f.write(html)

    return html_path, json_path
