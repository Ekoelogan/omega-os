"""omega report — Interactive HTML report with D3.js force graph + full findings dashboard."""
from __future__ import annotations
import json, os, re, glob, datetime
from typing import Any
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>omega-cli OSINT Report — {target}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  :root {{ --bg: #0d0d0d; --surface: #161616; --border: #2a2a2a; --accent: #ff2d78; --text: #e0e0e0; --dim: #888; --green: #39ff14; --yellow: #ffd700; --red: #ff4444; --cyan: #00d4ff; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }}
  header {{ background: linear-gradient(135deg, #1a0010, #0a0020); padding: 20px 32px; border-bottom: 1px solid var(--accent); display: flex; align-items: center; gap: 20px; }}
  header h1 {{ font-size: 24px; font-weight: 700; color: var(--accent); letter-spacing: 2px; }}
  header .meta {{ color: var(--dim); font-size: 12px; }}
  .badge {{ background: var(--accent); color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; margin-left: 8px; }}
  nav {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 0 32px; display: flex; gap: 0; }}
  nav a {{ color: var(--dim); text-decoration: none; padding: 12px 20px; font-size: 13px; border-bottom: 2px solid transparent; cursor: pointer; transition: all .2s; }}
  nav a.active, nav a:hover {{ color: var(--accent); border-bottom-color: var(--accent); }}
  .content {{ padding: 24px 32px; max-width: 1400px; }}
  .tab {{ display: none; }} .tab.active {{ display: block; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
  .card .val {{ font-size: 28px; font-weight: 700; color: var(--accent); }}
  .card .lbl {{ font-size: 11px; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .risk-badge {{ display: inline-block; padding: 4px 14px; border-radius: 20px; font-weight: 700; font-size: 13px; }}
  .risk-CRITICAL {{ background: #3d0000; color: var(--red); border: 1px solid var(--red); }}
  .risk-HIGH {{ background: #2d1a00; color: #ff8800; border: 1px solid #ff8800; }}
  .risk-MEDIUM {{ background: #2d2500; color: var(--yellow); border: 1px solid var(--yellow); }}
  .risk-LOW {{ background: #001a0a; color: var(--green); border: 1px solid var(--green); }}
  .risk-UNKNOWN {{ background: #1a1a1a; color: var(--dim); border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th {{ background: #1e1e1e; color: var(--accent); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #1e1e1e; color: var(--text); font-size: 13px; }}
  tr:hover td {{ background: #1a1a1a; }}
  .tag {{ display: inline-block; background: #1e1e2e; border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 11px; margin: 2px; color: var(--cyan); }}
  pre {{ background: #111; border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 12px; color: #aaa; white-space: pre-wrap; }}
  #graph-container {{ width: 100%; height: 600px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; position: relative; }}
  .node circle {{ stroke-width: 2; cursor: pointer; }}
  .node text {{ font-size: 11px; fill: var(--text); pointer-events: none; }}
  .link {{ stroke: #333; stroke-width: 1.5; }}
  .tooltip {{ position: absolute; background: #1a1a2e; border: 1px solid var(--accent); border-radius: 6px; padding: 8px 12px; font-size: 12px; pointer-events: none; color: var(--text); max-width: 300px; z-index: 100; display: none; }}
  h2 {{ color: var(--accent); font-size: 16px; margin: 20px 0 10px; font-weight: 600; }}
  h3 {{ color: var(--dim); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin: 16px 0 8px; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
  .empty {{ color: var(--dim); font-style: italic; padding: 20px; text-align: center; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>⚡ OMEGA-CLI</h1>
    <div class="meta">OSINT Intelligence Report — Generated {timestamp}</div>
  </div>
  <div style="margin-left:auto; text-align:right">
    <div style="font-size:20px; font-weight:700; color:var(--cyan)">{target}</div>
    <div class="meta">omega-cli v1.2.0</div>
  </div>
</header>

<nav>
  <a class="active" onclick="showTab('overview')">Overview</a>
  <a onclick="showTab('network')">Network</a>
  <a onclick="showTab('threats')">Threats</a>
  <a onclick="showTab('graph')">Force Graph</a>
  <a onclick="showTab('raw')">Raw Data</a>
</nav>

<div class="content">

<!-- OVERVIEW TAB -->
<div id="tab-overview" class="tab active">
  <div class="grid" id="stat-cards"></div>
  <div class="section">
    <h2>🎯 Risk Assessment</h2>
    <div id="risk-section"></div>
  </div>
  <div class="section">
    <h2>📋 Key Findings</h2>
    <div id="key-findings"></div>
  </div>
</div>

<!-- NETWORK TAB -->
<div id="tab-network" class="tab">
  <div class="section">
    <h2>🌐 DNS Records</h2>
    <div id="dns-table"></div>
  </div>
  <div class="section">
    <h2>🔐 SSL Certificate</h2>
    <div id="ssl-section"></div>
  </div>
  <div class="section">
    <h2>🌍 Subdomains</h2>
    <div id="subdomain-table"></div>
  </div>
</div>

<!-- THREATS TAB -->
<div id="tab-threats" class="tab">
  <div class="section">
    <h2>🔴 IOCs</h2>
    <div id="ioc-table"></div>
  </div>
  <div class="section">
    <h2>🛡️ Technologies</h2>
    <div id="tech-table"></div>
  </div>
  <div class="section">
    <h2>📦 Open Ports</h2>
    <div id="port-table"></div>
  </div>
</div>

<!-- FORCE GRAPH TAB -->
<div id="tab-graph" class="tab">
  <div id="graph-container">
    <div class="tooltip" id="tooltip"></div>
    <svg id="graph-svg" style="width:100%;height:100%"></svg>
  </div>
  <div style="margin-top:8px; color:var(--dim); font-size:12px">
    Scroll to zoom · Drag to pan · Click nodes for details
  </div>
</div>

<!-- RAW DATA TAB -->
<div id="tab-raw" class="tab">
  <div class="section">
    <h2>📄 Raw JSON Data</h2>
    <pre id="raw-json"></pre>
  </div>
</div>

</div><!-- /content -->

<script>
const REPORT = {report_json};
const TARGET = REPORT.target || "{target}";

function showTab(name) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
}}

function riskColor(r) {{
  return {{CRITICAL:'var(--red)', HIGH:'#ff8800', MEDIUM:'var(--yellow)', LOW:'var(--green)'}};[r] || 'var(--dim)';
}}

function buildCards() {{
  const cards = [
    {{val: REPORT.subdomains?.length || 0, lbl: 'Subdomains'}},
    {{val: REPORT.ports?.length || 0, lbl: 'Open Ports'}},
    {{val: REPORT.iocs?.total || 0, lbl: 'IOCs Found'}},
    {{val: REPORT.technologies?.length || 0, lbl: 'Technologies'}},
    {{val: REPORT.breaches?.length || 0, lbl: 'Breaches'}},
    {{val: REPORT.dns?.length || 0, lbl: 'DNS Records'}},
  ];
  document.getElementById('stat-cards').innerHTML = cards
    .map(c => `<div class="card"><div class="val">${{c.val}}</div><div class="lbl">${{c.lbl}}</div></div>`)
    .join('');
}}

function buildRisk() {{
  const risk = REPORT.risk_level || 'UNKNOWN';
  const score = REPORT.risk_score || 0;
  document.getElementById('risk-section').innerHTML = `
    <span class="risk-badge risk-${{risk}}">${{risk}}</span>
    <span style="color:var(--dim); margin-left:12px">Risk Score: <strong style="color:var(--text)">${{score}}/100</strong></span>
    ${{REPORT.risk_reasons ? '<ul style="margin-top:12px">' + REPORT.risk_reasons.map(r => `<li style="margin:4px 0;color:var(--dim)">• ${{r}}</li>`).join('') + '</ul>' : ''}}
  `;
}}

function buildFindings() {{
  const items = [];
  if (REPORT.ips) items.push(`IPs: ${{REPORT.ips.join(', ')}}`);
  if (REPORT.asn) items.push(`ASN: ${{REPORT.asn}}`);
  if (REPORT.registrar) items.push(`Registrar: ${{REPORT.registrar}}`);
  if (REPORT.ssl_issuer) items.push(`SSL Issuer: ${{REPORT.ssl_issuer}}`);
  if (REPORT.cdn) items.push(`CDN: ${{REPORT.cdn}}`);
  if (REPORT.waf) items.push(`WAF: ${{REPORT.waf}}`);
  document.getElementById('key-findings').innerHTML = items.length
    ? `<ul>${{items.map(i => `<li style="padding:4px 0;border-bottom:1px solid var(--border)"> ${{i}}</li>`).join('')}}</ul>`
    : '<div class="empty">No summary data available — run omega auto or omega dossier first</div>';
}}

function buildTable(containerId, rows, cols) {{
  if (!rows || !rows.length) {{
    document.getElementById(containerId).innerHTML = '<div class="empty">No data</div>';
    return;
  }}
  const html = `<table><thead><tr>${{cols.map(c=>`<th>${{c}}</th>`).join('')}}</tr></thead><tbody>
    ${{rows.map(r => `<tr>${{cols.map(c => `<td>${{r[c] || '—'}}</td>`).join('')}}</tr>`).join('')}}
  </tbody></table>`;
  document.getElementById(containerId).innerHTML = html;
}}

function buildGraph() {{
  const nodes = [];
  const links = [];
  const nodeMap = {{}};
  function addNode(id, label, type, color) {{
    if (!nodeMap[id]) {{
      nodeMap[id] = nodes.length;
      nodes.push({{id, label, type, color}});
    }}
    return nodeMap[id];
  }}
  const rootIdx = addNode(TARGET, TARGET, 'root', '#ff2d78');
  (REPORT.subdomains || []).slice(0,30).forEach(s => {{
    const idx = addNode(s, s, 'subdomain', '#00d4ff');
    links.push({{source: TARGET, target: s}});
  }});
  (REPORT.ips || []).forEach(ip => {{
    addNode(ip, ip, 'ip', '#39ff14');
    links.push({{source: TARGET, target: ip}});
  }});
  (REPORT.technologies || []).slice(0,15).forEach(t => {{
    const tid = 'tech:' + t;
    addNode(tid, t, 'tech', '#ffd700');
    links.push({{source: TARGET, target: tid}});
  }});
  if (nodes.length < 3) {{
    document.getElementById('graph-container').innerHTML = '<div class="empty" style="padding:40px">Not enough data for graph. Run omega auto or omega dossier first.</div>';
    return;
  }}
  const svg = d3.select('#graph-svg');
  const w = document.getElementById('graph-container').offsetWidth;
  const h = 600;
  const tooltip = document.getElementById('tooltip');
  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(100))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(w/2, h/2))
    .force('collision', d3.forceCollide(30));
  const link = svg.append('g').selectAll('line').data(links).join('line').attr('class','link');
  const node = svg.append('g').selectAll('g').data(nodes).join('g').attr('class','node')
    .call(d3.drag().on('start', (e,d) => {{ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }})
      .on('drag', (e,d) => {{ d.fx=e.x; d.fy=e.y; }})
      .on('end', (e,d) => {{ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }}));
  node.append('circle').attr('r', d => d.type==='root'?14:d.type==='subdomain'?8:6)
    .attr('fill', d => d.color + '22').attr('stroke', d => d.color);
  node.append('text').attr('dx',12).attr('dy',4).text(d => d.label.length>20 ? d.label.slice(0,20)+'…' : d.label);
  node.on('mouseover', (e,d) => {{
    tooltip.style.display='block'; tooltip.style.left=(e.offsetX+12)+'px'; tooltip.style.top=(e.offsetY-8)+'px';
    tooltip.innerHTML=`<strong>${{d.label}}</strong><br><span style="color:var(--dim)">${{d.type}}</span>`;
  }}).on('mouseout', () => {{ tooltip.style.display='none'; }});
  sim.on('tick', () => {{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform',d=>`translate(${{d.x}},${{d.y}})`);
  }});
  svg.call(d3.zoom().scaleExtent([0.2,4]).on('zoom', e => svg.select('g').attr('transform', e.transform)));
}}

// Init
buildCards();
buildRisk();
buildFindings();
buildTable('dns-table', REPORT.dns, ['type','value','ttl']);
buildTable('subdomain-table', (REPORT.subdomains||[]).map(s=>({{'subdomain':s}})), ['subdomain']);
buildTable('port-table', REPORT.ports, ['port','protocol','service','banner']);
buildTable('tech-table', (REPORT.technologies||[]).map(t=>({{'technology':t}})), ['technology']);
document.getElementById('raw-json').textContent = JSON.stringify(REPORT, null, 2);
buildGraph();
</script>
</body>
</html>
"""


def _discover_json(target: str) -> dict[str, Any]:
    """Auto-discover and merge latest recon JSON files for target."""
    report_dir = os.path.expanduser("~/.omega/reports")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    pattern = os.path.join(report_dir, f"*{safe}*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    merged: dict[str, Any] = {"target": target}
    seen_types: set = set()

    for f in files[:10]:
        try:
            with open(f) as fh:
                data = json.load(fh)
            prefix = os.path.basename(f).split("_")[0]
            if prefix not in seen_types:
                seen_types.add(prefix)
                merged[prefix] = data
                # Hoist common fields
                for key in ("ips", "subdomains", "dns", "ports", "technologies",
                            "risk_level", "risk_score", "asn", "ssl_issuer",
                            "registrar", "cdn", "waf", "iocs"):
                    if key in data and key not in merged:
                        merged[key] = data[key]
        except Exception:
            pass
    return merged


def _calc_risk(report: dict) -> tuple[str, int, list[str]]:
    score = 0
    reasons = []
    ports = report.get("ports") or []
    subs = report.get("subdomains") or []
    iocs = report.get("iocs") or {}
    breaches = report.get("breaches") or []

    if len(ports) > 10:
        score += 20
        reasons.append(f"{len(ports)} open ports detected")
    elif len(ports) > 3:
        score += 10
        reasons.append(f"{len(ports)} open ports")

    if len(subs) > 50:
        score += 15
        reasons.append(f"Large attack surface: {len(subs)} subdomains")
    elif len(subs) > 10:
        score += 8

    total_iocs = iocs.get("total", 0) if isinstance(iocs, dict) else len(iocs)
    if total_iocs > 0:
        score += min(30, total_iocs * 5)
        reasons.append(f"{total_iocs} IOCs extracted")

    if breaches:
        score += 20
        reasons.append(f"{len(breaches)} breach(es) found")

    if score >= 70:
        return "CRITICAL", score, reasons
    if score >= 50:
        return "HIGH", score, reasons
    if score >= 25:
        return "MEDIUM", score, reasons
    return "LOW", score, reasons


def run(
    target: str,
    json_file: str = "",
    output: str = "",
    open_browser: bool = False,
):
    console.print(Panel(
        f"[bold #ff2d78]📊  Interactive HTML Report[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    # Build report data
    if json_file and os.path.exists(json_file):
        with console.status("[cyan]Loading JSON file…"):
            with open(json_file) as f:
                report = json.load(f)
            report.setdefault("target", target)
    else:
        with console.status("[cyan]Auto-discovering recon data…"):
            report = _discover_json(target)

    # Calculate risk
    risk_level, risk_score, risk_reasons = _calc_risk(report)
    report["risk_level"] = risk_level
    report["risk_score"] = risk_score
    report["risk_reasons"] = risk_reasons

    # Render HTML
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = HTML_TEMPLATE.format(
        target=target,
        timestamp=ts,
        report_json=json.dumps(report),
    )

    # Output path
    if not output:
        out_dir = os.path.expanduser("~/.omega/reports")
        os.makedirs(out_dir, exist_ok=True)
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
        output = os.path.join(out_dir, f"report_{safe}_{ts_file}.html")

    with open(output, "w", encoding="utf-8") as f:
        f.write(html)

    file_size = os.path.getsize(output)
    console.print(f"\n[bold green]✓  Report generated![/bold green]")
    console.print(f"   [bold]File:[/bold]  [cyan]{output}[/cyan]")
    console.print(f"   [bold]Size:[/bold]  {file_size:,} bytes")
    console.print(f"   [bold]Risk:[/bold]  [{('green' if risk_level == 'LOW' else 'yellow' if risk_level == 'MEDIUM' else 'red')}]{risk_level}[/] ({risk_score}/100)")
    console.print(f"   [bold]Data sources merged:[/bold] {len([k for k in report if isinstance(report[k], dict)])}")

    if open_browser:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(output)}")
        console.print("   [dim]Opened in browser.[/dim]")
    else:
        console.print(f"\n[dim]Open with: xdg-open {output}[/dim]")
