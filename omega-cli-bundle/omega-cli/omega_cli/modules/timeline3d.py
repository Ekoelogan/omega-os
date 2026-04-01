"""omega timeline3d — Interactive D3.js temporal intelligence timeline from all omega findings."""
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
<title>omega-cli Intelligence Timeline — {target}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  :root {{ --bg:#0d0d0d; --surface:#161616; --border:#2a2a2a; --accent:#ff2d78; --text:#e0e0e0; --dim:#666; --green:#39ff14; --yellow:#ffd700; --red:#ff4444; --cyan:#00d4ff; --purple:#bb86fc; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; font-size:13px; overflow-x:hidden; }}
  header {{ background:linear-gradient(135deg,#1a0010,#0a0020); padding:16px 28px; border-bottom:2px solid var(--accent); display:flex; align-items:center; gap:16px; }}
  header h1 {{ font-size:22px; font-weight:700; color:var(--accent); letter-spacing:2px; }}
  header .sub {{ color:var(--dim); font-size:12px; margin-top:2px; }}
  .controls {{ background:var(--surface); border-bottom:1px solid var(--border); padding:10px 28px; display:flex; gap:16px; align-items:center; flex-wrap:wrap; }}
  .controls label {{ color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:1px; }}
  select, input[type=range] {{ background:#1e1e1e; border:1px solid var(--border); color:var(--text); padding:4px 8px; border-radius:4px; font-size:12px; }}
  #timeline-container {{ width:100%; height:580px; position:relative; overflow:hidden; background:var(--bg); }}
  svg#timeline {{ width:100%; height:100%; }}
  .axis path, .axis line {{ stroke:var(--border); }}
  .axis text {{ fill:var(--dim); font-size:11px; }}
  .event-dot {{ cursor:pointer; transition:r .15s; }}
  .event-dot:hover {{ r:8; }}
  .lane-label {{ font-size:11px; fill:var(--dim); }}
  .lane-line {{ stroke:var(--border); stroke-width:1; stroke-dasharray:4,4; }}
  .tooltip {{
    position:absolute; background:#1a1a2e; border:1px solid var(--accent);
    border-radius:6px; padding:10px 14px; font-size:12px; pointer-events:none;
    color:var(--text); max-width:320px; z-index:100; display:none; box-shadow:0 4px 20px rgba(255,45,120,.2);
  }}
  .tooltip .t-type {{ color:var(--accent); font-weight:700; font-size:11px; text-transform:uppercase; margin-bottom:4px; }}
  .tooltip .t-val  {{ color:var(--cyan); margin-bottom:2px; word-break:break-all; }}
  .tooltip .t-ts   {{ color:var(--dim); font-size:11px; }}
  .legend {{ padding:10px 28px; display:flex; gap:16px; flex-wrap:wrap; border-top:1px solid var(--border); background:var(--surface); }}
  .legend-item {{ display:flex; align-items:center; gap:6px; font-size:11px; color:var(--dim); }}
  .legend-dot {{ width:10px; height:10px; border-radius:50%; }}
  #stats {{ padding:12px 28px; background:var(--surface); border-top:1px solid var(--border); display:flex; gap:24px; flex-wrap:wrap; }}
  .stat {{ text-align:center; }}
  .stat .val {{ font-size:20px; font-weight:700; color:var(--accent); }}
  .stat .lbl {{ font-size:10px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }}
  #search-box {{ background:#1e1e1e; border:1px solid var(--border); color:var(--text); padding:4px 10px; border-radius:4px; font-size:12px; width:200px; }}
  #search-box::placeholder {{ color:var(--dim); }}
  .highlighted {{ stroke:#fff !important; stroke-width:2 !important; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>⚡ OMEGA TIMELINE</h1>
    <div class="sub">Intelligence Event Timeline — Generated {timestamp}</div>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div style="font-size:18px;font-weight:700;color:var(--cyan)">{target}</div>
    <div class="sub">omega-cli v1.4.0</div>
  </div>
</header>

<div class="controls">
  <label>Filter type:</label>
  <select id="type-filter" onchange="applyFilters()">
    <option value="">All types</option>
  </select>
  <label>Filter module:</label>
  <select id="module-filter" onchange="applyFilters()">
    <option value="">All modules</option>
  </select>
  <label>Search:</label>
  <input type="text" id="search-box" placeholder="Search values…" oninput="applyFilters()">
  <label style="margin-left:auto">Zoom:</label>
  <input type="range" id="zoom-slider" min="0.5" max="5" step="0.1" value="1" oninput="setZoom(this.value)">
</div>

<div id="timeline-container">
  <div class="tooltip" id="tooltip"></div>
  <svg id="timeline"></svg>
</div>

<div id="stats"></div>

<div class="legend" id="legend"></div>

<script>
const EVENTS = {events_json};
const TARGET = "{target}";

const TYPE_COLORS = {{
  ipv4:"#39ff14", domain:"#00d4ff", subdomain:"#00aaff",
  email:"#ffd700", url:"#ff8c00", hash:"#bb86fc",
  md5:"#bb86fc", sha256:"#9966ff", cve:"#ff4444",
  port:"#ff6b35", technology:"#00e5cc", breach:"#ff2d78",
  malware:"#ff0000", onion:"#cc44ff", asn:"#44aaff",
  default:"#888"
}};

const MODULE_SHAPES = {{
  auto:"circle", dns:"circle", ssl:"circle", ports:"rect",
  ioc:"diamond", hunt:"diamond", creds:"triangle",
  breach:"triangle", default:"circle"
}};

let currentZoom = 1;
let filteredEvents = [...EVENTS];

function getColor(type) {{ return TYPE_COLORS[type] || TYPE_COLORS.default; }}

function buildFilters() {{
  const types = [...new Set(EVENTS.map(e => e.type))].sort();
  const modules = [...new Set(EVENTS.map(e => e.module))].sort();
  const tsel = document.getElementById('type-filter');
  const msel = document.getElementById('module-filter');
  types.forEach(t => {{ const o=document.createElement('option'); o.value=t; o.textContent=t; tsel.appendChild(o); }});
  modules.forEach(m => {{ const o=document.createElement('option'); o.value=m; o.textContent=m; msel.appendChild(o); }});
}}

function applyFilters() {{
  const tf = document.getElementById('type-filter').value;
  const mf = document.getElementById('module-filter').value;
  const sf = document.getElementById('search-box').value.toLowerCase();
  filteredEvents = EVENTS.filter(e =>
    (!tf || e.type===tf) &&
    (!mf || e.module===mf) &&
    (!sf || e.value.toLowerCase().includes(sf) || (e.context||'').toLowerCase().includes(sf))
  );
  render();
}}

function setZoom(val) {{ currentZoom=parseFloat(val); render(); }}

function buildStats() {{
  const total = EVENTS.length;
  const types = new Set(EVENTS.map(e=>e.type)).size;
  const modules = new Set(EVENTS.map(e=>e.module)).size;
  const datesSorted = EVENTS.map(e=>e.timestamp).filter(Boolean).sort();
  const span = datesSorted.length >= 2
    ? datesSorted[0].slice(0,10) + ' → ' + datesSorted[datesSorted.length-1].slice(0,10)
    : '—';
  document.getElementById('stats').innerHTML = [
    {{val:total,lbl:'Events'}},
    {{val:types,lbl:'IOC Types'}},
    {{val:modules,lbl:'Modules'}},
    {{val:span,lbl:'Time Span'}},
  ].map(s=>`<div class="stat"><div class="val">${{s.val}}</div><div class="lbl">${{s.lbl}}</div></div>`).join('');
}}

function buildLegend() {{
  const types = [...new Set(EVENTS.map(e=>e.type))].sort().slice(0,15);
  document.getElementById('legend').innerHTML = types
    .map(t=>`<div class="legend-item"><div class="legend-dot" style="background:${{getColor(t)}}"></div>${{t}}</div>`)
    .join('');
}}

function render() {{
  const svg = d3.select('#timeline');
  svg.selectAll('*').remove();

  const container = document.getElementById('timeline-container');
  const W = container.offsetWidth;
  const H = container.offsetHeight;
  const margin = {{top:20, right:30, bottom:50, left:130}};
  const innerW = (W - margin.left - margin.right) * currentZoom;
  const innerH = H - margin.top - margin.bottom;

  if (!filteredEvents.length) {{
    svg.append('text').attr('x',W/2).attr('y',H/2).attr('text-anchor','middle')
      .attr('fill','var(--dim)').text('No events match current filters');
    return;
  }}

  // Parse dates
  const events = filteredEvents.map(e => ({{
    ...e,
    date: e.timestamp ? new Date(e.timestamp) : new Date()
  }})).sort((a,b) => a.date - b.date);

  const dates = events.map(e=>e.date);
  const xScale = d3.scaleTime()
    .domain([d3.min(dates), d3.max(dates)])
    .range([0, innerW]);

  // Lanes by type
  const types = [...new Set(events.map(e=>e.type))];
  const yScale = d3.scaleBand()
    .domain(types)
    .range([0, innerH])
    .padding(0.3);

  const g = svg.append('g').attr('transform', `translate(${{margin.left}},${{margin.top}})`);

  // Enable horizontal scroll
  svg.attr('width', innerW + margin.left + margin.right).attr('height', H);
  container.style.overflowX = currentZoom > 1 ? 'scroll' : 'hidden';

  // Lane lines
  types.forEach(type => {{
    const y = yScale(type) + yScale.bandwidth()/2;
    g.append('line').attr('class','lane-line').attr('x1',0).attr('x2',innerW).attr('y1',y).attr('y2',y);
    g.append('text').attr('class','lane-label').attr('x',-8).attr('y',y+4).attr('text-anchor','end').text(type);
  }});

  // X axis
  g.append('g').attr('class','axis').attr('transform',`translate(0,${{innerH}})`).call(
    d3.axisBottom(xScale).ticks(Math.min(10, Math.round(currentZoom*8))).tickFormat(d3.timeFormat('%Y-%m-%d'))
  ).selectAll('text').attr('transform','rotate(-25)').attr('text-anchor','end');

  // Events
  const tooltip = document.getElementById('tooltip');
  const dots = g.selectAll('.event-dot').data(events).join('circle')
    .attr('class','event-dot')
    .attr('cx', d => xScale(d.date))
    .attr('cy', d => (yScale(d.type)||0) + yScale.bandwidth()/2)
    .attr('r', 5)
    .attr('fill', d => getColor(d.type))
    .attr('fill-opacity', 0.85)
    .attr('stroke', d => getColor(d.type))
    .attr('stroke-width', 1)
    .on('mouseover', (event, d) => {{
      tooltip.style.display='block';
      tooltip.style.left=(event.offsetX+14)+'px';
      tooltip.style.top=(event.offsetY-10)+'px';
      tooltip.innerHTML=`
        <div class="t-type">${{d.type}} · ${{d.module}}</div>
        <div class="t-val">${{d.value}}</div>
        ${{d.context ? `<div style="color:var(--dim);margin-bottom:2px">${{d.context}}</div>` : ''}}
        <div class="t-ts">${{d.timestamp || '?'}}</div>
      `;
    }})
    .on('mouseout', () => {{ tooltip.style.display='none'; }});

  // Connecting line per type
  types.forEach(type => {{
    const typeEvents = events.filter(e=>e.type===type).sort((a,b)=>a.date-b.date);
    if (typeEvents.length < 2) return;
    const line = d3.line()
      .x(d => xScale(d.date))
      .y(d => (yScale(d.type)||0) + yScale.bandwidth()/2)
      .curve(d3.curveMonotoneX);
    g.append('path')
      .datum(typeEvents)
      .attr('fill','none')
      .attr('stroke', getColor(type))
      .attr('stroke-width', 1.2)
      .attr('stroke-opacity', 0.3)
      .attr('d', line);
  }});
}}

buildFilters();
buildStats();
buildLegend();
render();
window.addEventListener('resize', render);
</script>
</body>
</html>
"""


def _load_events(target: str, report_dir: str) -> list[dict]:
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    pattern = os.path.join(report_dir, f"*{safe}*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime)

    events: list[dict] = []

    def add(ts: str, ioc_type: str, value: str, module: str, context: str = ""):
        if not value or not str(value).strip():
            return
        events.append({
            "timestamp": ts,
            "type": ioc_type,
            "value": str(value)[:120],
            "module": module,
            "context": context[:80],
        })

    for fpath in files:
        try:
            with open(fpath) as f:
                data = json.load(f)
        except Exception:
            continue

        module = os.path.basename(fpath).split("_")[0]
        file_ts = datetime.datetime.fromtimestamp(
            os.path.getmtime(fpath)
        ).isoformat()[:19]

        # Generic field extraction
        field_map = {
            "ips":          "ipv4",
            "subdomains":   "subdomain",
            "domains":      "domain",
            "emails":       "email",
            "urls":         "url",
            "technologies": "technology",
        }
        for field, ioc_type in field_map.items():
            for item in (data.get(field) or []):
                if item:
                    add(file_ts, ioc_type, str(item), module)

        # Ports
        for p in (data.get("ports") or []):
            val = str(p.get("port", p)) if isinstance(p, dict) else str(p)
            svc = p.get("service", "") if isinstance(p, dict) else ""
            add(file_ts, "port", val, module, f"Service: {svc}")

        # IOCs with their own timestamps
        ioc_data = data.get("iocs", {})
        if isinstance(ioc_data, dict):
            for ioc_type, items in ioc_data.items():
                if isinstance(items, list):
                    for item in items:
                        add(file_ts, ioc_type, str(item), module)

        # Breaches (HIBP)
        for breach in (data.get("hibp_breaches") or data.get("breaches") or []):
            if isinstance(breach, dict):
                ts = breach.get("BreachDate", file_ts)
                add(ts + "T00:00:00" if len(ts) == 10 else file_ts,
                    "breach", breach.get("Name", "?"), module,
                    f"{breach.get('Domain', '')} — {breach.get('PwnCount', 0):,} records")

        # Ransomware victims
        for v in (data.get("ransomware_victims") or []):
            ts = v.get("discovered", file_ts)
            if ts and len(ts) == 10:
                ts += "T00:00:00"
            add(ts or file_ts, "ransomware", str(v.get("victim", "?")), module,
                f"Group: {v.get('group', '?')}")

        # Git commits
        for commit in (data.get("commits") or []):
            if isinstance(commit, dict):
                add(commit.get("date", file_ts), "git_commit",
                    commit.get("sha", "?")[:12], module,
                    commit.get("message", "")[:60])

        # CVEs
        for cve in (data.get("cves") or data.get("known_cves") or []):
            add(file_ts, "cve", str(cve), module)

        # Certificates (SSL history)
        for cert in (data.get("certificates") or []):
            if isinstance(cert, dict):
                ts = cert.get("not_before") or cert.get("issued", file_ts)
                add(ts, "certificate", cert.get("cn", "?"), module,
                    f"Issuer: {cert.get('issuer', '?')}")

    # Deduplicate
    seen = set()
    unique: list[dict] = []
    for e in events:
        key = (e["type"], e["value"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return sorted(unique, key=lambda x: x["timestamp"])


def run(
    target: str,
    report_dir: str = "",
    output: str = "",
    open_browser: bool = False,
    json_file: str = "",
):
    console.print(Panel(
        f"[bold #ff2d78]⏱  Intelligence Timeline[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    rdir = report_dir or os.path.expanduser("~/.omega/reports")

    if json_file and os.path.exists(json_file):
        with open(json_file) as f:
            data = json.load(f)
        events: list[dict] = []
        module = os.path.basename(json_file).split("_")[0]
        ts = datetime.datetime.now().isoformat()[:19]
        for field, ioc_type in [("ips","ipv4"),("subdomains","subdomain"),("technologies","technology")]:
            for item in (data.get(field) or []):
                events.append({"timestamp": ts, "type": ioc_type, "value": str(item), "module": module, "context": ""})
    else:
        with console.status("[cyan]Loading intelligence events…"):
            events = _load_events(target, rdir)

    console.print(f"[dim]Loaded {len(events)} intelligence events[/dim]")

    if not events:
        console.print("[yellow]No events found. Run recon first: omega auto <target>[/yellow]")
        return

    # Type breakdown
    type_counts: dict[str, int] = {}
    for e in events:
        type_counts[e["type"]] = type_counts.get(e["type"], 0) + 1
    console.print("\n[bold]Event breakdown:[/bold]")
    for etype, cnt in sorted(type_counts.items(), key=lambda x: -x[1])[:10]:
        bar = "█" * min(cnt, 30)
        console.print(f"  [cyan]{etype:<18}[/cyan] {bar} {cnt}")

    # Build HTML
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = HTML_TEMPLATE.format(
        target=target,
        timestamp=ts,
        events_json=json.dumps(events),
    )

    if not output:
        ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
        output = os.path.join(rdir, f"timeline3d_{safe}_{ts_file}.html")

    with open(output, "w", encoding="utf-8") as f:
        f.write(html)

    size = os.path.getsize(output)
    console.print(f"\n[bold green]✓  Timeline generated![/bold green]")
    console.print(f"   File:   [cyan]{output}[/cyan]")
    console.print(f"   Events: {len(events)}")
    console.print(f"   Types:  {len(type_counts)}")
    console.print(f"   Size:   {size:,} bytes")

    if open_browser:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(output)}")
    else:
        console.print(f"\n[dim]Open with: xdg-open {output}[/dim]")
