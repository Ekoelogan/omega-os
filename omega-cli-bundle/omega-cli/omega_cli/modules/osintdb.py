"""omega osintdb — Local SQLite intelligence database: store, search, correlate all omega findings."""
from __future__ import annotations
import json, os, re, datetime, sqlite3
from typing import Any
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()
DB_PATH = os.path.expanduser("~/.omega/osint.db")


def _get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS findings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target      TEXT NOT NULL,
        source_file TEXT,
        module      TEXT,
        ioc_type    TEXT,
        value       TEXT,
        context     TEXT,
        risk        TEXT DEFAULT 'UNKNOWN',
        tags        TEXT DEFAULT '[]',
        created_at  TEXT DEFAULT (datetime('now')),
        raw_json    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_target ON findings(target);
    CREATE INDEX IF NOT EXISTS idx_value  ON findings(value);
    CREATE INDEX IF NOT EXISTS idx_module ON findings(module);
    CREATE INDEX IF NOT EXISTS idx_ioc_type ON findings(ioc_type);

    CREATE TABLE IF NOT EXISTS targets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT UNIQUE NOT NULL,
        first_seen  TEXT DEFAULT (datetime('now')),
        last_seen   TEXT DEFAULT (datetime('now')),
        risk        TEXT DEFAULT 'UNKNOWN',
        notes       TEXT DEFAULT '',
        tags        TEXT DEFAULT '[]'
    );
    CREATE INDEX IF NOT EXISTS idx_target_name ON targets(name);

    CREATE TABLE IF NOT EXISTS relationships (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        source      TEXT NOT NULL,
        relation    TEXT NOT NULL,
        target_val  TEXT NOT NULL,
        confidence  REAL DEFAULT 1.0,
        source_module TEXT,
        created_at  TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source);
    CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_val);
    """)
    conn.commit()


def _ingest_json_file(conn: sqlite3.Connection, filepath: str) -> int:
    """Parse an omega JSON report and insert findings into DB."""
    count = 0
    try:
        with open(filepath) as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]Cannot read {filepath}: {e}[/red]")
        return 0

    target = data.get("target", os.path.basename(filepath))
    module = os.path.basename(filepath).split("_")[0]

    # Upsert target
    conn.execute("""
        INSERT INTO targets (name) VALUES (?)
        ON CONFLICT(name) DO UPDATE SET last_seen=datetime('now')
    """, (target,))

    def insert(ioc_type: str, value: str, context: str = "", risk: str = "UNKNOWN", tags: list = []):
        nonlocal count
        if not value or not str(value).strip():
            return
        conn.execute("""
            INSERT INTO findings (target, source_file, module, ioc_type, value, context, risk, tags, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (target, filepath, module, ioc_type, str(value)[:500], context[:200], risk,
              json.dumps(tags), json.dumps(data)[:2000]))
        count += 1

    def insert_rel(source: str, relation: str, tgt: str):
        conn.execute("""
            INSERT INTO relationships (source, relation, target_val, source_module)
            VALUES (?, ?, ?, ?)
        """, (source, relation, tgt, module))

    # Generic field extraction
    FIELD_MAP = {
        "ips":          ("ipv4", "IP address"),
        "subdomains":   ("subdomain", "Subdomain"),
        "emails":       ("email", "Email"),
        "domains":      ("domain", "Domain"),
        "hashes":       ("hash", "File hash"),
        "cves":         ("cve", "CVE"),
        "technologies": ("technology", "Technology"),
        "urls":         ("url", "URL"),
        "onions":       ("onion", "Onion address"),
    }

    for field, (ioc_type, ctx) in FIELD_MAP.items():
        val = data.get(field)
        if isinstance(val, list):
            for item in val:
                insert(ioc_type, str(item), ctx)
                insert_rel(target, f"has_{ioc_type}", str(item))

    # Ports
    ports = data.get("ports", [])
    for p in ports:
        if isinstance(p, dict):
            insert("port", str(p.get("port", "")), f"Service: {p.get('service', '?')}")
        else:
            insert("port", str(p), "Open port")

    # DNS records
    dns = data.get("dns", [])
    for rec in dns:
        if isinstance(rec, dict):
            insert("dns_record", rec.get("value", ""), f"{rec.get('type', '?')} record")

    # IOCs
    iocs = data.get("iocs", {})
    if isinstance(iocs, dict):
        for ioc_type, items in iocs.items():
            if isinstance(items, list):
                for item in items:
                    insert(ioc_type, str(item), "IOC extraction")

    # Risk
    risk_level = data.get("risk_level", "UNKNOWN")
    if risk_level != "UNKNOWN":
        conn.execute("UPDATE targets SET risk=? WHERE name=?", (risk_level, target))

    conn.commit()
    return count


def _bulk_ingest(conn: sqlite3.Connection, directory: str) -> dict[str, int]:
    """Ingest all JSON files from omega reports directory."""
    import glob
    stats: dict[str, int] = {}
    pattern = os.path.join(directory, "*.json")
    files = glob.glob(pattern)
    for f in sorted(files, key=os.path.getmtime, reverse=True):
        count = _ingest_json_file(conn, f)
        if count:
            stats[os.path.basename(f)] = count
    return stats


def _search(conn: sqlite3.Connection, query: str, ioc_type: str = "", limit: int = 50) -> list[sqlite3.Row]:
    sql = "SELECT * FROM findings WHERE (value LIKE ? OR target LIKE ? OR context LIKE ?)"
    params: list[Any] = [f"%{query}%", f"%{query}%", f"%{query}%"]
    if ioc_type:
        sql += " AND ioc_type = ?"
        params.append(ioc_type)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def _stats(conn: sqlite3.Connection) -> dict:
    return {
        "targets":      conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0],
        "findings":     conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
        "relationships":conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0],
        "by_type":      dict(conn.execute(
            "SELECT ioc_type, COUNT(*) FROM findings GROUP BY ioc_type ORDER BY COUNT(*) DESC"
        ).fetchall()),
        "top_targets":  conn.execute(
            "SELECT target, COUNT(*) as cnt FROM findings GROUP BY target ORDER BY cnt DESC LIMIT 5"
        ).fetchall(),
    }


def _export_stix_lite(conn: sqlite3.Connection, target: str) -> dict:
    """Export findings as simplified STIX-lite JSON."""
    rows = conn.execute(
        "SELECT * FROM findings WHERE target=? ORDER BY ioc_type", (target,)
    ).fetchall()
    bundle = {"type": "bundle", "id": f"bundle--{target}", "objects": []}
    for row in rows:
        obj: dict = {
            "type": f"indicator",
            "ioc_type": row["ioc_type"],
            "value": row["value"],
            "context": row["context"],
            "target": row["target"],
            "module": row["module"],
            "created": row["created_at"],
        }
        bundle["objects"].append(obj)
    return bundle


def run(
    action: str = "stats",
    query: str = "",
    target: str = "",
    ioc_type: str = "",
    ingest_dir: str = "",
    ingest_file: str = "",
    export_format: str = "table",
    limit: int = 50,
):
    conn = _get_conn()

    if action == "ingest":
        _cmd_ingest(conn, ingest_dir, ingest_file)
    elif action == "search":
        _cmd_search(conn, query, ioc_type, limit)
    elif action == "stats":
        _cmd_stats(conn)
    elif action == "targets":
        _cmd_targets(conn)
    elif action == "graph":
        _cmd_graph(conn, target or query)
    elif action == "export":
        _cmd_export(conn, target or query, export_format)
    elif action == "clear":
        _cmd_clear(conn)
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
    conn.close()


def _cmd_ingest(conn, ingest_dir, ingest_file):
    console.print(Panel("[bold #ff2d78]📥  Ingesting omega reports…[/bold #ff2d78]", box=box.ROUNDED))
    if ingest_file:
        count = _ingest_json_file(conn, ingest_file)
        console.print(f"[green]✓ Ingested {count} findings from {ingest_file}[/green]")
    else:
        directory = ingest_dir or os.path.expanduser("~/.omega/reports")
        stats = _bulk_ingest(conn, directory)
        total = sum(stats.values())
        console.print(f"[green]✓ Ingested {total} findings from {len(stats)} file(s)[/green]")
        if stats:
            for fname, cnt in list(stats.items())[:10]:
                console.print(f"  [dim]{fname}[/dim]: {cnt}")


def _cmd_stats(conn):
    s = _stats(conn)
    console.print(Panel(
        f"[bold #ff2d78]🗄  OSINT Database[/bold #ff2d78]  [dim]{DB_PATH}[/dim]",
        box=box.ROUNDED
    ))
    console.print(f"\n[bold]Targets:[/bold]   [cyan]{s['targets']}[/cyan]")
    console.print(f"[bold]Findings:[/bold]  [cyan]{s['findings']}[/cyan]")
    console.print(f"[bold]Edges:[/bold]     [cyan]{s['relationships']}[/cyan]")

    if s["by_type"]:
        t = Table("IOC Type", "Count", box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
        for ioc_type, cnt in list(s["by_type"].items())[:15]:
            t.add_row(ioc_type, str(cnt))
        console.print(t)

    if s["top_targets"]:
        console.print("\n[bold]Top targets:[/bold]")
        for row in s["top_targets"]:
            console.print(f"  [cyan]{row[0]}[/cyan] — {row[1]} findings")


def _cmd_search(conn, query, ioc_type, limit):
    if not query:
        console.print("[red]Provide a search query.[/red]")
        return
    rows = _search(conn, query, ioc_type, limit)
    if not rows:
        console.print(f"[yellow]No results for: {query}[/yellow]")
        return
    t = Table("Target", "Type", "Value", "Context", "Module", "Date",
              title=f"[bold]🔍 {len(rows)} Result(s) for '{query}'[/bold]",
              box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
    for row in rows:
        t.add_row(
            row["target"][:25],
            row["ioc_type"][:15],
            row["value"][:45],
            (row["context"] or "")[:35],
            (row["module"] or "")[:15],
            (row["created_at"] or "")[:16],
        )
    console.print(t)


def _cmd_targets(conn):
    rows = conn.execute("SELECT * FROM targets ORDER BY last_seen DESC LIMIT 50").fetchall()
    if not rows:
        console.print("[dim]No targets in database yet. Run: omega osintdb ingest[/dim]")
        return
    t = Table("Target", "Risk", "First Seen", "Last Seen", "Notes",
              title="[bold]🎯 Tracked Targets[/bold]",
              box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
    for row in rows:
        risk = row["risk"] or "UNKNOWN"
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk, "dim")
        t.add_row(
            row["name"],
            f"[{color}]{risk}[/{color}]",
            (row["first_seen"] or "")[:16],
            (row["last_seen"] or "")[:16],
            (row["notes"] or "")[:40],
        )
    console.print(t)


def _cmd_graph(conn, target):
    if not target:
        console.print("[red]Provide a target for graph view.[/red]")
        return
    from rich.tree import Tree
    rows = conn.execute(
        "SELECT ioc_type, value, context FROM findings WHERE target=? ORDER BY ioc_type",
        (target,)
    ).fetchall()
    rels = conn.execute(
        "SELECT relation, target_val FROM relationships WHERE source=? LIMIT 30",
        (target,)
    ).fetchall()

    tree = Tree(f"[bold #ff2d78]🎯 {target}[/bold #ff2d78]")
    by_type: dict[str, list] = {}
    for row in rows:
        by_type.setdefault(row["ioc_type"], []).append(row["value"])
    for ioc_type, values in sorted(by_type.items()):
        branch = tree.add(f"[bold cyan]{ioc_type}[/bold cyan] ({len(values)})")
        for v in values[:10]:
            branch.add(f"[dim]{v[:70]}[/dim]")
    console.print(tree)
    console.print(f"\n[dim]Total: {len(rows)} findings, {len(rels)} relationships[/dim]")


def _cmd_export(conn, target, fmt):
    if fmt == "stix":
        bundle = _export_stix_lite(conn, target)
        out = os.path.expanduser(f"~/.omega/reports/stix_{target}_{datetime.datetime.now():%Y%m%d}.json")
        with open(out, "w") as f:
            json.dump(bundle, f, indent=2)
        console.print(f"[green]✓ STIX bundle exported → {out}[/green]")
    else:
        rows = conn.execute("SELECT * FROM findings WHERE target=? ORDER BY ioc_type", (target,)).fetchall()
        if fmt == "csv":
            out = os.path.expanduser(f"~/.omega/reports/export_{target}_{datetime.datetime.now():%Y%m%d}.csv")
            import csv
            with open(out, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["target", "module", "ioc_type", "value", "context", "risk", "created_at"])
                for row in rows:
                    w.writerow([row["target"], row["module"], row["ioc_type"],
                                row["value"], row["context"], row["risk"], row["created_at"]])
            console.print(f"[green]✓ CSV exported ({len(rows)} rows) → {out}[/green]")
        else:
            console.print_json(json.dumps([dict(r) for r in rows[:50]], indent=2))


def _cmd_clear(conn):
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM targets")
    conn.execute("DELETE FROM relationships")
    conn.commit()
    console.print("[green]✓ Database cleared.[/green]")
