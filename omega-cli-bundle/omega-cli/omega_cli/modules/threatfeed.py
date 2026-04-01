"""omega threatfeed — Threat feed manager: MISP community feeds, Feodo tracker C2 IPs,
URLhaus malware URLs, ThreatFox IOCs, Emerging Threats rules, Abuse.ch botnet C2."""
from __future__ import annotations
import json, os, re, csv, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
TIMEOUT = 12

FEEDS: dict[str, dict] = {
    "feodo": {
        "name":        "Feodo Tracker (Botnet C2 IPs)",
        "url":         "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "type":        "json",
        "category":    "c2",
        "description": "Emotet, Dridex, TrickBot, QakBot, IcedID C2 servers",
    },
    "urlhaus": {
        "name":        "URLhaus (Malware URLs)",
        "url":         "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "type":        "json_post",
        "category":    "malware_url",
        "description": "Recent malware distribution URLs",
    },
    "threatfox": {
        "name":        "ThreatFox (IOCs)",
        "url":         "https://threatfox-api.abuse.ch/api/v1/",
        "type":        "json_post",
        "category":    "ioc",
        "description": "Multi-type IOCs: IPs, domains, URLs, hashes",
    },
    "sslbl": {
        "name":        "SSLBL (Malicious SSL Certs)",
        "url":         "https://sslbl.abuse.ch/blacklist/sslblacklist.json",
        "type":        "json",
        "category":    "ssl",
        "description": "Blacklisted SSL certificate fingerprints (C2, botnet)",
    },
    "bazaar": {
        "name":        "MalwareBazaar (Recent Samples)",
        "url":         "https://mb-api.abuse.ch/api/v1/",
        "type":        "json_post",
        "category":    "malware_hash",
        "description": "Recent malware sample hashes from MalwareBazaar",
    },
    "misp-osint": {
        "name":        "MISP OSINT Community Feed",
        "url":         "https://www.misp-project.org/feeds/",
        "type":        "html",
        "category":    "misp",
        "description": "Public MISP event feeds for OSINT community",
    },
}

CATEGORY_COLORS = {
    "c2":           "#ff0000",
    "malware_url":  "#ff4444",
    "ioc":          "#ff2d78",
    "ssl":          "#ffd700",
    "malware_hash": "#bb86fc",
    "misp":         "#00d4ff",
}


def _fetch_feodo() -> list[dict]:
    try:
        r = httpx.get(FEEDS["feodo"]["url"], timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            return [
                {
                    "ioc":     item.get("ip_address", item.get("dst_ip", "?")),
                    "type":    "IPv4",
                    "malware": item.get("malware", "?"),
                    "status":  item.get("status", "?"),
                    "country": item.get("country", "?"),
                    "port":    str(item.get("dst_port", "?")),
                    "since":   item.get("first_seen", "?")[:10],
                }
                for item in (data if isinstance(data, list) else data.get("results", []))[:50]
            ]
    except Exception:
        pass
    return []


def _fetch_urlhaus(limit: int = 20) -> list[dict]:
    try:
        r = httpx.get(f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/",
                      timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            results = []
            for item in (data.get("urls") or [])[:limit]:
                results.append({
                    "ioc":     item.get("url", "?"),
                    "type":    "URL",
                    "threat":  item.get("threat", "?"),
                    "status":  item.get("url_status", "?"),
                    "tags":    ", ".join(item.get("tags") or [])[:30],
                    "since":   item.get("date_added", "?")[:10],
                })
            return results
    except Exception:
        pass
    return []


def _fetch_threatfox(limit: int = 20) -> list[dict]:
    try:
        r = httpx.post(
            FEEDS["threatfox"]["url"],
            json={"query": "get_iocs", "days": 1},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            results = []
            for item in (data.get("data") or [])[:limit]:
                results.append({
                    "ioc":        item.get("ioc", "?"),
                    "type":       item.get("ioc_type", "?"),
                    "threat":     item.get("threat_type", "?"),
                    "malware":    item.get("malware", "?"),
                    "confidence": item.get("confidence_level", "?"),
                    "since":      (item.get("first_seen") or "?")[:10],
                })
            return results
    except Exception:
        pass
    return []


def _fetch_sslbl(limit: int = 20) -> list[dict]:
    try:
        r = httpx.get(FEEDS["sslbl"]["url"], timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            results = []
            for item in (data if isinstance(data, list) else data.get("results", []))[:limit]:
                results.append({
                    "ioc":       item.get("sha1_fingerprint", "?"),
                    "type":      "SSL_SHA1",
                    "subject":   item.get("subject", "?")[:40],
                    "reason":    item.get("reason", "?"),
                    "since":     (item.get("listing_date") or "?")[:10],
                })
            return results
    except Exception:
        pass
    return []


def _fetch_bazaar(limit: int = 20) -> list[dict]:
    try:
        r = httpx.post(
            FEEDS["bazaar"]["url"],
            data={"query": "get_recent", "selector": "time", "limit": limit},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            results = []
            for item in (data.get("data") or [])[:limit]:
                results.append({
                    "ioc":      item.get("sha256_hash", "?"),
                    "type":     "SHA256",
                    "malware":  item.get("file_name", "?"),
                    "family":   item.get("signature", "?"),
                    "filetype": item.get("file_type", "?"),
                    "size":     str(item.get("file_size", "?")),
                    "since":    (item.get("first_seen") or "?")[:10],
                })
            return results
    except Exception:
        pass
    return []


def _search_all_feeds(query: str) -> list[dict]:
    """Search across feeds for a specific IOC."""
    hits = []
    # ThreatFox exact search
    try:
        r = httpx.post(
            FEEDS["threatfox"]["url"],
            json={"query": "search_ioc", "search_term": query},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            for item in (data.get("data") or [])[:10]:
                hits.append({
                    "source":  "ThreatFox",
                    "ioc":     item.get("ioc", "?"),
                    "type":    item.get("ioc_type", "?"),
                    "malware": item.get("malware", "?"),
                    "threat":  item.get("threat_type", "?"),
                })
    except Exception:
        pass

    # URLhaus
    try:
        r = httpx.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": query},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") in ("is_listed", "online"):
                hits.append({
                    "source":  "URLhaus",
                    "ioc":     query,
                    "type":    "URL",
                    "malware": data.get("threat", "?"),
                    "status":  data.get("url_status", "?"),
                })
    except Exception:
        pass

    return hits


def run(
    action: str = "list",
    feed: str = "",
    query: str = "",
    limit: int = 20,
    export: str = "",
):
    console.print(Panel(
        "[bold #ff2d78]📡  Threat Feed Manager[/bold #ff2d78]",
        box=box.ROUNDED
    ))

    if action == "list":
        t = Table("Feed ID", "Name", "Category", "Description",
                  title="[bold]Available Threat Feeds[/bold]",
                  box=box.ROUNDED, header_style="bold #ff2d78")
        for fid, fdata in FEEDS.items():
            color = CATEGORY_COLORS.get(fdata["category"], "#888")
            t.add_row(
                f"[cyan]{fid}[/cyan]",
                fdata["name"],
                f"[{color}]{fdata['category']}[/{color}]",
                fdata["description"],
            )
        console.print(t)
        console.print("\n[dim]Usage: omega threatfeed fetch --feed feodo|urlhaus|threatfox|sslbl|bazaar[/dim]")
        console.print("[dim]       omega threatfeed search --query <ip|domain|hash>[/dim]")
        return

    if action == "search":
        if not query:
            console.print("[red]Provide --query <ioc>[/red]")
            return
        with console.status(f"[cyan]Searching threat feeds for: {query}…"):
            hits = _search_all_feeds(query)
        if hits:
            t = Table("Source", "IOC", "Type", "Malware/Threat",
                      title=f"[bold red]⚠  {len(hits)} Match(es) Found[/bold red]",
                      box=box.SIMPLE_HEAD, header_style="bold red")
            for h in hits:
                t.add_row(h["source"], h["ioc"][:60], h.get("type","?"), h.get("malware", h.get("threat","?")))
            console.print(t)
        else:
            console.print(f"[green]✓  '{query}' not found in threat feeds[/green]")
        return

    if action == "fetch":
        feeds_to_fetch = [f.strip() for f in feed.split(",")] if feed else list(FEEDS.keys())[:4]
        all_results: dict[str, list] = {}

        for fid in feeds_to_fetch:
            if fid not in FEEDS:
                console.print(f"[yellow]Unknown feed: {fid}[/yellow]")
                continue
            fmeta = FEEDS[fid]
            with console.status(f"[cyan]Fetching {fmeta['name']}…"):
                if fid == "feodo":
                    results = _fetch_feodo()
                elif fid == "urlhaus":
                    results = _fetch_urlhaus(limit)
                elif fid == "threatfox":
                    results = _fetch_threatfox(limit)
                elif fid == "sslbl":
                    results = _fetch_sslbl(limit)
                elif fid == "bazaar":
                    results = _fetch_bazaar(limit)
                else:
                    results = []

            all_results[fid] = results
            color = CATEGORY_COLORS.get(fmeta["category"], "#888")

            if results:
                # Build appropriate table per feed
                if fid == "feodo":
                    t = Table("IP", "Malware", "Status", "Country", "Port", "First Seen",
                              title=f"[bold {color}]{fmeta['name']} — {len(results)} entries[/bold {color}]",
                              box=box.SIMPLE_HEAD, header_style=f"bold {color}")
                    for item in results[:15]:
                        t.add_row(item["ioc"], item["malware"], item["status"],
                                  item["country"], item["port"], item["since"])
                elif fid == "urlhaus":
                    t = Table("URL", "Threat", "Status", "Tags", "Date",
                              title=f"[bold {color}]{fmeta['name']} — {len(results)} entries[/bold {color}]",
                              box=box.SIMPLE_HEAD, header_style=f"bold {color}")
                    for item in results[:10]:
                        t.add_row(item["ioc"][:55], item.get("threat","?"),
                                  item.get("status","?"), item.get("tags",""), item["since"])
                elif fid == "threatfox":
                    t = Table("IOC", "Type", "Threat", "Malware", "Confidence", "Date",
                              title=f"[bold {color}]{fmeta['name']} — {len(results)} entries[/bold {color}]",
                              box=box.SIMPLE_HEAD, header_style=f"bold {color}")
                    for item in results[:10]:
                        t.add_row(item["ioc"][:45], item["type"], item.get("threat","?"),
                                  item.get("malware","?"), str(item.get("confidence","?")), item["since"])
                elif fid == "sslbl":
                    t = Table("SHA1", "Subject", "Reason", "Listed",
                              title=f"[bold {color}]{fmeta['name']} — {len(results)} entries[/bold {color}]",
                              box=box.SIMPLE_HEAD, header_style=f"bold {color}")
                    for item in results[:10]:
                        t.add_row(item["ioc"][:40], item.get("subject","?"),
                                  item.get("reason","?"), item["since"])
                elif fid == "bazaar":
                    t = Table("SHA256", "File", "Family", "Type", "Size", "Date",
                              title=f"[bold {color}]{fmeta['name']} — {len(results)} entries[/bold {color}]",
                              box=box.SIMPLE_HEAD, header_style=f"bold {color}")
                    for item in results[:10]:
                        t.add_row(item["ioc"][:40], item.get("malware","?"),
                                  item.get("family","?"), item.get("filetype","?"),
                                  item.get("size","?"), item["since"])
                else:
                    t = Table(box=box.SIMPLE_HEAD)
                    t.add_column("IOC"); t.add_column("Type")
                    for item in results[:10]:
                        t.add_row(str(item.get("ioc","?")), str(item.get("type","?")))

                console.print(t)
            else:
                console.print(f"[dim]{fmeta['name']}: no results (API may be rate-limited)[/dim]")

        if export:
            with open(export, "w") as f:
                json.dump(all_results, f, indent=2)
            console.print(f"\n[dim]Exported → {export}[/dim]")
        else:
            out_dir = os.path.expanduser("~/.omega/reports")
            os.makedirs(out_dir, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out = os.path.join(out_dir, f"threatfeed_{ts}.json")
            with open(out, "w") as f:
                json.dump(all_results, f, indent=2)
            console.print(f"\n[dim]Saved → {out}[/dim]")
