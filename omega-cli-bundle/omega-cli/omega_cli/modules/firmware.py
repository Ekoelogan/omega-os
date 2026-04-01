"""omega firmware — IoT/firmware OSINT: Shodan device search, default creds, CVE mapping."""
from __future__ import annotations
import json, os, re, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.tree import Tree

console = Console()
TIMEOUT = 10

# Default credential database for common devices
DEFAULT_CREDS = {
    "router": [
        {"vendor": "Cisco", "product": "IOS", "user": "admin", "password": "cisco"},
        {"vendor": "Netgear", "product": "Any", "user": "admin", "password": "password"},
        {"vendor": "Linksys", "product": "Any", "user": "admin", "password": ""},
        {"vendor": "D-Link", "product": "Any", "user": "admin", "password": ""},
        {"vendor": "TP-Link", "product": "Any", "user": "admin", "password": "admin"},
        {"vendor": "Asus", "product": "Any", "user": "admin", "password": "admin"},
        {"vendor": "Ubiquiti", "product": "UniFi", "user": "ubnt", "password": "ubnt"},
        {"vendor": "MikroTik", "product": "RouterOS", "user": "admin", "password": ""},
    ],
    "camera": [
        {"vendor": "Hikvision", "product": "Any", "user": "admin", "password": "12345"},
        {"vendor": "Dahua", "product": "Any", "user": "admin", "password": "admin"},
        {"vendor": "Axis", "product": "Any", "user": "root", "password": "pass"},
        {"vendor": "Foscam", "product": "Any", "user": "admin", "password": ""},
        {"vendor": "Amcrest", "product": "Any", "user": "admin", "password": "admin"},
    ],
    "printer": [
        {"vendor": "HP", "product": "JetDirect", "user": "admin", "password": ""},
        {"vendor": "Xerox", "product": "Any", "user": "admin", "password": "1111"},
        {"vendor": "Canon", "product": "Any", "user": "ADMIN", "password": "canon"},
        {"vendor": "Brother", "product": "Any", "user": "admin", "password": ""},
    ],
    "nas": [
        {"vendor": "Synology", "product": "DSM", "user": "admin", "password": ""},
        {"vendor": "QNAP", "product": "QTS", "user": "admin", "password": "admin"},
        {"vendor": "Western Digital", "product": "MyCloud", "user": "admin", "password": ""},
        {"vendor": "Netgear ReadyNAS", "product": "Any", "user": "admin", "password": "password"},
    ],
    "plc": [
        {"vendor": "Siemens", "product": "S7", "user": "admin", "password": "admin"},
        {"vendor": "Allen-Bradley", "product": "Any", "user": "", "password": ""},
        {"vendor": "Schneider", "product": "Modicon", "user": "USER", "password": "USER"},
    ],
    "switch": [
        {"vendor": "Cisco", "product": "IOS", "user": "cisco", "password": "cisco"},
        {"vendor": "HP/Aruba", "product": "Any", "user": "manager", "password": "manager"},
        {"vendor": "Juniper", "product": "JunOS", "user": "root", "password": ""},
    ],
}

# Known firmware CVEs by vendor keyword
FIRMWARE_CVES = {
    "hikvision": ["CVE-2021-36260", "CVE-2017-7921", "CVE-2014-4878"],
    "dahua":     ["CVE-2022-30563", "CVE-2021-33044", "CVE-2019-3929"],
    "netgear":   ["CVE-2021-27239", "CVE-2020-35785", "CVE-2017-5521"],
    "dlink":     ["CVE-2022-28958", "CVE-2021-45382", "CVE-2019-16920"],
    "tp-link":   ["CVE-2022-30075", "CVE-2020-28347", "CVE-2021-4144"],
    "zyxel":     ["CVE-2022-0342", "CVE-2021-35029", "CVE-2020-29583"],
    "fortinet":  ["CVE-2022-40684", "CVE-2018-13379", "CVE-2021-44228"],
    "cisco":     ["CVE-2020-3452", "CVE-2019-1663", "CVE-2018-0296"],
    "mikrotik":  ["CVE-2018-14847", "CVE-2019-3977", "CVE-2022-45315"],
    "axis":      ["CVE-2018-10660", "CVE-2018-10661", "CVE-2021-31986"],
    "ubiquiti":  ["CVE-2021-22908", "CVE-2019-13279", "CVE-2020-8233"],
    "siemens":   ["CVE-2019-13945", "CVE-2022-37786", "CVE-2021-37172"],
}


def _shodan_internet_db(ip: str) -> dict[str, Any]:
    """Query Shodan InternetDB (free, no key needed)."""
    try:
        r = httpx.get(f"https://internetdb.shodan.io/{ip}", timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def _shodan_search(query: str, api_key: str) -> list[dict]:
    """Search Shodan for IoT devices."""
    if not api_key:
        return []
    try:
        r = httpx.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": api_key, "query": query, "minify": "false"},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            return [
                {
                    "ip": m.get("ip_str"),
                    "port": m.get("port"),
                    "org": m.get("org"),
                    "country": m.get("location", {}).get("country_name"),
                    "product": m.get("product"),
                    "version": m.get("version"),
                    "os": m.get("os"),
                    "banner": (m.get("data") or "")[:150],
                    "vulns": list(m.get("vulns", {}).keys())[:5],
                    "cpe": m.get("cpe23", [])[:3],
                }
                for m in matches[:20]
            ]
    except Exception:
        pass
    return []


def _fofa_search(query: str) -> list[dict]:
    """Search FOFA (no auth needed for basic queries via public endpoint)."""
    results = []
    try:
        import base64
        q_b64 = base64.b64encode(query.encode()).decode()
        r = httpx.get(
            "https://fofa.info/api/v1/search/all",
            params={"qbase64": q_b64, "size": 10, "full": "false"},
            timeout=TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200:
            data = r.json()
            for item in (data.get("results") or [])[:10]:
                if isinstance(item, list) and len(item) >= 3:
                    results.append({"ip": item[0], "port": item[1], "domain": item[2]})
    except Exception:
        pass
    return results


def _censys_search(query: str, api_id: str = "", api_secret: str = "") -> list[dict]:
    if not api_id:
        return []
    results = []
    try:
        r = httpx.post(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(api_id, api_secret),
            json={"q": query, "per_page": 10},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            for hit in r.json().get("result", {}).get("hits", []):
                results.append({
                    "ip": hit.get("ip"),
                    "services": [s.get("port") for s in hit.get("services", [])],
                    "name": hit.get("name"),
                    "country": hit.get("location", {}).get("country"),
                })
    except Exception:
        pass
    return results


def _classify_device(banner: str, product: str, cpe: list) -> str:
    """Classify device type from banner/product."""
    text = (banner + " " + (product or "") + " " + " ".join(cpe)).lower()
    if any(k in text for k in ["camera", "dvr", "nvr", "ipcam", "hikvision", "dahua", "axis"]):
        return "camera"
    if any(k in text for k in ["router", "gateway", "linksys", "netgear", "dlink", "zyxel"]):
        return "router"
    if any(k in text for k in ["printer", "jetdirect", "hp laserjet", "xerox"]):
        return "printer"
    if any(k in text for k in ["nas", "synology", "qnap", "readynas", "buffalo"]):
        return "nas"
    if any(k in text for k in ["plc", "scada", "modbus", "siemens", "allen-bradley"]):
        return "plc"
    if any(k in text for k in ["switch", "catalyst", "aruba", "juniper"]):
        return "switch"
    return "unknown"


def _get_default_creds(device_type: str, vendor_hint: str = "") -> list[dict]:
    creds = DEFAULT_CREDS.get(device_type, [])
    if vendor_hint:
        vendor_lower = vendor_hint.lower()
        creds = [c for c in creds if vendor_lower in c["vendor"].lower()] or creds
    return creds[:5]


def _firmware_cves_for_vendor(product_text: str) -> list[str]:
    text = product_text.lower()
    cves = []
    for vendor, vcves in FIRMWARE_CVES.items():
        if vendor in text:
            cves.extend(vcves)
    return list(set(cves))


def run(target: str, query: str = "", api_key: str = "", deep: bool = False):
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    console.print(Panel(
        f"[bold #ff2d78]📡  IoT/Firmware OSINT[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    from omega_cli.config import load as load_cfg
    cfg = load_cfg()
    shodan_key = api_key or cfg.get("shodan_api_key", "")

    findings: dict[str, Any] = {"target": target}

    if is_ip:
        # IP-based lookup
        with console.status(f"[cyan]Querying Shodan InternetDB for {target}…"):
            idb = _shodan_internet_db(target)
        findings["internetdb"] = idb

        if idb:
            ports = idb.get("ports", [])
            cpes = idb.get("cpes", [])
            vulns = idb.get("vulns", [])
            hostnames = idb.get("hostnames", [])
            tags = idb.get("tags", [])

            console.print(f"\n[bold]Hostnames:[/bold] {', '.join(hostnames[:5]) or 'None'}")
            console.print(f"[bold]Open Ports:[/bold] {', '.join(str(p) for p in ports[:15])}")
            if tags:
                console.print(f"[bold]Tags:[/bold] {', '.join(tags)}")

            device_type = _classify_device(
                " ".join(hostnames), "", cpes
            )
            console.print(f"[bold]Device type:[/bold] [cyan]{device_type}[/cyan]")
            findings["device_type"] = device_type

            if vulns:
                t = Table("CVE", title=f"[bold red]⚠  {len(vulns)} Known Vuln(s)[/bold red]",
                          box=box.SIMPLE_HEAD, header_style="bold red")
                for v in vulns[:15]:
                    t.add_row(f"[red]{v}[/red]")
                console.print(t)
                findings["cves"] = list(vulns)

            # Default creds
            creds = _get_default_creds(device_type)
            if creds:
                console.print(f"\n[bold yellow]🔑 Default credentials for {device_type}:[/bold yellow]")
                t2 = Table("Vendor", "User", "Password", box=box.SIMPLE_HEAD, header_style="bold yellow")
                for c in creds:
                    t2.add_row(c["vendor"], c["user"], c["password"] or "[empty]")
                console.print(t2)
                findings["default_creds"] = creds

            # Firmware CVEs from CPE
            fw_cves = _firmware_cves_for_vendor(" ".join(cpes + hostnames))
            if fw_cves:
                console.print(f"\n[bold red]🔩 Known firmware CVEs:[/bold red]")
                for cve in fw_cves[:5]:
                    console.print(f"  [red]•[/red] {cve}")
                findings["firmware_cves"] = fw_cves

    else:
        # Device/vendor search
        search_q = query or f'product:"{target}"'
        console.print(f"[dim]Shodan search: {search_q}[/dim]")

        if shodan_key:
            with console.status("[cyan]Searching Shodan…"):
                shodan_results = _shodan_search(search_q, shodan_key)
            findings["shodan"] = shodan_results
            if shodan_results:
                t = Table("IP", "Port", "Country", "Product", "Version", "CVEs",
                          title=f"[bold]📡 {len(shodan_results)} Shodan Result(s)[/bold]",
                          box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
                for r in shodan_results:
                    t.add_row(
                        r.get("ip", "?"),
                        str(r.get("port", "?")),
                        r.get("country", "?")[:15],
                        (r.get("product") or "?")[:20],
                        (r.get("version") or "?")[:15],
                        ", ".join(r.get("vulns", [])[:2]),
                    )
                console.print(t)
        else:
            console.print("[dim]Set shodan_api_key for full Shodan search.[/dim]")

        # Show default creds for device type
        device_type = _classify_device("", target, [])
        creds = _get_default_creds(device_type if device_type != "unknown" else "router",
                                    vendor_hint=target)
        if creds:
            console.print(f"\n[bold yellow]🔑 Default credentials:[/bold yellow]")
            t3 = Table("Vendor", "Product", "User", "Password",
                       box=box.SIMPLE_HEAD, header_style="bold yellow")
            for c in creds:
                t3.add_row(c["vendor"], c["product"], c["user"], c["password"] or "[empty]")
            console.print(t3)

        # Known CVEs
        fw_cves = _firmware_cves_for_vendor(target.lower())
        if fw_cves:
            console.print(f"\n[bold red]🔩 Known CVEs for {target}:[/bold red]")
            for cve in fw_cves:
                console.print(f"  [red]•[/red] {cve}")
            findings["known_cves"] = fw_cves

    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"firmware_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
