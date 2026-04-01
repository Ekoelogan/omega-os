"""omega stix — STIX 2.1 threat intelligence bundle export from omega findings."""
from __future__ import annotations
import json, os, re, uuid, datetime, glob
from typing import Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# STIX 2.1 type mappings from omega IOC types
IOC_TO_STIX = {
    "ipv4":       ("ipv4-addr", "value"),
    "ipv6":       ("ipv6-addr", "value"),
    "domain":     ("domain-name", "value"),
    "subdomain":  ("domain-name", "value"),
    "url":        ("url", "value"),
    "email":      ("email-addr", "value"),
    "md5":        ("file", "hashes.MD5"),
    "sha1":       ("file", "hashes.SHA-1"),
    "sha256":     ("file", "hashes.SHA-256"),
    "onion":      ("domain-name", "value"),
    "cve":        ("vulnerability", "name"),
    "asn":        ("autonomous-system", "number"),
}

STIX_MARKING = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--tlp-white",
    "definition_type": "tlp",
    "definition": {"tlp": "white"},
}


def _new_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def _timestamp() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_identity(name: str = "omega-cli") -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _new_id("identity"),
        "name": name,
        "identity_class": "tool",
        "created": _timestamp(),
        "modified": _timestamp(),
    }


def _ioc_to_observable(ioc_type: str, value: str) -> dict | None:
    """Convert an omega IOC to a STIX 2.1 Cyber Observable."""
    mapping = IOC_TO_STIX.get(ioc_type)
    if not mapping:
        return None
    stix_type, field = mapping

    obj: dict[str, Any] = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": _new_id(stix_type),
    }

    if "." in field:
        # Nested field (e.g. hashes.MD5)
        parts = field.split(".", 1)
        obj["name"] = value
        obj[parts[0]] = {parts[1]: value}
    else:
        if stix_type == "autonomous-system":
            # Strip "AS" prefix
            num = re.sub(r"^AS", "", value, flags=re.IGNORECASE)
            try:
                obj[field] = int(num)
            except ValueError:
                obj[field] = value
        else:
            obj[field] = value

    return obj


def _make_indicator(observable: dict, ioc_type: str, value: str, pattern_lang: str = "stix") -> dict:
    """Wrap an observable in a STIX Indicator SDO."""
    # Build pattern
    type_map = {
        "ipv4-addr":   f"[ipv4-addr:value = '{value}']",
        "ipv6-addr":   f"[ipv6-addr:value = '{value}']",
        "domain-name": f"[domain-name:value = '{value}']",
        "url":         f"[url:value = '{value}']",
        "email-addr":  f"[email-addr:value = '{value}']",
        "file":        f"[file:hashes.MD5 = '{value}']",
        "vulnerability": f"[vulnerability:name = '{value}']",
    }
    stix_type = observable.get("type", "")
    pattern = type_map.get(stix_type, f"[{stix_type}:value = '{value}']")

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _new_id("indicator"),
        "name": f"{ioc_type}: {value[:60]}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _timestamp(),
        "created": _timestamp(),
        "modified": _timestamp(),
        "labels": [ioc_type, "omega-cli"],
        "object_refs": [observable["id"]],
    }


def _load_omega_reports(target: str, report_dir: str) -> list[dict]:
    """Load all omega JSON reports matching target."""
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    pattern = os.path.join(report_dir, f"*{safe}*.json")
    reports = []
    for f in glob.glob(pattern):
        try:
            with open(f) as fh:
                data = json.load(fh)
            data["_source_file"] = os.path.basename(f)
            reports.append(data)
        except Exception:
            pass
    return reports


def _extract_iocs_from_report(report: dict) -> list[tuple[str, str]]:
    """Extract (ioc_type, value) pairs from any omega report."""
    iocs: list[tuple[str, str]] = []

    FIELD_MAP = {
        "ips":        "ipv4",
        "subdomains": "subdomain",
        "domains":    "domain",
        "emails":     "email",
        "urls":       "url",
        "hashes":     "sha256",
    }

    for field, ioc_type in FIELD_MAP.items():
        val = report.get(field)
        if isinstance(val, list):
            for item in val:
                if item:
                    iocs.append((ioc_type, str(item)))

    # IOC extractor output
    ioc_data = report.get("iocs", {})
    if isinstance(ioc_data, dict):
        for ioc_type, items in ioc_data.items():
            if isinstance(items, list):
                for item in items:
                    if item:
                        iocs.append((ioc_type, str(item)))

    # CVEs
    ports = report.get("ports", [])
    for p in ports:
        if isinstance(p, dict) and p.get("cves"):
            for cve in p["cves"]:
                iocs.append(("cve", str(cve)))

    return list(set(iocs))


def _build_stix_bundle(
    target: str,
    reports: list[dict],
    tlp: str = "white",
    include_indicators: bool = True,
) -> dict:
    """Build a full STIX 2.1 bundle."""
    bundle_id = _new_id("bundle")
    identity = _make_identity()
    objects: list[dict] = [STIX_MARKING, identity]

    # Target as identity/domain
    target_obj: dict[str, Any] = {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": _new_id("domain-name"),
        "value": target,
    }
    objects.append(target_obj)

    seen_values: set = set()
    observable_ids: list[str] = [target_obj["id"]]

    for report in reports:
        iocs = _extract_iocs_from_report(report)
        for ioc_type, value in iocs:
            key = (ioc_type, value)
            if key in seen_values:
                continue
            seen_values.add(key)

            obs = _ioc_to_observable(ioc_type, value)
            if obs:
                objects.append(obs)
                observable_ids.append(obs["id"])
                if include_indicators:
                    ind = _make_indicator(obs, ioc_type, value)
                    objects.append(ind)

    # Observed data wrapping all observables
    if observable_ids:
        observed = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": _new_id("observed-data"),
            "created_by_ref": identity["id"],
            "created": _timestamp(),
            "modified": _timestamp(),
            "first_observed": _timestamp(),
            "last_observed": _timestamp(),
            "number_observed": len(observable_ids),
            "object_refs": observable_ids[:100],
        }
        objects.append(observed)

    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }


def run(
    target: str,
    json_file: str = "",
    output: str = "",
    tlp: str = "white",
    no_indicators: bool = False,
    report_dir: str = "",
):
    console.print(Panel(
        f"[bold #ff2d78]🔰  STIX 2.1 Export[/bold #ff2d78] — [cyan]{target}[/cyan]  "
        f"[dim]TLP:{tlp.upper()}[/dim]",
        box=box.ROUNDED
    ))

    rdir = report_dir or os.path.expanduser("~/.omega/reports")

    if json_file and os.path.exists(json_file):
        with open(json_file) as f:
            data = json.load(f)
        data["_source_file"] = os.path.basename(json_file)
        reports = [data]
    else:
        with console.status("[cyan]Loading omega reports…"):
            reports = _load_omega_reports(target, rdir)

    if not reports:
        console.print("[yellow]No omega reports found. Run some recon first.[/yellow]")
        return

    console.print(f"[dim]Loaded {len(reports)} report(s)[/dim]")

    with console.status("[cyan]Building STIX 2.1 bundle…"):
        bundle = _build_stix_bundle(target, reports, tlp, not no_indicators)

    # Stats
    type_counts: dict[str, int] = {}
    for obj in bundle["objects"]:
        type_counts[obj["type"]] = type_counts.get(obj["type"], 0) + 1

    t = Table("STIX Type", "Count",
              title=f"[bold]📦 Bundle: {len(bundle['objects'])} objects[/bold]",
              box=box.SIMPLE_HEAD, header_style="bold #ff2d78")
    for stype, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        t.add_row(stype, str(cnt))
    console.print(t)

    # Output
    if not output:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
        output = os.path.join(rdir, f"stix_{safe}_{ts}.json")

    with open(output, "w") as f:
        json.dump(bundle, f, indent=2)

    size = os.path.getsize(output)
    console.print(f"\n[bold green]✓  STIX bundle saved![/bold green]")
    console.print(f"   File:    [cyan]{output}[/cyan]")
    console.print(f"   Objects: {len(bundle['objects'])}")
    console.print(f"   Size:    {size:,} bytes")
    console.print(f"   TLP:     {tlp.upper()}")
    console.print(f"\n[dim]Compatible with: MISP, OpenCTI, TheHive, Cortex XSOAR[/dim]")
