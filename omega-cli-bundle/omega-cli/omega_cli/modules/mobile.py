"""omega mobile — Mobile app OSINT: APK/IPA static analysis, permissions, trackers, secrets."""
from __future__ import annotations
import json, os, re, zipfile, hashlib, datetime
from typing import Any
import httpx
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.tree import Tree

console = Console()
TIMEOUT = 10

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
}

TRACKER_SIGNATURES = {
    "Google Analytics":   ["com.google.android.gms.analytics", "GoogleAnalytics"],
    "Firebase":           ["com.google.firebase", "FirebaseAnalytics"],
    "Facebook SDK":       ["com.facebook.analytics", "FacebookSdk"],
    "Crashlytics":        ["com.crashlytics", "io.fabric"],
    "Mixpanel":           ["com.mixpanel.android"],
    "Amplitude":          ["com.amplitude.android"],
    "AppsFlyer":          ["com.appsflyer"],
    "Adjust":             ["com.adjust.sdk"],
    "Branch.io":          ["io.branch.referral"],
    "Intercom":           ["io.intercom.android"],
    "Segment":            ["com.segment.analytics"],
    "OneSignal":          ["com.onesignal"],
    "AppLovin":           ["com.applovin"],
    "AdMob":              ["com.google.android.gms.ads"],
    "Kochava":            ["com.kochava.base"],
    "Singular":           ["com.singular.sdk"],
}

SECRET_PATTERNS = [
    (r"AIza[0-9A-Za-z\-_]{35}",          "Google API Key"),
    (r"AKIA[0-9A-Z]{16}",                  "AWS Access Key"),
    (r"sk-[a-zA-Z0-9]{48}",               "OpenAI Key"),
    (r"ghp_[a-zA-Z0-9]{36}",              "GitHub PAT"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,48}", "Slack Token"),
    (r"ya29\.[0-9A-Za-z\-_]+",            "Google OAuth Token"),
    (r"['\"]password['\"]:\s*['\"][^'\"]{6,}['\"]", "Hardcoded password"),
    (r"['\"]api_?key['\"]:\s*['\"][a-zA-Z0-9]{16,}['\"]", "API Key in JSON"),
    (r"BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY", "Private Key"),
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "Email address"),
]

URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9.\-_/?=&%#@:+,;~]+", re.IGNORECASE
)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_apk(apk_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": "APK",
        "permissions": [],
        "dangerous_permissions": [],
        "trackers": [],
        "secrets": [],
        "urls": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "file_list": [],
        "native_libs": [],
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            result["file_list"] = names[:50]
            result["file_count"] = len(names)

            # Native libs
            result["native_libs"] = [n for n in names if n.endswith(".so")]

            # Parse AndroidManifest.xml (binary XML — read as bytes, grep patterns)
            if "AndroidManifest.xml" in names:
                manifest_bytes = zf.read("AndroidManifest.xml")
                manifest_str = manifest_bytes.decode("latin-1")

                # Extract permission strings
                for m in re.finditer(r"android\.permission\.[A-Z_]+", manifest_str):
                    p = m.group(0)
                    if p not in result["permissions"]:
                        result["permissions"].append(p)
                    if p in DANGEROUS_PERMISSIONS and p not in result["dangerous_permissions"]:
                        result["dangerous_permissions"].append(p)

                # Activities / services
                for m in re.finditer(r'[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*){2,}Activity', manifest_str):
                    if m.group(0) not in result["activities"]:
                        result["activities"].append(m.group(0))

            # Scan DEX/class files for trackers + secrets + URLs
            dex_files = [n for n in names if n.endswith(".dex")]
            all_text = ""
            for dex in dex_files[:5]:
                try:
                    data = zf.read(dex).decode("latin-1")
                    all_text += data
                except Exception:
                    pass

            # Also scan assets/res
            for name in names:
                if any(name.endswith(ext) for ext in (".json", ".xml", ".js", ".properties", ".conf")):
                    try:
                        data = zf.read(name).decode("utf-8", errors="ignore")
                        all_text += data
                    except Exception:
                        pass

            # Trackers
            for tracker, sigs in TRACKER_SIGNATURES.items():
                for sig in sigs:
                    if sig in all_text:
                        if tracker not in result["trackers"]:
                            result["trackers"].append(tracker)
                        break

            # Secrets
            for pattern, label in SECRET_PATTERNS:
                for m in re.finditer(pattern, all_text):
                    val = m.group(0)[:80]
                    if val not in [s["value"] for s in result["secrets"]]:
                        result["secrets"].append({"type": label, "value": val})
                    if len(result["secrets"]) >= 30:
                        break

            # URLs
            for m in URL_PATTERN.finditer(all_text):
                url = m.group(0)[:120]
                if url not in result["urls"] and not any(skip in url for skip in ["schemas.android", "www.w3.org"]):
                    result["urls"].append(url)
                if len(result["urls"]) >= 50:
                    break

    except zipfile.BadZipFile:
        result["error"] = "Not a valid APK/ZIP file"
    except Exception as e:
        result["error"] = str(e)

    return result


def _lookup_app_store(package_or_name: str) -> dict:
    """Lookup app metadata from Google Play / App Store."""
    results: dict[str, Any] = {}
    # Google Play (via scraping public page)
    try:
        url = f"https://play.google.com/store/apps/details?id={package_or_name}&hl=en"
        r = httpx.get(url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0"},
                      follow_redirects=True)
        if r.status_code == 200:
            body = r.text
            title_m = re.search(r'<title>([^<]+)</title>', body)
            rating_m = re.search(r'"ratingValue":"([0-9.]+)"', body)
            installs_m = re.search(r'"[0-9,]+ downloads"', body)
            results["google_play"] = {
                "url": url,
                "title": title_m.group(1).replace(" - Apps on Google Play", "") if title_m else "?",
                "rating": rating_m.group(1) if rating_m else "?",
                "package": package_or_name,
            }
    except Exception:
        pass

    # App Store lookup (by name)
    try:
        r2 = httpx.get(
            "https://itunes.apple.com/search",
            params={"term": package_or_name, "entity": "software", "limit": 1},
            timeout=TIMEOUT,
        )
        if r2.status_code == 200:
            items = r2.json().get("results", [])
            if items:
                app = items[0]
                results["app_store"] = {
                    "name": app.get("trackName"),
                    "developer": app.get("artistName"),
                    "version": app.get("version"),
                    "rating": app.get("averageUserRating"),
                    "reviews": app.get("userRatingCount"),
                    "url": app.get("trackViewUrl"),
                    "bundle_id": app.get("bundleId"),
                    "description": (app.get("description") or "")[:200],
                    "permissions": app.get("features", []),
                }
    except Exception:
        pass

    return results


def run(target: str, apk_file: str = "", store_lookup: bool = True):
    console.print(Panel(
        f"[bold #ff2d78]📱  Mobile App OSINT[/bold #ff2d78] — [cyan]{target}[/cyan]",
        box=box.ROUNDED
    ))

    findings: dict[str, Any] = {"target": target}

    # APK static analysis
    apk_path = apk_file or (target if target.endswith(".apk") else "")
    if apk_path and os.path.exists(apk_path):
        console.print(f"\n[bold]Static Analysis:[/bold] {apk_path}")
        findings["sha256"] = _sha256_file(apk_path)
        console.print(f"  SHA256: [dim]{findings['sha256']}[/dim]")

        with console.status("[cyan]Parsing APK…"):
            apk = _parse_apk(apk_path)
        findings["static"] = apk

        if apk.get("error"):
            console.print(f"[red]Error: {apk['error']}[/red]")
        else:
            # Permissions
            dp = apk.get("dangerous_permissions", [])
            console.print(f"\n[bold]Permissions:[/bold] {len(apk.get('permissions', []))} total, "
                          f"[{'red' if dp else 'green'}]{len(dp)} dangerous[/{'red' if dp else 'green'}]")
            if dp:
                t = Table("Dangerous Permission", box=box.SIMPLE_HEAD, header_style="bold red")
                for p in dp:
                    t.add_row(f"[red]{p}[/red]")
                console.print(t)

            # Trackers
            trackers = apk.get("trackers", [])
            if trackers:
                console.print(f"\n[bold yellow]📡 Tracker SDKs ({len(trackers)}):[/bold yellow]")
                for tr in trackers:
                    console.print(f"  [yellow]•[/yellow] {tr}")

            # Secrets
            secrets = apk.get("secrets", [])
            if secrets:
                console.print(f"\n[bold red]🔑 Hardcoded Secrets ({len(secrets)}):[/bold red]")
                t2 = Table("Type", "Value (truncated)", box=box.SIMPLE_HEAD, header_style="bold red")
                for s in secrets[:15]:
                    t2.add_row(s["type"], s["value"][:60] + ("…" if len(s["value"]) > 60 else ""))
                console.print(t2)

            # Endpoints
            urls = apk.get("urls", [])
            if urls:
                console.print(f"\n[bold]🌐 Embedded URLs ({len(urls)}):[/bold]")
                for u in urls[:15]:
                    console.print(f"  [cyan]{u}[/cyan]")

            # Native libs
            libs = apk.get("native_libs", [])
            if libs:
                console.print(f"\n[dim]Native libs: {', '.join(libs[:5])}[/dim]")

    # App store lookup
    if store_lookup:
        with console.status("[cyan]Querying app stores…"):
            store = _lookup_app_store(target)
        findings["store"] = store

        if store.get("google_play"):
            gp = store["google_play"]
            console.print(f"\n[bold]Google Play:[/bold] [cyan]{gp.get('title')}[/cyan] "
                          f"(⭐ {gp.get('rating')}) — {gp.get('url')}")

        if store.get("app_store"):
            ap = store["app_store"]
            console.print(f"\n[bold]App Store:[/bold] [cyan]{ap.get('name')}[/cyan] "
                          f"by {ap.get('developer')} v{ap.get('version')} "
                          f"⭐ {ap.get('rating')} ({ap.get('reviews')} reviews)")
            if ap.get("bundle_id"):
                console.print(f"  Bundle ID: [dim]{ap.get('bundle_id')}[/dim]")

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
    out_file = os.path.join(out_dir, f"mobile_{safe}_{ts}.json")
    with open(out_file, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out_file}[/dim]")
