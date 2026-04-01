"""omega docosint — Document/file OSINT: PDF/Office metadata, author, creation date,
embedded URLs, hidden text, revision history, and secret patterns."""
from __future__ import annotations
import json, os, re, zipfile, datetime, struct
from typing import Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def _extract_pdf_metadata(data: bytes) -> dict[str, Any]:
    """Extract metadata from raw PDF bytes without external libs."""
    result: dict[str, Any] = {}
    text = data.decode("latin-1", errors="ignore")

    # Info dictionary fields
    info_fields = {
        "Title":    r"/Title\s*\(([^)]+)\)",
        "Author":   r"/Author\s*\(([^)]+)\)",
        "Subject":  r"/Subject\s*\(([^)]+)\)",
        "Creator":  r"/Creator\s*\(([^)]+)\)",
        "Producer": r"/Producer\s*\(([^)]+)\)",
        "Keywords": r"/Keywords\s*\(([^)]+)\)",
        "CreationDate": r"/CreationDate\s*\(([^)]+)\)",
        "ModDate":  r"/ModDate\s*\(([^)]+)\)",
    }
    for field, pat in info_fields.items():
        m = re.search(pat, text)
        if m:
            result[field] = m.group(1).strip()

    # Page count
    pages = re.findall(r"/Type\s*/Page\b", text)
    result["PageCount"] = len(pages)

    # PDF version
    m = re.match(r"%PDF-(\d+\.\d+)", text)
    if m:
        result["PDFVersion"] = m.group(1)

    # Embedded URLs
    urls = list(set(re.findall(r"https?://[^\s\)>\"]+", text)))
    result["EmbeddedURLs"] = [u[:120] for u in urls[:20]]

    # JavaScript (suspicious)
    js = re.findall(r"/JS\s*\(([^)]{0,80})\)", text)
    if js:
        result["JavaScript"] = js[:5]

    # OpenAction / Launch actions
    if "/OpenAction" in text:
        result["HasOpenAction"] = True
    if "/Launch" in text:
        result["HasLaunch"] = True

    # Revision count
    revs = text.count("%%EOF")
    if revs > 1:
        result["Revisions"] = revs

    # XMP metadata
    xmp_m = re.search(r"<x:xmpmeta[^>]*>(.*?)</x:xmpmeta>", text, re.DOTALL)
    if xmp_m:
        xmp = xmp_m.group(1)
        for tag in ["dc:creator", "xmp:CreatorTool", "xmp:CreateDate", "xmp:ModifyDate",
                    "xmpMM:DocumentID", "xmpMM:OriginalDocumentID"]:
            tm = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xmp, re.DOTALL)
            if tm:
                result[f"XMP_{tag}"] = re.sub(r"<[^>]+>", "", tm.group(1)).strip()[:80]

    return result


def _extract_office_metadata(path: str) -> dict[str, Any]:
    """Extract metadata from OOXML (.docx/.xlsx/.pptx)."""
    result: dict[str, Any] = {}
    try:
        with zipfile.ZipFile(path, "r") as z:
            names = z.namelist()

            # Core properties
            if "docProps/core.xml" in names:
                core = z.read("docProps/core.xml").decode("utf-8", errors="ignore")
                fields = {
                    "Title":          r"<dc:title>(.*?)</dc:title>",
                    "Author":         r"<dc:creator>(.*?)</dc:creator>",
                    "LastAuthor":     r"<cp:lastModifiedBy>(.*?)</cp:lastModifiedBy>",
                    "Created":        r"<dcterms:created[^>]*>(.*?)</dcterms:created>",
                    "Modified":       r"<dcterms:modified[^>]*>(.*?)</dcterms:modified>",
                    "Description":    r"<dc:description>(.*?)</dc:description>",
                    "Keywords":       r"<cp:keywords>(.*?)</cp:keywords>",
                    "Category":       r"<cp:category>(.*?)</cp:category>",
                    "Revision":       r"<cp:revision>(.*?)</cp:revision>",
                    "ContentStatus":  r"<cp:contentStatus>(.*?)</cp:contentStatus>",
                }
                for field, pat in fields.items():
                    m = re.search(pat, core)
                    if m:
                        result[field] = m.group(1).strip()

            # App properties
            if "docProps/app.xml" in names:
                app = z.read("docProps/app.xml").decode("utf-8", errors="ignore")
                for field, pat in [
                    ("Application",  r"<Application>(.*?)</Application>"),
                    ("Company",      r"<Company>(.*?)</Company>"),
                    ("Pages",        r"<Pages>(.*?)</Pages>"),
                    ("Words",        r"<Words>(.*?)</Words>"),
                    ("AppVersion",   r"<AppVersion>(.*?)</AppVersion>"),
                ]:
                    m = re.search(pat, app)
                    if m:
                        result[field] = m.group(1).strip()

            # Extract all URLs from document
            urls = set()
            for name in names:
                if name.endswith(".rels") or name.endswith(".xml"):
                    try:
                        content = z.read(name).decode("utf-8", errors="ignore")
                        found = re.findall(r"https?://[^\s\"<>]+", content)
                        urls.update(found[:10])
                    except Exception:
                        pass
            result["EmbeddedURLs"] = [u[:120] for u in list(urls)[:20]]

            # Template reference
            for name in names:
                if "settings.xml" in name:
                    try:
                        settings = z.read(name).decode("utf-8", errors="ignore")
                        tm = re.search(r'Target="([^"]+\.dot[mx]?)"', settings)
                        if tm:
                            result["Template"] = tm.group(1)
                    except Exception:
                        pass

    except (zipfile.BadZipFile, Exception):
        pass
    return result


def _extract_ole_metadata(data: bytes) -> dict[str, Any]:
    """Minimal OLE2 (.doc/.xls/.ppt) metadata extraction."""
    result: dict[str, Any] = {}
    # OLE2 magic
    if data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return result

    # Scan for readable strings that look like author/title
    text = data.decode("utf-16-le", errors="ignore")
    for pat, key in [
        (r"(?:Author|Creator)[:\s]+([A-Za-z][A-Za-z\s]{2,40})", "Author"),
        (r"(?:Title)[:\s]+([A-Za-z][A-Za-z\s]{2,60})", "Title"),
    ]:
        m = re.search(pat, text)
        if m:
            result[key] = m.group(1).strip()

    urls = list(set(re.findall(r"https?://[^\x00\s]{5,100}", text)))
    if urls:
        result["EmbeddedURLs"] = urls[:10]

    result["Format"] = "OLE2 (legacy Office)"
    return result


def _scan_secrets(content: str) -> list[dict]:
    patterns = [
        (r"AKIA[0-9A-Z]{16}",           "AWS Access Key ID"),
        (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "Password field"),
        (r"ghp_[A-Za-z0-9]{36}",         "GitHub Personal Access Token"),
        (r"-----BEGIN [A-Z ]+PRIVATE KEY-----", "Private Key"),
        (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "Email address"),
        (r"\b(?:\d{4}[- ]){3}\d{4}\b",   "Credit card pattern"),
        (r"\b\d{3}-\d{2}-\d{4}\b",        "SSN pattern"),
    ]
    hits = []
    for pat, label in patterns:
        matches = re.findall(pat, content, re.I)
        for m in matches[:3]:
            hits.append({"type": label, "value": str(m)[:60]})
    return hits[:10]


def run(file_path: str, show_urls: bool = True, show_secrets: bool = True):
    if not os.path.exists(file_path):
        console.print(f"[red]File not found: {file_path}[/red]")
        return

    fname = os.path.basename(file_path)
    ext   = os.path.splitext(fname)[1].lower()
    size  = os.path.getsize(file_path)

    console.print(Panel(
        f"[bold #ff2d78]📄  Document OSINT[/bold #ff2d78] — [cyan]{fname}[/cyan]",
        box=box.ROUNDED
    ))
    console.print(f"[dim]Size: {size:,} bytes  |  Type: {ext}[/dim]\n")

    with open(file_path, "rb") as f:
        raw = f.read()

    findings: dict[str, Any] = {"file": file_path, "size": size, "extension": ext}
    meta: dict[str, Any] = {}

    if ext == ".pdf":
        meta = _extract_pdf_metadata(raw)
    elif ext in (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"):
        meta = _extract_office_metadata(file_path)
    elif ext in (".doc", ".xls", ".ppt"):
        meta = _extract_ole_metadata(raw)
    else:
        # Generic: try as zip (OOXML), then PDF, then raw string scan
        meta = _extract_office_metadata(file_path)
        if not meta:
            meta = _extract_pdf_metadata(raw)

    findings["metadata"] = meta

    # Display metadata
    skip = {"EmbeddedURLs", "JavaScript"}
    display_meta = {k: v for k, v in meta.items() if k not in skip and v}
    if display_meta:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        t.add_column("Field", style="bold #ff2d78", width=20)
        t.add_column("Value", style="cyan")
        for k, v in display_meta.items():
            if isinstance(v, bool):
                t.add_row(k, "[red]YES[/red]" if v else "No")
            else:
                t.add_row(k, str(v)[:90])
        console.print(t)
    else:
        console.print("[dim]No metadata extracted[/dim]")

    # Embedded URLs
    urls = meta.get("EmbeddedURLs", [])
    if urls and show_urls:
        console.print(f"\n[bold]🔗 Embedded URLs ({len(urls)}):[/bold]")
        for url in urls[:15]:
            console.print(f"  [cyan]•[/cyan] {url}")
        findings["embedded_urls"] = urls

    # JavaScript / macros warning
    if meta.get("JavaScript") or meta.get("HasLaunch") or meta.get("HasOpenAction"):
        console.print("\n[bold red]⚠  Active content detected (JavaScript/Launch/OpenAction)[/bold red]")
        findings["active_content"] = True

    # Secret scan
    if show_secrets:
        text_content = raw.decode("latin-1", errors="ignore")
        secrets = _scan_secrets(text_content)
        if secrets:
            console.print(f"\n[bold red]⚠  {len(secrets)} potential secret(s) found:[/bold red]")
            st = Table("Type", "Value", box=box.SIMPLE_HEAD, header_style="bold red")
            for s in secrets:
                st.add_row(s["type"], s["value"])
            console.print(st)
            findings["secrets"] = secrets

    # Revision history
    if meta.get("Revisions", 0) > 1 or meta.get("Revision", "1") not in ("0", "1", ""):
        console.print(f"\n[yellow]📝 Document has revision history — may contain deleted content[/yellow]")

    # Save
    out_dir = os.path.expanduser("~/.omega/reports")
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_.]", "_", fname)
    out = os.path.join(out_dir, f"docosint_{safe}_{ts}.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)
    console.print(f"\n[dim]Saved → {out}[/dim]")
