"""Headless browser screenshots using Playwright."""
import os
import asyncio
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

OUTPUT_DIR = Path.home() / "omega-reports" / "screenshots"


def _ensure_playwright():
    try:
        from playwright.async_api import async_playwright
        return True
    except ImportError:
        return False


async def _screenshot_url(url: str, output_path: str, width: int = 1280, full_page: bool = True):
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=[
            "--no-sandbox", "--disable-setuid-sandbox",
            "--disable-dev-shm-usage", "--disable-gpu",
        ])
        context = await browser.new_context(
            viewport={"width": width, "height": 720},
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True,
        )
        page = await context.new_page()
        try:
            resp = await page.goto(url, wait_until="networkidle", timeout=20000)
            status = resp.status if resp else 0
            title = await page.title()
            await page.screenshot(path=output_path, full_page=full_page, type="png")
            await browser.close()
            return {"url": url, "status": status, "title": title, "path": output_path, "ok": True}
        except Exception as e:
            await browser.close()
            return {"url": url, "error": str(e), "ok": False}


async def _screenshot_batch(urls: list, output_dir: Path, width: int = 1280) -> list:
    from playwright.async_api import async_playwright
    results = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=[
            "--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu",
        ])
        sem = asyncio.Semaphore(3)  # max 3 concurrent

        async def shot(url: str):
            async with sem:
                safe = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")[:80]
                out = str(output_dir / f"{safe}.png")
                context = await browser.new_context(
                    viewport={"width": width, "height": 720},
                    ignore_https_errors=True,
                )
                page = await context.new_page()
                try:
                    resp = await page.goto(url, wait_until="networkidle", timeout=20000)
                    status = resp.status if resp else 0
                    title = await page.title()
                    await page.screenshot(path=out, full_page=False, type="png")
                    await context.close()
                    return {"url": url, "status": status, "title": title, "path": out, "ok": True}
                except Exception as e:
                    await context.close()
                    return {"url": url, "error": str(e)[:60], "ok": False}

        tasks = [shot(url) for url in urls]
        results = await asyncio.gather(*tasks)
        await browser.close()
    return list(results)


def _install_playwright():
    console.print("[dim]Installing Playwright Chromium (one-time setup)...[/]")
    ret = os.system("playwright install chromium --with-deps 2>&1 | tail -5")
    return ret == 0


def run(targets: list, width: int = 1280, full_page: bool = True, output_dir: str = ""):
    """Take screenshots of one or more URLs."""
    out_dir = Path(output_dir) if output_dir else OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(Panel(
        f"[bold #ff2d78]📸 Screenshot Engine[/]\n"
        f"[dim]Targets:[/] {len(targets)}  [dim]Output:[/] [cyan]{out_dir}[/]",
        border_style="#ff85b3",
    ))

    if not _ensure_playwright():
        console.print("[yellow]Playwright not installed.[/]  Installing...")
        os.system("pip install playwright 2>&1 | tail -3")
        _install_playwright()
        if not _ensure_playwright():
            console.print("[red]Playwright install failed.[/]  Try: [cyan]pip install playwright && playwright install chromium[/]")
            return []

    # Check if chromium is available
    chromium_ok = os.system("playwright install chromium --with-deps > /dev/null 2>&1") == 0

    results = []
    if len(targets) == 1:
        safe = targets[0].replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")[:80]
        out_path = str(out_dir / f"{safe}.png")
        try:
            result = asyncio.run(_screenshot_url(targets[0], out_path, width, full_page))
            results.append(result)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(_screenshot_url(targets[0], out_path, width, full_page))
            loop.close()
            results.append(result)
    else:
        try:
            results = asyncio.run(_screenshot_batch(targets, out_dir, width))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            results = loop.run_until_complete(_screenshot_batch(targets, out_dir, width))
            loop.close()

    tbl = Table(
        title=f"Screenshots ({len(results)})",
        box=box.ROUNDED, border_style="#ff85b3",
    )
    tbl.add_column("URL", style="cyan")
    tbl.add_column("Title")
    tbl.add_column("Status", width=8)
    tbl.add_column("File")

    for r in results:
        if r.get("ok"):
            tbl.add_row(
                r["url"][:60], r.get("title", "")[:40],
                f"[green]{r.get('status','')}[/]",
                Path(r["path"]).name,
            )
        else:
            tbl.add_row(
                r["url"][:60], f"[red]{r.get('error','failed')}[/]",
                "[red]ERR[/]", "",
            )
    console.print(tbl)
    return results
