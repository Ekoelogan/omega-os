"""omega crypto — Blockchain OSINT: BTC/ETH address & transaction analysis."""
from __future__ import annotations
import re
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

BTC_RE = re.compile(r"^(1|3|bc1)[A-Za-z0-9]{25,62}$")
ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

BTC_API = "https://blockchain.info/rawaddr/{addr}?limit=5"
ETH_API = "https://api.etherscan.io/api"
BTCABU  = "https://www.bitcoinabuse.com/api/reports/check?address={addr}&api_token=free"


def _detect_chain(addr: str) -> str:
    if BTC_RE.match(addr):
        return "BTC"
    if ETH_RE.match(addr):
        return "ETH"
    return "UNKNOWN"


def _btc_lookup(addr: str) -> None:
    console.print(f"[dim]Querying Blockchain.info for BTC address…[/dim]")
    try:
        resp = requests.get(BTC_API.format(addr=addr), timeout=12)
        resp.raise_for_status()
        data = resp.json()

        balance_btc = data.get("final_balance", 0) / 1e8
        total_recv  = data.get("total_received", 0) / 1e8
        total_sent  = data.get("total_sent", 0) / 1e8
        n_tx        = data.get("n_tx", 0)

        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column("Key",   style="bold #ff2d78")
        tbl.add_column("Value", style="white")
        tbl.add_row("Address",        addr)
        tbl.add_row("Chain",          "Bitcoin (BTC)")
        tbl.add_row("Balance",        f"{balance_btc:.8f} BTC")
        tbl.add_row("Total received", f"{total_recv:.8f} BTC")
        tbl.add_row("Total sent",     f"{total_sent:.8f} BTC")
        tbl.add_row("Transactions",   str(n_tx))
        console.print(tbl)

        txs = data.get("txs", [])[:5]
        if txs:
            console.print("\n[bold]Last 5 transactions:[/bold]")
            tx_tbl = Table(show_lines=True)
            tx_tbl.add_column("Hash",      style="cyan",  max_width=20)
            tx_tbl.add_column("Time",      style="dim")
            tx_tbl.add_column("Value (BTC)", style="white", justify="right")
            tx_tbl.add_column("Result",    style="white", justify="right")
            for tx in txs:
                import datetime
                ts  = datetime.datetime.fromtimestamp(tx.get("time", 0)).strftime("%Y-%m-%d %H:%M")
                val = tx.get("result", 0) / 1e8
                h   = tx.get("hash", "")
                tx_tbl.add_row(h[:16] + "…", ts, "—", f"{val:+.8f}")
            console.print(tx_tbl)

        # Abuse check
        try:
            ab = requests.get(BTCABU.format(addr=addr), timeout=6)
            if ab.ok:
                abusedata = ab.json()
                count = abusedata.get("count", 0)
                if count:
                    console.print(f"\n[bold red]⚠  {count} abuse report(s) on BitcoinAbuse.com[/bold red]")
        except Exception:
            pass

    except Exception as exc:
        console.print(f"[red]BTC lookup failed:[/red] {exc}")


def _eth_lookup(addr: str, api_key: str = "") -> None:
    console.print(f"[dim]Querying Etherscan for ETH address…[/dim]")
    try:
        params: dict = {"module": "account", "action": "balance",
                        "address": addr, "tag": "latest"}
        if api_key:
            params["apikey"] = api_key
        resp = requests.get(ETH_API, params=params, timeout=12)
        resp.raise_for_status()
        data = resp.json()
        wei = int(data.get("result", 0))
        eth = wei / 1e18

        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column("Key",   style="bold #ff2d78")
        tbl.add_column("Value", style="white")
        tbl.add_row("Address", addr)
        tbl.add_row("Chain",   "Ethereum (ETH)")
        tbl.add_row("Balance", f"{eth:.6f} ETH  ({wei} wei)")
        console.print(tbl)

        # Tx count
        params2 = {"module": "proxy", "action": "eth_getTransactionCount",
                   "address": addr, "tag": "latest"}
        if api_key:
            params2["apikey"] = api_key
        r2 = requests.get(ETH_API, params=params2, timeout=8)
        if r2.ok:
            hexval = r2.json().get("result", "0x0")
            console.print(f"[dim]Nonce / tx count:[/dim] {int(hexval, 16)}")

    except Exception as exc:
        console.print(f"[red]ETH lookup failed:[/red] {exc}")


def run(address: str, eth_api_key: str = "") -> None:
    chain = _detect_chain(address)
    console.print(Panel(
        f"[bold #ff2d78]₿  Blockchain OSINT[/bold #ff2d78]  →  [cyan]{address}[/cyan]  "
        f"([bold]{chain}[/bold])",
        expand=False,
    ))

    if chain == "BTC":
        _btc_lookup(address)
    elif chain == "ETH":
        _eth_lookup(address, api_key=eth_api_key)
    else:
        console.print("[yellow]Unknown address format. Supported: BTC (1/3/bc1…) and ETH (0x…)[/yellow]")
