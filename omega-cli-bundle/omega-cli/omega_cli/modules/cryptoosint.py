"""cryptoosint.py — Blockchain OSINT: BTC/ETH address analysis, tx history, mixing, exchange ID."""
from __future__ import annotations
import json, re, time
from pathlib import Path
from typing import Optional
import urllib.request, urllib.error

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **kw): print(*a)
    console = Console()
    Table = Panel = box = None

BANNER = r"""
██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  OMEGA-CLI v1.7.0 — OSINT & Passive Recon Toolkit
"""

UA = "Mozilla/5.0 (compatible; OmegaCLI/1.7.0)"

SATOSHI = 1e8

# Known address clusters (simplified — exchange hot wallets, mixers etc.)
KNOWN_CLUSTERS = {
    # Exchanges
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na": "Bitcoin Genesis Block",
    "3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6": "Binance",
    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h": "Binance",
    "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97": "BitFinex",
    "3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64": "BitFinex",
    "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s": "Binance Cold",
    "bc1qazcm763858nkj2dj986etajv6wquslv8uxjv5": "Kraken",
    "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe": "Ethereum Foundation",
    "0xab5801a7d398351b8be11c439e05c5b3259aec9b": "Vitalik Buterin",
}

# Mixer/tumbler patterns
MIXING_INDICATORS = [
    "coinjoin", "wasabi", "joinmarket", "chipmixer", "tornado",
    "samourai", "whirlpool", "blender", "bitblender",
]

# BTC address regex
BTC_RE = re.compile(r"^(1|3|bc1)[A-Za-z0-9]{25,62}$")
ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _get_json(url: str, timeout: int = 10) -> Optional[dict | list]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _btc_blockchain_info(address: str) -> dict:
    """Blockchain.info API — free, no key."""
    data = _get_json(f"https://blockchain.info/rawaddr/{address}?limit=10")
    return data or {}


def _btc_blockchair(address: str) -> dict:
    """Blockchair — free tier."""
    data = _get_json(f"https://api.blockchair.com/bitcoin/dashboards/address/{address}?limit=10,0")
    if data and "data" in data:
        return data["data"].get(address, {})
    return {}


def _eth_etherscan(address: str, api_key: str = "") -> dict:
    """Etherscan — free tier (5tx/s without key, 10tx/s with key)."""
    key_param = f"&apikey={api_key}" if api_key else ""
    txs = _get_json(f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&sort=desc&offset=10{key_param}")
    bal = _get_json(f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest{key_param}")
    return {
        "transactions": (txs or {}).get("result", [])[:10],
        "balance_wei":  (bal or {}).get("result", "0"),
    }


def _eth_blockchair(address: str) -> dict:
    data = _get_json(f"https://api.blockchair.com/ethereum/dashboards/address/{address}?limit=10,0")
    if data and "data" in data:
        return data["data"].get(address, {})
    return {}


def _check_chainalysis_sanctions(address: str) -> bool:
    """Check OFAC sanctions via free API."""
    data = _get_json(f"https://public.chainalysis.com/api/v1/address/{address}")
    if data and isinstance(data.get("identifications"), list):
        return len(data["identifications"]) > 0
    return False


def _detect_mixing(tx_list: list) -> dict:
    """Heuristic mixing/tumbler detection."""
    if not tx_list:
        return {"detected": False, "indicators": []}
    indicators = []
    # Round amount heuristic
    round_amounts = sum(1 for tx in tx_list
                       if isinstance(tx.get("value"), (int, float)) and tx.get("value", 0) % 1_000_000 == 0)
    if round_amounts > len(tx_list) * 0.6:
        indicators.append("Round amounts (CoinJoin pattern)")
    # Many equal-value outputs
    amounts = [tx.get("value", 0) for tx in tx_list]
    if len(set(amounts)) < len(amounts) * 0.3 and len(amounts) > 3:
        indicators.append("Equal-value outputs")
    return {"detected": bool(indicators), "indicators": indicators}


def _known_cluster(address: str) -> Optional[str]:
    return KNOWN_CLUSTERS.get(address)


def run(address: str, chain: str = "auto", api_key: str = "", export: str = ""):
    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"₿  Blockchain OSINT — {address}", style="bold cyan"))

    # Auto-detect chain
    if chain == "auto":
        if ETH_RE.match(address):
            chain = "eth"
        elif BTC_RE.match(address):
            chain = "btc"
        else:
            chain = "btc"
            console.print("[yellow]⚠ Could not auto-detect chain, defaulting to BTC[/yellow]")

    console.print(f"[cyan]Chain:[/cyan] {chain.upper()}")

    results = {
        "address": address,
        "chain":   chain,
        "balance": None,
        "tx_count": 0,
        "transactions": [],
        "mixing": {},
        "sanctions": False,
        "known_entity": None,
        "risk_score": 0,
        "risk_flags": [],
    }

    # Known entity check
    known = _known_cluster(address)
    if known:
        results["known_entity"] = known
        console.print(f"[bold green]Known Entity: {known}[/bold green]")

    if chain == "btc":
        console.print("\n[bold]Bitcoin Analysis[/bold]")

        # blockchain.info
        bi = _btc_blockchain_info(address)
        if bi:
            bal_sat = bi.get("final_balance", 0)
            bal_btc = bal_sat / SATOSHI
            results["balance"] = f"{bal_btc:.8f} BTC"
            results["tx_count"] = bi.get("n_tx", 0)
            results["total_received"] = f"{bi.get('total_received',0)/SATOSHI:.8f} BTC"
            results["total_sent"] = f"{bi.get('total_sent',0)/SATOSHI:.8f} BTC"

            console.print(f"  Balance:        [{'green' if bal_btc > 0 else 'dim'}]{bal_btc:.8f} BTC[/]")
            console.print(f"  Total received: {bi.get('total_received',0)/SATOSHI:.8f} BTC")
            console.print(f"  Total sent:     {bi.get('total_sent',0)/SATOSHI:.8f} BTC")
            console.print(f"  Transactions:   {results['tx_count']}")

            txs = bi.get("txs", [])
            results["transactions"] = []
            if txs:
                t = Table(title="Recent Transactions (last 10)", box=box.SIMPLE if box else None)
                t.add_column("TxID",    style="dim",    max_width=20)
                t.add_column("Time",    style="cyan")
                t.add_column("Inputs")
                t.add_column("Outputs")
                t.add_column("Value", style="yellow")
                for tx in txs[:10]:
                    txid = tx.get("hash", "")[:16] + "…"
                    ts = time.strftime("%Y-%m-%d", time.gmtime(tx.get("time", 0))) if tx.get("time") else ""
                    n_in  = len(tx.get("inputs", []))
                    n_out = len(tx.get("out",    []))
                    val = sum(o.get("value", 0) for o in tx.get("out", [])) / SATOSHI
                    t.add_row(txid, ts, str(n_in), str(n_out), f"{val:.4f}")
                    results["transactions"].append({"txid": tx.get("hash"), "time": ts, "value_btc": val})
                console.print(t)

                # Mixing detection
                mixing_input = [{"value": sum(o.get("value",0) for o in tx.get("out",[]))} for tx in txs]
                results["mixing"] = _detect_mixing(mixing_input)

        # Blockchair additional data
        bc = _btc_blockchair(address)
        if bc and bc.get("address"):
            addr_data = bc["address"]
            results["first_seen"] = addr_data.get("first_seen_receiving")
            results["last_seen"]  = addr_data.get("last_seen_receiving")
            console.print(f"  First seen: {results.get('first_seen', 'N/A')}")
            console.print(f"  Last seen:  {results.get('last_seen',  'N/A')}")

    elif chain == "eth":
        console.print("\n[bold]Ethereum Analysis[/bold]")

        eth = _eth_etherscan(address, api_key)
        bc  = _eth_blockchair(address)

        bal_wei = int(eth.get("balance_wei") or 0)
        bal_eth = bal_wei / 1e18
        results["balance"] = f"{bal_eth:.6f} ETH"

        if bc and bc.get("address"):
            addr = bc["address"]
            results["tx_count"] = addr.get("transaction_count", 0)
            console.print(f"  Balance:      [green]{bal_eth:.6f} ETH[/green]")
            console.print(f"  Transactions: {results['tx_count']}")
            console.print(f"  Type:         {'Contract' if addr.get('is_contract') else 'EOA (wallet)'}")

        txs = eth.get("transactions", [])
        results["transactions"] = []
        if txs:
            t = Table(title="Recent Transactions (last 10)", box=box.SIMPLE if box else None)
            t.add_column("TxHash",   style="dim",    max_width=20)
            t.add_column("Time",     style="cyan")
            t.add_column("From",     style="yellow", max_width=20)
            t.add_column("To",       style="green",  max_width=20)
            t.add_column("ETH",      style="bold")
            for tx in txs[:10]:
                ts = time.strftime("%Y-%m-%d", time.gmtime(int(tx.get("timeStamp",0)))) if tx.get("timeStamp") else ""
                val = int(tx.get("value", 0)) / 1e18
                t.add_row(
                    tx.get("hash","")[:16] + "…", ts,
                    tx.get("from","")[:16] + "…",
                    tx.get("to","")[:16] + "…",
                    f"{val:.4f}"
                )
                results["transactions"].append({"hash": tx.get("hash"), "time": ts, "value_eth": val})
            console.print(t)

    # Sanctions check
    console.print("\n[bold]Sanctions Check[/bold]")
    try:
        sanctioned = _check_chainalysis_sanctions(address)
        results["sanctions"] = sanctioned
        if sanctioned:
            console.print("  [red bold]⛔ SANCTIONED — appears on OFAC/Chainalysis list[/red bold]")
            results["risk_flags"].append("OFAC Sanctioned")
        else:
            console.print("  [green]✅ Not found in sanctions database[/green]")
    except Exception:
        console.print("  [dim]Sanctions check unavailable[/dim]")

    # Mixing report
    if results["mixing"].get("detected"):
        console.print(f"\n[red bold]⚠ Mixing/Tumbling Indicators:[/red bold]")
        for ind in results["mixing"]["indicators"]:
            console.print(f"  [yellow]• {ind}[/yellow]")
            results["risk_flags"].append(ind)

    # Risk score
    score = 0
    if results["sanctions"]:   score += 80
    if results["mixing"].get("detected"): score += 30
    if not results["known_entity"] and results.get("tx_count", 0) > 1000: score += 10
    score = min(100, score)
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"
    color = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"green"}[level]
    results["risk_score"] = score
    results["risk_level"] = level
    console.print(f"\n[bold]Risk Score:[/bold] [{color}]{score}/100 ({level})[/{color}]")
    if results["risk_flags"]:
        console.print(f"Flags: {', '.join(results['risk_flags'])}")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", address)
    out_path = Path(export) if export else out_dir / f"cryptoosint_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
