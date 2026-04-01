"""IP information and geolocation module."""
import ipwhois
import requests
from rich.console import Console
from rich.table import Table

console = Console()


def run(target: str):
    """Fetch IP info: geolocation, ASN, ISP, abuse contacts."""
    console.print(f"\n[bold cyan][ IP INFO ] {target}[/bold cyan]\n")

    # Public IP geolocation via ip-api.com (no key required)
    try:
        r = requests.get(f"http://ip-api.com/json/{target}?fields=66846719", timeout=5)
        data = r.json()

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow")
        table.add_column("Value", style="white")

        geo_fields = {
            "IP": data.get("query"),
            "Status": data.get("status"),
            "Country": f"{data.get('country')} ({data.get('countryCode')})",
            "Region": f"{data.get('regionName')} ({data.get('region')})",
            "City": data.get("city"),
            "ZIP": data.get("zip"),
            "Lat/Lon": f"{data.get('lat')}, {data.get('lon')}",
            "Timezone": data.get("timezone"),
            "ISP": data.get("isp"),
            "Org": data.get("org"),
            "ASN": data.get("as"),
            "Reverse DNS": data.get("reverse"),
            "Mobile": str(data.get("mobile")),
            "Proxy/VPN": str(data.get("proxy")),
            "Hosting": str(data.get("hosting")),
        }

        for field, value in geo_fields.items():
            if value and value not in ("None", "False"):
                table.add_row(field, str(value))

        console.print(table)
    except Exception as e:
        console.print(f"[yellow]ip-api error:[/yellow] {e}")

    # WHOIS / ASN via ipwhois
    console.print()
    try:
        obj = ipwhois.IPWhois(target)
        result = obj.lookup_rdap(depth=1)
        asn_table = Table(title="ASN / RDAP", show_header=False, box=None, padding=(0, 2))
        asn_table.add_column("Field", style="bold yellow")
        asn_table.add_column("Value", style="white")

        asn_data = {
            "ASN": result.get("asn"),
            "ASN CIDR": result.get("asn_cidr"),
            "ASN Country": result.get("asn_country_code"),
            "ASN Description": result.get("asn_description"),
            "Network Name": result.get("network", {}).get("name"),
            "Network CIDR": result.get("network", {}).get("cidr"),
        }
        for field, value in asn_data.items():
            if value:
                asn_table.add_row(field, str(value))

        console.print(asn_table)
    except Exception as e:
        console.print(f"[yellow]ipwhois error:[/yellow] {e}")
