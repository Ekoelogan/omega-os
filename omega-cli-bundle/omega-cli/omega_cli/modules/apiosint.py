"""apiosint.py — API discovery: Swagger/OpenAPI, GraphQL, REST endpoints, auth detection."""
from __future__ import annotations
import json, re
from pathlib import Path
from urllib.parse import urljoin, urlparse
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

# Common API/doc paths to probe
API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/api", "/rest/v1",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json",
    "/docs", "/redoc", "/scalar",
    "/.well-known/openapi.json",
    "/actuator", "/actuator/health", "/actuator/env",  # Spring Boot
    "/health", "/healthz", "/ping", "/status",
    "/metrics",           # Prometheus
    "/__admin", "/admin/api",
    "/wp-json", "/wp-json/wp/v2",  # WordPress
    "/api/swagger-ui.html",
    "/api-explorer",
]

AUTH_HEADERS = [
    "WWW-Authenticate", "X-RateLimit-Limit", "X-Api-Version",
    "X-Powered-By", "X-Frame-Options",
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{types{name kind description}}}"}'
GRAPHQL_TYPENAME = '{"query":"{__typename}"}'


def _probe(url: str, method: str = "GET", body: Optional[bytes] = None,
           extra_headers: Optional[dict] = None, timeout: int = 8) -> tuple[int, dict, str]:
    headers = {"User-Agent": UA, "Accept": "application/json,text/html,*/*"}
    if body:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp_headers = dict(r.headers)
            content = r.read(100_000).decode("utf-8", errors="replace")
            return r.status, resp_headers, content
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), ""
    except Exception:
        return 0, {}, ""


def _sniff_auth(headers: dict) -> list[str]:
    hints = []
    www = headers.get("WWW-Authenticate", headers.get("www-authenticate", ""))
    if "bearer" in www.lower(): hints.append("Bearer JWT")
    if "basic" in www.lower():  hints.append("HTTP Basic")
    if "digest" in www.lower(): hints.append("HTTP Digest")
    if "apikey" in str(headers).lower(): hints.append("API Key header")
    if "oauth" in www.lower():  hints.append("OAuth")
    return hints


def _parse_openapi(spec: str, base_url: str) -> list[dict]:
    """Extract endpoints from OpenAPI/Swagger JSON."""
    endpoints = []
    try:
        doc = json.loads(spec)
    except Exception:
        try:
            import yaml
            doc = yaml.safe_load(spec)
        except Exception:
            return endpoints

    paths = doc.get("paths", {})
    base = doc.get("servers", [{}])[0].get("url", base_url) if "servers" in doc else \
           f"{base_url}{doc.get('basePath', '')}"

    for path, methods in paths.items():
        if isinstance(methods, dict):
            for method, details in methods.items():
                if method in ("get","post","put","patch","delete","head","options"):
                    endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "url": urljoin(base, path),
                        "summary": details.get("summary", ""),
                        "tags": details.get("tags", []),
                        "auth": bool(details.get("security")),
                    })
    return endpoints


def _graphql_introspect(url: str) -> dict:
    status, headers, body = _probe(url, "POST", GRAPHQL_INTROSPECTION.encode())
    if status in (200, 201):
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            user_types = [t for t in types if not t["name"].startswith("__")]
            return {"url": url, "types": [t["name"] for t in user_types[:30]], "total": len(user_types)}
        except Exception:
            pass
    return {}


def run(target: str, deep: bool = False, export: str = ""):
    if not target.startswith("http"):
        target = "https://" + target
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    console.print(BANNER, style="bold magenta")
    console.print(Panel(f"⚙  API OSINT — {target}", style="bold cyan"))

    results = {
        "target": target, "base": base,
        "endpoints_discovered": [], "openapi_endpoints": [],
        "graphql": None, "auth_methods": [],
        "interesting_paths": [],
    }

    # Probe all candidate paths
    console.print(f"\n[bold]Probing {len(API_PATHS)} common API paths...[/bold]")
    t = Table(title="API Path Probe", box=box.SIMPLE if box else None)
    t.add_column("Status", style="bold")
    t.add_column("Path", style="cyan")
    t.add_column("Type", style="yellow")
    t.add_column("Auth Hints", style="dim")

    interesting = []
    openapi_urls = []
    graphql_urls = []

    for path in API_PATHS:
        url = urljoin(base, path)
        status, resp_headers, body = _probe(url)
        if status in (0, 404):
            continue

        ct = resp_headers.get("Content-Type", resp_headers.get("content-type", ""))
        auth_hints = _sniff_auth(resp_headers)

        # classify
        kind = "HTML"
        if "json" in ct: kind = "JSON"
        elif "yaml" in ct: kind = "YAML"
        elif "xml" in ct: kind = "XML"

        # detect openapi/swagger
        is_openapi = any(k in body[:500] for k in ["swagger", "openapi", '"paths":', "Swagger UI"])
        is_graphql = any(k in body for k in ["__typename", "graphql", "GraphQL", "__schema"])

        if is_openapi:
            openapi_urls.append((url, body))
            kind = "OpenAPI/Swagger"
        if is_graphql or "graphql" in path.lower():
            graphql_urls.append(url)
            kind = "GraphQL"

        color = "green" if status == 200 else "yellow" if status in (301,302,307,308) else "orange3" if status == 401 else "dim"
        t.add_row(f"[{color}]{status}[/{color}]", path, kind, ", ".join(auth_hints) or "")

        record = {"path": path, "url": url, "status": status, "type": kind, "auth_hints": auth_hints}
        results["endpoints_discovered"].append(record)
        if status in (200, 201, 401, 403):
            interesting.append(record)
        if auth_hints:
            results["auth_methods"].extend(auth_hints)

    console.print(t)

    # Parse OpenAPI specs
    if openapi_urls:
        console.print(f"\n[bold cyan]OpenAPI/Swagger Specs Found: {len(openapi_urls)}[/bold cyan]")
        for spec_url, spec_body in openapi_urls:
            eps = _parse_openapi(spec_body, base)
            results["openapi_endpoints"].extend(eps)
            console.print(f"  {spec_url}: [green]{len(eps)} endpoints[/green]")

        if results["openapi_endpoints"]:
            te = Table(title="📋 API Endpoints", box=box.SIMPLE if box else None)
            te.add_column("Method", style="bold")
            te.add_column("Path", style="cyan")
            te.add_column("Auth")
            te.add_column("Summary", style="dim")
            for ep in results["openapi_endpoints"][:40]:
                m_color = {"GET":"green","POST":"yellow","PUT":"blue","DELETE":"red","PATCH":"orange3"}.get(ep["method"],"white")
                te.add_row(
                    f"[{m_color}]{ep['method']}[/{m_color}]",
                    ep["path"],
                    "🔒" if ep["auth"] else "",
                    ep["summary"][:60],
                )
            console.print(te)

    # GraphQL introspection
    for gql_url in graphql_urls[:3]:
        console.print(f"\n[bold magenta]GraphQL Introspection → {gql_url}[/bold magenta]")
        gql = _graphql_introspect(gql_url)
        if gql:
            results["graphql"] = gql
            console.print(f"  Types ({gql['total']}): {', '.join(gql['types'][:15])}")
        else:
            console.print("  [dim]Introspection disabled or not available[/dim]")

    # Auth methods summary
    auth_set = list(set(results["auth_methods"]))
    if auth_set:
        console.print(f"\n[bold]Auth Methods Detected:[/bold] {', '.join(auth_set)}")

    console.print(f"\n[bold]Summary:[/bold] {len(results['endpoints_discovered'])} paths probed | "
                  f"{len(interesting)} interesting | "
                  f"{len(results['openapi_endpoints'])} OpenAPI endpoints | "
                  f"GraphQL: {'Yes' if results['graphql'] else 'No'}")

    out_dir = Path.home() / ".omega" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", parsed.netloc or target)
    out_path = Path(export) if export else out_dir / f"apiosint_{safe}.json"
    out_path.write_text(json.dumps(results, indent=2))
    console.print(f"[dim]Saved → {out_path}[/dim]")
