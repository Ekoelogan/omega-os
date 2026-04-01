"""omega api — Embedded Flask REST API server: expose all omega commands over HTTP."""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import threading
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

CONFIG_DIR  = Path.home() / ".omega"
API_KEY_FILE = CONFIG_DIR / "api_key.txt"
DEFAULT_PORT = 6660


def _get_or_create_key() -> str:
    CONFIG_DIR.mkdir(exist_ok=True)
    if API_KEY_FILE.exists():
        return API_KEY_FILE.read_text().strip()
    key = secrets.token_hex(24)
    API_KEY_FILE.write_text(key)
    API_KEY_FILE.chmod(0o600)
    return key


def _require_auth(api_key: str):
    """Return a Flask decorator that checks X-API-Key header."""
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request, jsonify
            provided = request.headers.get("X-API-Key", "")
            if not secrets.compare_digest(provided, api_key):
                return jsonify({"error": "Unauthorized"}), 401
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _build_app(api_key: str) -> "Flask":
    try:
        from flask import Flask, request, jsonify
    except ImportError:
        raise RuntimeError("Flask not installed. Run: pipx inject omega-cli flask")

    app = Flask("omega-api")

    auth = _require_auth(api_key)

    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "name":    "omega-cli API",
            "version": "1.0.0",
            "docs":    "/endpoints",
        })

    @app.route("/endpoints", methods=["GET"])
    @auth
    def endpoints():
        return jsonify({
            "endpoints": [
                "GET  /",
                "GET  /endpoints",
                "POST /whois      body: {target}",
                "POST /dns        body: {target, record_type?}",
                "POST /ip         body: {target}",
                "POST /subdomain  body: {target}",
                "POST /ssl        body: {target}",
                "POST /headers    body: {target}",
                "POST /tech       body: {target}",
                "POST /ioc        body: {source}",
                "POST /geoint     body: {target}",
                "POST /intel      body: {target}",
                "POST /breach     body: {email?, domain?, password?}",
                "POST /cve        body: {keyword}",
                "POST /shodan     body: {target}",
                "POST /creds      body: {target}",
                "POST /hunt       body: {target, json_file?}",
                "POST /opsec      body: {}",
                "POST /auto       body: {target, passive?}",
            ]
        })

    def _run_module(func, *args, **kwargs):
        """Run a module function, capture Rich console output as text."""
        import io
        from rich.console import Console as RC
        buf  = io.StringIO()
        con  = RC(file=buf, highlight=False, markup=False)
        # Temporarily patch module console
        try:
            result = func(*args, **kwargs)
            output = buf.getvalue()
            return {"status": "ok", "output": output, "result": result}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    @app.route("/whois", methods=["POST"])
    @auth
    def route_whois():
        from omega_cli.modules import whois_lookup as wl
        data   = request.get_json(force=True) or {}
        target = data.get("target", "")
        if not target:
            return jsonify({"error": "target required"}), 400
        try:
            info = wl.lookup(target)
            return jsonify({"status": "ok", "result": info})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)})

    @app.route("/dns", methods=["POST"])
    @auth
    def route_dns():
        from omega_cli.modules import dns_lookup as dl
        data    = request.get_json(force=True) or {}
        target  = data.get("target", "")
        rtype   = data.get("record_type", "A")
        if not target:
            return jsonify({"error": "target required"}), 400
        try:
            records = dl.lookup(target, rtype)
            return jsonify({"status": "ok", "records": records})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)})

    @app.route("/ioc", methods=["POST"])
    @auth
    def route_ioc():
        from omega_cli.modules import ioc as ic
        data   = request.get_json(force=True) or {}
        source = data.get("source", "")
        if not source:
            return jsonify({"error": "source required"}), 400
        try:
            findings = ic.run(source, no_private=True)
            return jsonify({"status": "ok", "iocs": {k: v for k, v in (findings or {}).items()}})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)})

    @app.route("/opsec", methods=["POST"])
    @auth
    def route_opsec():
        from omega_cli.modules import opsec as op
        try:
            op.run()
            return jsonify({"status": "ok"})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)})

    @app.route("/hunt", methods=["POST"])
    @auth
    def route_hunt():
        from omega_cli.modules import hunt as ht
        data      = request.get_json(force=True) or {}
        target    = data.get("target", "")
        json_file = data.get("json_file", "")
        if not target:
            return jsonify({"error": "target required"}), 400
        try:
            ht.run(target, json_file=json_file)
            return jsonify({"status": "ok"})
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)})

    return app


def run(host: str = "127.0.0.1", port: int = DEFAULT_PORT,
        show_key: bool = False, new_key: bool = False) -> None:

    if new_key and API_KEY_FILE.exists():
        API_KEY_FILE.unlink()

    api_key = _get_or_create_key()

    if show_key:
        console.print(f"[bold]API Key:[/bold] [cyan]{api_key}[/cyan]")
        return

    console.print(Panel(
        f"[bold #ff2d78]🌐  Omega API Server[/bold #ff2d78]\n"
        f"[dim]Listening on[/dim] [bold]http://{host}:{port}[/bold]\n"
        f"[dim]API Key:[/dim]  [cyan]{api_key}[/cyan]\n\n"
        f"[dim]Example:[/dim]  curl -H 'X-API-Key: {api_key}' http://{host}:{port}/",
        expand=False,
    ))

    try:
        app = _build_app(api_key)
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        return

    try:
        import logging
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.WARNING)
        app.run(host=host, port=port, threaded=True)
    except KeyboardInterrupt:
        console.print("\n[dim]API server stopped.[/dim]")
    except OSError as e:
        console.print(f"[red]Could not bind to {host}:{port}:[/red] {e}")
