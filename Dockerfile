# ============================================================================
#  OMEGA-OS v2.0 — AI-Powered OSINT & Recon Container
#  Built on Kali Linux with omega-cli v1.8.0 (AI agents) + Ollama + MCP
#  Usage:  docker build -t omega-os .
#          docker run -it --rm -v ~/omega-reports:/reports omega-os
# ============================================================================
FROM kalilinux/kali-rolling:latest

LABEL maintainer="omega-os" \
      description="Omega-CLI + AI Agents + Ollama + MCP Server on Kali Linux" \
      version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive \
    TERM=xterm-256color \
    HOME=/root \
    OMEGA_REPORTS=/reports \
    OLLAMA_HOST=0.0.0.0:11434 \
    OLLAMA_MODELS=/root/.ollama/models

# ── 1. System update + core utilities ────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    curl wget git \
    python3 python3-pip python3-venv python3-dev \
    build-essential libffi-dev libssl-dev \
    jq tmux zsh vim nano htop tree unzip \
    ca-certificates gnupg lsb-release procps \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Kali Security Tools (slim — no seclists/hashcat/wordlists/Go) ────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    # -- Network scanning & enumeration --
    nmap masscan netcat-openbsd \
    # -- DNS tools --
    dnsutils dnsrecon dnsenum fierce \
    # -- Web recon & fuzzing --
    nikto dirb gobuster whatweb \
    # -- OSINT frameworks --
    theharvester recon-ng spiderfoot \
    # -- Exploitation & vuln scanning --
    sqlmap nuclei \
    # -- Credential & password tools --
    hydra john \
    # -- Packet analysis --
    tcpdump tshark \
    # -- Forensics & metadata --
    exiftool foremost binwalk steghide \
    # -- SSL/TLS analysis --
    sslyze sslscan testssl.sh \
    # -- Subdomain enumeration --
    amass subfinder \
    # -- Additional recon --
    whois traceroute \
    && rm -rf /var/lib/apt/lists/*

# ── 3. Install Ollama (local AI inference) ───────────────────────────────────
RUN curl -fsSL https://ollama.com/download/ollama-linux-amd64.tgz \
        -o /opt/ollama.tgz && \
    tar -xzf /opt/ollama.tgz -C /usr && \
    rm -f /opt/ollama.tgz && \
    mkdir -p /root/.ollama/models

# ── 4. Install omega-cli (includes AI agent framework in omega_cli/agents/) ──
COPY omega-cli/ /opt/omega-cli/
RUN python3 -m venv /opt/omega-venv && \
    /opt/omega-venv/bin/pip install --no-cache-dir -U pip && \
    /opt/omega-venv/bin/pip install --no-cache-dir /opt/omega-cli/ && \
    ln -sf /opt/omega-venv/bin/omega /usr/local/bin/omega

# ── 5. Install omega-mcp-server ─────────────────────────────────────────────
COPY omega-mcp-server/ /opt/omega-mcp-server/
RUN /opt/omega-venv/bin/pip install --no-cache-dir /opt/omega-mcp-server/ && \
    ln -sf /opt/omega-venv/bin/omega-mcp /usr/local/bin/omega-mcp

# ── 6. PATH ─────────────────────────────────────────────────────────────────
ENV PATH="/opt/omega-venv/bin:/usr/local/bin:${PATH}"

# ── 7. Entrypoint — starts Ollama, prints banner, drops to bash ─────────────
RUN cat <<'ENTRY' > /usr/local/bin/omega-entrypoint && chmod +x /usr/local/bin/omega-entrypoint
#!/bin/bash
set -e

# --- Start Ollama in background ---
if command -v ollama &>/dev/null; then
    ollama serve &>/var/log/ollama.log &
    OLLAMA_PID=$!
    echo "[✓] Ollama running (PID ${OLLAMA_PID}) — pull models with: ollama pull mistral"
fi

# --- Banner ---
echo ""
echo -e "\033[38;2;255;45;120m"
echo " ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗       ██████╗ ███████╗"
echo "██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗     ██╔═══██╗██╔════╝"
echo "██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║     ██║   ██║███████╗"
echo "██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║     ██║   ██║╚════██║"
echo "╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║     ╚██████╔╝███████║"
echo " ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚═════╝╚══════╝"
echo -e "\033[0m"
echo "  OMEGA-OS v2.0.0 — AI-Powered OSINT & Recon System"
echo ""
echo "  🤖 AI:        ollama (local LLM) | omega-mcp (MCP server)"
echo "  🧠 Agents:    omega agent <task>  (AI agent framework)"
echo "  🔧 Scanning:  nmap masscan nikto sqlmap nuclei"
echo "  🔍 OSINT:     theHarvester recon-ng spiderfoot amass subfinder"
echo "  🌐 Web:       gobuster dirb whatweb"
echo "  🔑 Creds:     hydra john"
echo "  📡 Network:   tcpdump tshark"
echo "  🔬 Forensics: exiftool binwalk foremost steghide"
echo "  📂 Reports:   /reports"
echo ""
echo "  omega --help | omega auto <target> | omega-mcp --help"
echo ""

exec /bin/bash "$@"
ENTRY

# ── 8. Reports volume ───────────────────────────────────────────────────────
RUN mkdir -p /reports
VOLUME ["/reports"]

WORKDIR /root
ENTRYPOINT ["/usr/local/bin/omega-entrypoint"]
