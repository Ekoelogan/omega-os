# 🔴 OMEGA-OS v2.0 — Full Architecture Plan
## Parrot OS 7.1 Framework + AI Agent Manager + MCP Server + Desktop OS

---

## 🎯 Vision

Omega-OS v2.0 is a fully self-contained, AI-agent-driven offensive security OS built as a Docker container (and optionally a bootable ISO). It combines:

1. **Parrot OS 7.1 tool categories** — 800+ tools organized into 15 categories
2. **Omega-CLI v1.8.0** — 108 existing OSINT/recon commands
3. **AI Agent Manager** — autonomous bot that orchestrates tools, chains workflows, and provides real-time analysis
4. **Per-category AI specialist agents** — each tool category gets its own AI agent with domain expertise

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    OMEGA-OS v2.0                        │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │            🤖 AI AGENT MANAGER                    │  │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │  │
│  │  │RECON │ │VULN  │ │WEB   │ │EXPLOIT│ │OSINT │   │  │
│  │  │Agent │ │Agent │ │Agent │ │Agent  │ │Agent │   │  │
│  │  └──┬───┘ └──┬───┘ └──┬───┘ └──┬────┘ └──┬───┘   │  │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │  │
│  │  │WIFI  │ │PASS  │ │FOREN │ │REVENG│ │PRIV  │   │  │
│  │  │Agent │ │Agent │ │Agent │ │Agent │ │Agent │   │  │
│  │  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘   │  │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │  │
│  │  │SOCIAL│ │CLOUD │ │CRYPTO│ │REPORT│ │POST  │   │  │
│  │  │Agent │ │Agent │ │Agent │ │Agent │ │EXPL  │   │  │
│  │  └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘   │  │
│  └─────┼────────┼────────┼────────┼────────┼────────┘  │
│        ▼        ▼        ▼        ▼        ▼           │
│  ┌───────────────────────────────────────────────────┐  │
│  │              🔧 TOOL LAYER                        │  │
│  │  Parrot OS tools + Omega-CLI + Go/Rust tools      │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │           🐧 BASE: Parrot OS 7.1 / Kali           │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Phase 1: Parrot OS Tool Categories (Dockerfile)

### Category → Tools Mapping (modeled after Parrot OS 7.1)

#### 1. 🔍 Information Gathering (recon-agent)
```
nmap, zenmap, masscan, naabu
theHarvester, recon-ng, maltego
amass, subfinder, assetfinder
dnsrecon, dnsenum, fierce, dnsmap
wafw00f, whatweb, wappalyzer-cli
httpx, katana, hakrawler
netdiscover, arp-scan
omega: dns, crtsh, whois, headers, tech, harvest, asn, ipinfo, shodan
```

#### 2. 🔓 Vulnerability Analysis (vuln-agent)
```
nuclei, nikto, openvas-cli
searchsploit (exploit-db)
nmap --script vuln
legion, sparta
omega: cve, cvssrank, vuln2, redteam, riskcore
```

#### 3. 🌐 Web Application Analysis (web-agent)
```
burpsuite (community), zaproxy (OWASP ZAP)
wpscan, joomscan, droopescan
gobuster, dirb, dirbuster, feroxbuster, ffuf
wfuzz, arjun
sqlmap, commix, xsser
omega: cors, js, fuzz, spider, webcrawl, apiosint, robots
```

#### 4. 💣 Exploitation (exploit-agent)
```
metasploit-framework
beef-xss
sqlmap
crackmapexec
responder
omega: redteam
```

#### 5. 📡 Wireless Testing (wifi-agent)
```
aircrack-ng (full suite)
reaver, pixiewps, bully
wifite2
kismet
fern-wifi-cracker
hostapd-wpe
```

#### 6. 🔑 Password Attacks (password-agent)
```
john (jumbo)
hashcat
hydra
medusa
ncrack
cewl, crunch
omega: creds, wordlist
```

#### 7. 🔬 Digital Forensics (forensics-agent)
```
autopsy, sleuthkit
volatility3
binwalk, foremost, scalpel
bulk-extractor
dc3dd, dcfldd
photorec, testdisk
omega: docosint, imgosint, ioc
```

#### 8. 🔧 Reverse Engineering (reverse-agent)
```
ghidra
radare2, rizin
gdb, gdb-peda
objdump, strace, ltrace
jadx (Android)
omega: firmware, mobile
```

#### 9. 🕵️ Post-Exploitation (post-agent)
```
meterpreter (via metasploit)
empire, starkiller
mimikatz (Windows targets)
linpeas, winpeas
pspy
omega: c2, exfil, pivot
```

#### 10. 🎭 Social Engineering (social-agent)
```
set (Social-Engineer Toolkit)
gophish
king-phisher
omega: phish, persona, socmint, social, identity, user
```

#### 11. ☁️ Cloud Security (cloud-agent)
```
prowler, scoutsuite
pacu (AWS exploitation)
cloudsploit
trufflehog
gitleaks
omega: cloud, cloud2, buckets, secrets, creds, git, supply
```

#### 12. 🧅 Anonymity & Privacy (privacy-agent)
```
tor, torbrowser-launcher
i2p
anonsurf (Parrot native)
proxychains4
macchanger
omega: opsec, proxy, torcheck, dark, deepweb
```

#### 13. ₿ Crypto & Steganography (crypto-agent)
```
steghide, zsteg, stegsolve
gnupg, openssl
omega: crypto, cryptoosint
```

#### 14. 🤖 AI Security (NEW - ai-agent)
```
mcpwn (Parrot 7.1 native)
trufflehog v3.92 (AI-augmented)
omega: ai, aiassist, aisummary, executive, ml
```

#### 15. 📊 Reporting & Intelligence (report-agent)
```
omega: report, reportgen, pdf, executive, briefing, timeline, timeline3d
omega: stix, graph, viz, attackmap, dossier, hunt
omega: osintdb, autocorr, compare, riskcore
```

---

## 📦 Phase 2: AI Agent Framework

### Core: `omega_cli/agents/`

```
omega_cli/agents/
├── __init__.py
├── manager.py          # AI Agent Manager — orchestrates all agents
├── base_agent.py       # Base class for all agents
├── router.py           # Routes tasks to the right agent
├── memory.py           # Shared memory / context store (SQLite)
├── planner.py          # Task decomposition & planning
├── executor.py         # Tool execution engine
│
├── recon_agent.py      # Information Gathering specialist
├── vuln_agent.py       # Vulnerability Analysis specialist
├── web_agent.py        # Web Application specialist
├── exploit_agent.py    # Exploitation specialist
├── wifi_agent.py       # Wireless Testing specialist
├── password_agent.py   # Password Attack specialist
├── forensics_agent.py  # Digital Forensics specialist
├── reverse_agent.py    # Reverse Engineering specialist
├── post_agent.py       # Post-Exploitation specialist
├── social_agent.py     # Social Engineering specialist
├── cloud_agent.py      # Cloud Security specialist
├── privacy_agent.py    # Anonymity & Privacy specialist
├── crypto_agent.py     # Crypto & Stego specialist
├── ai_security_agent.py # AI Security specialist
└── report_agent.py     # Reporting & Intel specialist
```

### Base Agent Class

```python
class BaseAgent:
    name: str               # "recon-agent"
    description: str        # "Information gathering specialist"
    category: str           # "Information Gathering"
    tools: list[str]        # ["nmap", "amass", "omega dns", ...]
    system_prompt: str      # Domain-specific expertise prompt
    memory: AgentMemory     # Shared findings store

    def plan(self, task: str) -> list[Step]
    def execute(self, step: Step) -> Result
    def analyze(self, results: list[Result]) -> Analysis
    def report(self, analysis: Analysis) -> str
    def handoff(self, agent_name: str, context: dict)  # delegate to another agent
```

### Agent Manager

```python
class AgentManager:
    agents: dict[str, BaseAgent]
    memory: SharedMemory        # SQLite-backed cross-agent memory
    planner: TaskPlanner        # Decomposes user request into agent tasks
    llm: LLMProvider            # Ollama (local) or OpenAI

    def process(self, user_request: str) -> str
        # 1. Planner decomposes request into tasks
        # 2. Router assigns tasks to specialist agents
        # 3. Agents execute in parallel where possible
        # 4. Results aggregated into shared memory
        # 5. Report agent compiles final output
        # 6. Manager returns summary + saves report

    def chat(self, message: str) -> str
        # Interactive mode — maintains conversation context

    def autonomous(self, target: str, scope: str) -> Report
        # Full autonomous engagement — runs all relevant agents
```

### CLI Integration

```python
# New commands in main.py:

@cli.command()
@click.argument("request", nargs=-1)
def agent(request):
    """🤖 AI agent — natural language task execution."""
    # omega agent "scan tesla.com for web vulnerabilities"
    manager = AgentManager()
    manager.process(" ".join(request))

@cli.command()
def agents():
    """🤖 List all available AI agents and their capabilities."""
    # Shows table of 15 agents with status

@cli.command()
@click.argument("target")
@click.option("--scope", default="full")
def autopilot(target, scope):
    """🤖 Full autonomous engagement — AI manages everything."""
    # omega autopilot tesla.com --scope=passive
    manager = AgentManager()
    manager.autonomous(target, scope)

@cli.command()
def chat():
    """🤖 Interactive AI chat — ask questions, run tools."""
    # omega chat
    # > "What ports are open on tesla.com?"
    # Agent Manager routes to recon-agent, runs nmap, returns analysis
```

---

## 📦 Phase 3: Enhanced Dockerfile (Omega-OS v2.0)

```dockerfile
FROM parrotsec/security:latest  # Parrot OS Security Edition (full toolset)

# All 800+ Parrot tools come pre-installed
# Add omega-cli + AI agent framework
COPY omega-cli/ /opt/omega-cli/
RUN python3 -m venv /opt/omega-venv && \
    /opt/omega-venv/bin/pip install /opt/omega-cli/ && \
    ln -sf /opt/omega-venv/bin/omega /usr/local/bin/omega

# Ollama for local AI (no cloud dependency)
RUN curl -fsSL https://ollama.com/install.sh | sh
RUN ollama pull llama3.2    # 3B param model — fits in 4GB RAM
RUN ollama pull codellama   # Code-specialized model

# Go tools (ProjectDiscovery suite)
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Rust tools
RUN cargo install feroxbuster rustscan

ENTRYPOINT ["/usr/local/bin/omega-shell"]
```

### Slim variant (for 10GB disks):
```dockerfile
FROM kalilinux/kali-rolling:latest  # Smaller base
# Install only the tools each agent needs, on-demand
```

---

## 📦 Phase 4: Bootable USB ISO (Omega-OS Desktop — Plug & Play)

Full bootable live OS on USB — plug into any machine, boot, and go. No install required.

### Build Requirements (build machine)
- Debian/Ubuntu/Kali host with 30+ GB free
- `live-build`, `debootstrap`, `squashfs-tools`, `grub-efi`, `xorriso`
- 16+ GB USB drive (WD My Passport, SanDisk, etc.)

### What's On the USB
```
omega-os-2.0-amd64.iso (~8-10 GB)
├── 🐧 Debian 13 / Parrot base (Linux 6.x kernel)
├── 🖥️  MATE Desktop Environment (lightweight)
├── 🔴 800+ security tools (Parrot/Kali repos)
├── 🔍 omega-cli v2.0 (108+ commands + 15 AI agents)
├── 🤖 Ollama + llama3.2 (local AI, no internet needed)
├── 🔧 Go tools (httpx, nuclei, katana, subfinder, naabu)
├── 📂 Persistent partition (saves reports/configs across reboots)
├── 🎨 Custom pink OMEGA boot splash + wallpaper
└── 🔒 Full disk encryption option (LUKS)
```

### Boot Modes
1. **Live Mode** — RAM only, no traces left on host machine
2. **Persistent Mode** — saves data to USB partition between reboots
3. **Install Mode** — full install to internal drive (optional)

### Build Script: `build-iso.sh`
```bash
# 1. Bootstraps Debian live system
# 2. Adds Kali/Parrot repos for security tools
# 3. Installs all 15 tool categories
# 4. Installs omega-cli + AI agent framework
# 5. Installs Ollama + pre-pulls llama3.2 model
# 6. Configures MATE desktop with custom theme
# 7. Sets up auto-login → omega banner on boot
# 8. Builds hybrid ISO (BIOS + UEFI bootable)
# 9. Ready to dd to USB
```

### Flash to USB
```bash
# After building the ISO:
sudo dd if=omega-os-2.0-amd64.iso of=/dev/sdX bs=4M status=progress
sync

# Or use Etcher/Ventoy for GUI flashing
```

### Persistent Partition Setup
```bash
# Creates a 2nd partition on USB for saving data
# Reports, configs, API keys, custom wordlists persist across reboots
# Encrypted with LUKS by default
```

### Desktop Auto-Start
```
Boot → GRUB (pink OMEGA splash) → Auto-login → MATE Desktop
  → Terminal auto-opens with omega banner
  → Desktop shortcuts: omega-cli, Burp Suite, Wireshark, Metasploit
  → System tray: Ollama AI status, VPN/Tor toggle, notification agent
```

---

## 🗂️ Todo Summary

| # | Task | Depends On | Effort |
|---|------|-----------|--------|
| 1 | Create `omega_cli/agents/base_agent.py` — base class | — | Medium |
| 2 | Create `omega_cli/agents/memory.py` — SQLite shared memory | — | Medium |
| 3 | Create `omega_cli/agents/executor.py` — tool execution engine | — | Medium |
| 4 | Create `omega_cli/agents/planner.py` — task decomposition | 1 | Medium |
| 5 | Create `omega_cli/agents/router.py` — task→agent routing | 1,4 | Medium |
| 6 | Create `omega_cli/agents/manager.py` — orchestrator | 1-5 | Large |
| 7 | Create 15 specialist agents (recon, vuln, web, ...) | 1,2,3 | Large |
| 8 | Add `omega agent`, `omega agents`, `omega autopilot`, `omega chat` commands | 6 | Medium |
| 9 | Update Dockerfile to Parrot OS base + all tools | — | Medium |
| 10 | Integrate Ollama for 100% local AI | — | Small |
| 11 | Create bootable ISO build script | 9 | Large |
| 12 | Documentation & README | All | Medium |

---

## 💡 Key Design Decisions

1. **Ollama-first**: All AI runs locally by default. OpenAI is optional fallback.
2. **Agent handoff**: Agents can delegate to each other (recon→vuln→exploit chain).
3. **Shared memory**: SQLite DB stores all findings. Any agent can query it.
4. **Parallel execution**: Independent agents run concurrently.
5. **Human-in-the-loop**: Exploitation agents ALWAYS ask for confirmation before acting.
6. **Plugin system**: Custom agents can be added via `omega plugin`.
7. **100% offline capable**: Everything works without internet (except target scanning).

---

*Plan created: 2026-03-31 | Omega-OS v2.0 Architecture*

---

## 📦 Phase 5: MCP Server (Model Context Protocol)

Expose all 108+ omega tools as an MCP server so GitHub Copilot, VS Code, Claude, and any MCP client can call omega commands natively.

### Repo: `github.com/<user>/omega-mcp-server`

### Architecture

```
omega-mcp-server/
├── pyproject.toml
├── README.md
├── src/
│   └── omega_mcp/
│       ├── __init__.py
│       ├── server.py           # FastMCP server — registers all tools
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── recon.py        # whois, dns, crtsh, subdomains, asn, ipinfo
│       │   ├── web.py          # headers, tech, cors, js, robots, spider
│       │   ├── vuln.py         # cve, cvssrank, vuln2, nuclei wrapper
│       │   ├── osint.py        # email, user, socmint, harvest, dorks
│       │   ├── network.py      # ports, nmap wrapper, shodan, ssl
│       │   ├── threat.py       # intel, threatfeed, malware, ioc, phish
│       │   ├── cloud.py        # cloud, buckets, secrets, creds, git
│       │   ├── forensics.py    # docosint, imgosint, firmware, mobile
│       │   ├── privacy.py      # opsec, proxy, torcheck, dark, deepweb
│       │   ├── report.py       # pdf, report, briefing, timeline, stix
│       │   ├── ai.py           # ai, aiassist, aisummary, executive
│       │   └── kali.py         # nmap, nikto, sqlmap, nuclei, amass, etc.
│       ├── resources/
│       │   ├── __init__.py
│       │   ├── findings.py     # Access to stored findings/reports
│       │   └── config.py       # Read/write omega config
│       └── prompts/
│           ├── __init__.py
│           ├── recon_prompt.py  # "Run full recon on {target}"
│           ├── vuln_prompt.py   # "Find vulnerabilities on {target}"
│           └── report_prompt.py # "Generate executive report for {target}"
├── .github/
│   └── workflows/
│       └── ci.yml              # Test + publish
└── mcp-config.json             # Registration config for Copilot CLI
```

### Core Server (`server.py`)

```python
from mcp.server.fastmcp import FastMCP
import subprocess, json

mcp = FastMCP("omega-mcp-server",
    description="OSINT & Passive Recon Toolkit — 108 commands via MCP")

# ── Recon Tools ──────────────────────────────────────────

@mcp.tool()
def omega_whois(target: str) -> str:
    """WHOIS lookup for a domain or IP address."""
    return _run_omega("whois", target)

@mcp.tool()
def omega_dns(target: str, record_type: str = "ALL") -> str:
    """DNS record enumeration (A, MX, NS, TXT, CNAME, SOA)."""
    return _run_omega("dns", target, f"--type={record_type}")

@mcp.tool()
def omega_auto(target: str) -> str:
    """Full automated recon — chains ALL modules, exports report."""
    return _run_omega("auto", target)

@mcp.tool()
def omega_nmap(target: str, flags: str = "-sV --top-ports 100") -> str:
    """Network port scan using nmap."""
    result = subprocess.run(
        ["nmap"] + flags.split() + [target],
        capture_output=True, text=True, timeout=300)
    return result.stdout

# ... 100+ more tools registered ...

# ── Resources ────────────────────────────────────────────

@mcp.resource("omega://reports/{target}")
def get_report(target: str) -> str:
    """Get the latest omega findings for a target."""
    # Returns JSON from ~/omega-reports/

@mcp.resource("omega://config")
def get_config() -> str:
    """Get current omega configuration."""

# ── Prompts ──────────────────────────────────────────────

@mcp.prompt()
def full_recon(target: str) -> str:
    """Run comprehensive passive recon on a target."""
    return f"Run omega auto {target}, then analyze findings..."

@mcp.prompt()
def bug_bounty(target: str) -> str:
    """Bug bounty recon workflow for a target."""
    return f"Run headers, cors, ssl, js, crtsh, cloud on {target}..."

def _run_omega(command: str, *args) -> str:
    """Execute an omega CLI command and return output."""
    cmd = ["omega", command] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.stdout or result.stderr
```

### Registration with Copilot CLI

```json
// ~/.copilot/mcp-config.json
{
  "servers": {
    "omega": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "omega_mcp.server"],
      "env": {
        "SHODAN_API_KEY": "",
        "OPENAI_API_KEY": ""
      }
    }
  }
}
```

### Registration with VS Code

```json
// .vscode/mcp.json
{
  "servers": {
    "omega": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "omega_mcp.server"]
    }
  }
}
```

### MCP Tool Categories (108+ tools exposed)

| Category | Tools Exposed | Count |
|----------|--------------|-------|
| Recon | whois, dns, crtsh, subdomains, asn, ipinfo, revip | 7 |
| Web | headers, tech, cors, js, robots, spider, webcrawl, fuzz | 8 |
| Vulnerability | cve, cvssrank, vuln2, redteam, riskcore | 5 |
| OSINT | email, user, socmint, harvest, dorks, identity, org | 7 |
| Network | ports, ssl, shodan, nmap, masscan | 5 |
| Threat Intel | intel, threatfeed, malware, ioc, phish, c2 | 6 |
| Cloud | cloud, cloud2, buckets, secrets, creds, git, supply | 7 |
| Forensics | docosint, imgosint, firmware, mobile, codetrace | 5 |
| Privacy | opsec, proxy, torcheck, dark, deepweb, persona | 6 |
| Crypto | crypto, cryptoosint | 2 |
| AI | ai, aiassist, aisummary, executive, ml | 5 |
| Reporting | pdf, report, briefing, timeline, stix, graph, viz | 7 |
| Breach | breach, leaked, pastewatch, creds | 4 |
| Automation | auto, scan, chain, recon, autopilot | 5 |
| Kali Wrappers | nmap, nikto, sqlmap, nuclei, amass, subfinder, gobuster, hydra | 8+ |

---

## 📦 Phase 6: Full Desktop OS (Bootable USB — Plug & Play)

### Desktop Environment: MATE (lightweight, Parrot-style)

```
┌─────────────────────────────────────────────────────────────────┐
│ 🔴 OMEGA-OS v2.0  |  ☁ VPN: OFF  |  🧅 Tor: OFF  |  🤖 AI: ● │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ 🔍 Omega     │  │ 🌐 Firefox   │  │ 📊 Burp      │         │
│  │    CLI       │  │    Browser   │  │    Suite     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ 🤖 AI Agent  │  │ 🦈 Wireshark │  │ 💀 Metasploit│         │
│  │   Manager    │  │              │  │              │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ 📁 Files     │  │ 🔧 Settings  │  │ 📝 Notes     │         │
│  │              │  │              │  │ (CherryTree) │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ 🔴 Menu  📂 Files  🖥 Terminal  🌐 Browser          19:43 UTC  │
└─────────────────────────────────────────────────────────────────┘
```

### Desktop Apps & Features

| App | Purpose |
|-----|---------|
| Omega CLI Terminal | Auto-opens on login with pink banner |
| Omega AI Manager | GUI for agent control (Tkinter/GTK) |
| Firefox (hardened) | Pre-configured with privacy extensions |
| Burp Suite Community | Web application testing |
| Wireshark | Packet analysis |
| Metasploit | Exploitation framework |
| CherryTree | Note-taking for engagements |
| Thunar/Caja | File manager |
| Tilix/Terminator | Split terminal emulator |
| Ollama GUI | Local AI model management |

### Boot Sequence

```
Power On → GRUB (Pink OMEGA Splash)
  ├── Live Mode (RAM only — no traces)
  ├── Persistent Mode (saves to USB partition)
  └── Install to Disk (optional)

→ Auto-login → MATE Desktop
  → Terminal auto-opens → omega banner
  → Ollama starts in background (systemd service)
  → AI Agent Manager tray icon active
  → MCP Server starts (systemd service, port 6660)
  → Notification agent watches for findings
```

### Custom Theme

```
Colors:
  - Primary:    #ff2d78 (OMEGA pink)
  - Secondary:  #1a1a2e (dark background)
  - Accent:     #ff85b3 (light pink)
  - Terminal:   #0d0d0d bg, #ff2d78 prompt, #ffffff text

Plymouth boot splash:  Pink OMEGA ASCII art + progress bar
GRUB theme:            Dark with pink highlights
Wallpaper:             Custom OMEGA-OS branded dark wallpaper
Icon theme:            Papirus Dark (modified pink accents)
GTK theme:             Arc Dark (modified)
Terminal prompt:       [omega@omega-os] ~/target $
```

### Systemd Services (auto-start on boot)

```ini
# /etc/systemd/system/ollama.service
[Unit]
Description=Ollama AI Runtime
After=network.target
[Service]
ExecStart=/usr/local/bin/ollama serve
Restart=always
[Install]
WantedBy=multi-user.target

# /etc/systemd/system/omega-mcp.service
[Unit]
Description=Omega MCP Server
After=ollama.service
[Service]
ExecStart=/opt/omega-venv/bin/python -m omega_mcp.server --port 6660
Restart=always
User=omega
[Install]
WantedBy=multi-user.target

# /etc/systemd/system/omega-agent-manager.service
[Unit]
Description=Omega AI Agent Manager
After=ollama.service
[Service]
ExecStart=/opt/omega-venv/bin/python -m omega_cli.agents.manager --daemon
Restart=always
User=omega
[Install]
WantedBy=multi-user.target
```

### ISO Build Specs

```
Base:          Debian 13 Trixie (or Parrot Security Edition)
Kernel:        Linux 6.x (latest stable)
Desktop:       MATE 1.28+
Architecture:  amd64 (x86_64)
ISO Size:      ~8-10 GB (full), ~4 GB (slim)
USB Size:      16 GB minimum (32 GB recommended for persistent)
RAM Required:  4 GB minimum (8 GB recommended for AI)
```

### Partition Layout (USB)

```
/dev/sdX
├── Part 1: EFI System (512 MB, FAT32)
│   └── EFI/BOOT/grubx64.efi
├── Part 2: Live System (6-8 GB, SquashFS in ext4)
│   └── live/ (vmlinuz, initrd, filesystem.squashfs)
└── Part 3: Persistence (rest of drive, ext4, LUKS encrypted)
    └── /home, /opt/omega, /reports, /root/.config
```

---

## 📦 Phase 7: GitHub Repos Structure

### Repositories to Create

| Repo | Description | Contents |
|------|-------------|----------|
| `omega-cli` | Core CLI toolkit (existing) | 108 OSINT commands |
| `omega-mcp-server` | MCP server for Copilot/AI integration | FastMCP + all tool wrappers |
| `omega-agents` | AI Agent Framework | 15 specialist agents + manager |
| `omega-os` | Desktop OS build system | Dockerfile, ISO builder, desktop configs |
| `omega-plugins` | Community plugin repository | User-contributed modules |

### CI/CD (GitHub Actions)

```yaml
# omega-mcp-server/.github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e ".[dev]"
      - run: pytest tests/ -v

  publish:
    needs: test
    if: startsWith(github.ref, 'refs/tags/')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install build twine
      - run: python -m build
      - run: twine upload dist/*
        env: { TWINE_PASSWORD: "${{ secrets.PYPI_TOKEN }}" }

  docker:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:latest
```

---

## 🗂️ Updated Todo Summary

| # | Task | Phase | Depends On | Effort |
|---|------|-------|-----------|--------|
| 1 | `agents/base_agent.py` — base class | 2 | — | Medium |
| 2 | `agents/memory.py` — SQLite shared memory | 2 | — | Medium |
| 3 | `agents/executor.py` — tool execution | 2 | — | Medium |
| 4 | `agents/planner.py` — task decomposition | 2 | 1 | Medium |
| 5 | `agents/router.py` — task→agent routing | 2 | 1,4 | Medium |
| 6 | `agents/manager.py` — orchestrator | 2 | 1-5 | Large |
| 7 | 15 specialist agents | 2 | 1,2,3 | Large |
| 8 | CLI commands: agent, autopilot, chat | 2 | 6 | Medium |
| 9 | `omega-mcp-server` repo + server.py | 5 | — | Medium |
| 10 | MCP tools (108 wrappers) | 5 | 9 | Large |
| 11 | MCP resources + prompts | 5 | 9 | Small |
| 12 | MCP CI/CD + PyPI publish | 5 | 9,10 | Small |
| 13 | Dockerfile v2.0 (Parrot base) | 3 | — | Medium |
| 14 | Ollama integration | 3 | — | Small |
| 15 | Desktop theme + configs | 6 | — | Medium |
| 16 | build-iso.sh v2.0 | 4,6 | 13,15 | Large |
| 17 | make-bootable.sh v2.0 | 4,6 | 16 | Medium |
| 18 | Persistence + LUKS encryption | 4,6 | 16 | Medium |
| 19 | GitHub repos setup + CI | 7 | All | Medium |
| 20 | Documentation + README | 7 | All | Medium |

---

## 💡 Key Design Decisions

1. **Ollama-first**: All AI runs locally by default. OpenAI optional.
2. **Agent handoff**: Agents delegate to each other (recon→vuln→exploit).
3. **Shared memory**: SQLite stores all findings. Any agent can query.
4. **MCP-native**: Every omega tool is a first-class MCP tool.
5. **Human-in-the-loop**: Exploitation agents ALWAYS confirm before acting.
6. **Plugin system**: Custom agents/tools via `omega plugin`.
7. **100% offline**: Everything works without internet (except scanning).
8. **Persistent USB**: Reports/configs survive reboots (LUKS encrypted).
9. **Dual-mode**: Container (Docker) OR bootable USB — same codebase.

---

*Plan v2.0 — 2026-03-31 | Omega-OS Full Architecture*
*Phases: 7 | Repos: 5 | Tools: 800+ | AI Agents: 15 | MCP Tools: 108+*
