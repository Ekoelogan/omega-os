# OMEGA-OS v2.0

**AI-Powered OSINT & Security Operating System**

A complete security toolkit: Docker container, bootable USB, or full desktop OS.

## Quick Start (Docker)

```bash
git clone https://github.com/Ekoelogan/omega-os.git
cd omega-os
./build.sh        # Build container
./build.sh run    # Launch interactive shell
./build.sh mcp    # MCP server mode (for AI assistants)
```

## What's Inside

| Layer | Components |
|-------|-----------|
| **omega-cli** | 108+ OSINT commands (WHOIS, DNS, subdomains, headers, SSL, ports, CVEs...) |
| **AI Agents** | 6 specialist bots (recon, web, vuln, cloud, social, report) + shared memory |
| **MCP Server** | 30+ tools exposed to Copilot, Claude, VS Code via Model Context Protocol |
| **Ollama** | Local LLM (llama3.2) for AI analysis without cloud APIs |
| **Kali Tools** | nmap, nikto, sqlmap, nuclei, hydra, john, amass, subfinder, and more |

## AI Agent Framework

```bash
omega agents                                  # List agents
omega agent recon-agent example.com           # Single agent
omega autopilot example.com --task bug-bounty # Multi-agent workflow
omega memory --stats                          # Query findings
```

## MCP Server Integration

```json
{ "mcpServers": { "omega": { "command": "omega-mcp" } } }
```

## Bootable USB

```bash
sudo bash build-iso.sh                         # Build ISO
sudo bash make-bootable.sh /dev/sdX             # Flash to USB
sudo bash make-bootable.sh /dev/sdX --encrypt   # With LUKS encryption
```

Boot from USB: MATE desktop + all tools ready. Persistent storage survives reboots.

## Repos

| Repo | Description |
|------|-------------|
| [omega-cli](https://github.com/Ekoelogan/omega-cli) | Core CLI + AI agent framework |
| [omega-mcp-server](https://github.com/Ekoelogan/omega-mcp-server) | MCP server for AI assistants |
| [omega-os](https://github.com/Ekoelogan/omega-os) | Docker, ISO builder, USB flasher, desktop theme |

## Requirements
- Docker on host machine (container mode)
- OR: Debian/Ubuntu host + 8GB+ disk for ISO build
- 16GB+ USB drive for bootable mode

## License
MIT
