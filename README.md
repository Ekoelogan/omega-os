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
| **AI Agents** | 15 specialist bots (recon, web, vuln, cloud, social, exploit, forensics, etc.) + shared memory |
| **MCP Server** | 108+ tools exposed to Copilot, Claude, VS Code via Model Context Protocol |
| **Ollama** | Local LLM (llama3.2) for AI analysis without cloud APIs |
| **Kali Tools** | nmap, nikto, sqlmap, nuclei, hydra, john, amass, subfinder, and more |
| **Desktop** | MATE environment with pink OMEGA theme, Plymouth splash, custom GRUB |

## AI Agent Framework

```bash
omega agents                                  # List all 15 agents
omega agent recon-agent example.com           # Single agent
omega autopilot example.com --task bug-bounty # Multi-agent workflow
omega chat                                    # Interactive AI chat mode
omega memory --stats                          # Query findings
```

### 15 Specialist Agents

| Agent | Specialty |
|-------|-----------|
| recon-agent | WHOIS, DNS, subdomains, certs, IP intel |
| web-agent | Headers, CORS, JS secrets, crawling |
| vuln-agent | CVE lookup, vuln scanning, risk scoring |
| cloud-agent | S3 buckets, Azure/GCP storage |
| social-agent | Username/email search, social profiles |
| exploit-agent | Exploitation, red team ops |
| wifi-agent | Wireless analysis, AP discovery |
| password-agent | Credential auditing, breach checks |
| forensics-agent | Document/image analysis, IOC extraction |
| reverse-agent | Firmware/binary analysis |
| post-agent | Exfil/C2 detection, lateral movement |
| privacy-agent | Tor checks, OPSEC, dark web |
| crypto-agent | Blockchain tracing, stego detection |
| ai-security-agent | ML model auditing, AI threat detection |
| report-agent | PDF/HTML reports, executive summaries |

## MCP Server Integration

```json
{ "mcpServers": { "omega": { "command": "omega-mcp" } } }
```

## Bootable USB (Live OS)

```bash
sudo bash build-iso.sh                         # Build ISO (~8-10 GB)
sudo bash make-bootable.sh /dev/sdX             # Flash to USB
sudo bash make-bootable.sh /dev/sdX --encrypt   # With LUKS encryption
```

### Boot Modes
- **Live Mode** — RAM only, no traces left on host machine
- **Persistent Mode** — saves data to USB partition between reboots
- **Safe Mode** — no GPU drivers (nomodeset)
- **Forensics Mode** — loads entirely to RAM

### Desktop Features
- MATE environment with dark pink OMEGA theme
- Custom GRUB boot splash & Plymouth animation
- Auto-login → Terminal opens with omega banner
- Ollama + MCP server start as systemd services
- Persistent partition (optional LUKS encryption)

## Build Options

| Mode | Command | Description |
|------|---------|-------------|
| Docker build | `./build.sh` | Build container image |
| Docker run | `./build.sh run` | Interactive shell |
| Docker MCP | `./build.sh mcp` | MCP server (stdio) |
| Save to USB | `./build.sh save-usb /media/drive` | Save Docker image to USB |
| Build ISO | `sudo bash build-iso.sh` | Full bootable live ISO |
| Flash USB | `sudo bash make-bootable.sh /dev/sdX` | Flash ISO to USB drive |
| Portable | `./omega` | Run from USB without install |
| Install | `bash install.sh` | Install omega-cli to host |

## Repos

| Repo | Description |
|------|-------------|
| [omega-cli](https://github.com/Ekoelogan/omega-cli) | Core CLI + 15 AI agents |
| [omega-mcp-server](https://github.com/Ekoelogan/omega-mcp-server) | MCP server (108+ tools) |
| [omega-os](https://github.com/Ekoelogan/omega-os) | Docker, ISO builder, USB flasher, desktop theme |

## Requirements

- **Docker mode**: Docker on host machine
- **ISO build**: Debian/Ubuntu host + 8GB+ free disk + root access
- **USB boot**: 16GB+ USB drive (32GB recommended for persistent)
- **RAM**: 4GB minimum, 8GB recommended for AI features

## License

MIT — see [LICENSE](LICENSE)
