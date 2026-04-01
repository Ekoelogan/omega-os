# Omega-OS — Portable OSINT & Recon Container

## What's Inside

**Omega-CLI v1.8.0** (108 OSINT commands) + **40+ Kali Linux tools**:

### 🔍 Scanning & Enumeration
nmap, masscan, amass, subfinder, httpx, naabu

### 🌐 Web Application Testing
nikto, gobuster, dirb, wfuzz, whatweb, sqlmap, nuclei, katana

### 🔎 OSINT Frameworks
theHarvester, recon-ng, spiderfoot, waybackurls, gau

### 🔑 Credential Tools
hydra, john, hashcat

### 📡 Network Analysis
tcpdump, tshark, mitmproxy, sslyze, sslscan, testssl.sh

### 🔬 Forensics & Metadata
exiftool, binwalk, foremost, steghide, radare2

### 📚 Wordlists
SecLists (full), Kali default wordlists

---

## Quick Start

```bash
# Build
cd omega-portable && chmod +x build.sh
./build.sh build

# Run
./build.sh run

# Save to USB
./build.sh save-usb /media/username/MyPassport

# Load on another machine
docker load < omega-os.tar.gz
./omega-os.sh run
```

## Requirements
- Docker on host machine
- 5+ GB disk space
- 100% portable, 100% local
