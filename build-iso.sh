#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  build-iso.sh — OMEGA-OS v2.0 Live ISO builder using live-build
#
#  Produces a bootable ISO with:
#    - Debian 12 (Bookworm) base + Kali tools
#    - Python 3.11+ / pipx / omega-cli v1.8.0 + AI agents
#    - omega-mcp-server for AI assistant integration
#    - Ollama for local LLM inference
#    - MATE desktop with pink OMEGA theme
#    - GRUB (UEFI + BIOS), persistent storage support
#    - Auto-login to 'omega' user
#
#  Run as root on a Debian/Ubuntu host (needs ~8GB disk):
#    sudo bash build-iso.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/omega-live-build"
OUTPUT_ISO="$SCRIPT_DIR/omega-os-v2.iso"
OMEGA_CLI_SRC="$SCRIPT_DIR/../omega-cli"
OMEGA_MCP_SRC="$SCRIPT_DIR/../omega-mcp-server"

PINK='\033[38;2;255;45;120m'
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${PINK}"
echo " ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗       ██████╗ ███████╗"
echo "██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗     ██╔═══██╗██╔════╝"
echo "██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║     ██║   ██║███████╗"
echo "██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║     ██║   ██║╚════██║"
echo "╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║     ╚██████╔╝███████║"
echo " ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚═════╝╚══════╝"
echo -e "${NC}"
echo "  OMEGA-OS v2.0 — ISO Builder"
echo ""

# ── Preflight checks ────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Must run as root: sudo bash build-iso.sh${NC}"
    exit 1
fi

if ! command -v lb &>/dev/null; then
    echo -e "${CYAN}[*] Installing live-build...${NC}"
    apt-get update -qq && apt-get install -y live-build debootstrap squashfs-tools xorriso
fi

# ── Setup build dir ──────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ── Configure live-build ─────────────────────────────────────────────────────
echo -e "${CYAN}[*] Configuring live-build...${NC}"
lb config \
    --distribution bookworm \
    --architectures amd64 \
    --binary-images iso-hybrid \
    --bootloaders "grub-efi,syslinux" \
    --debian-installer none \
    --archive-areas "main contrib non-free non-free-firmware" \
    --apt-recommends false \
    --memtest none \
    --win32-loader false \
    --username omega \
    --hostname omega-os \
    --image-name omega-os-v2

# ── Package list ─────────────────────────────────────────────────────────────
mkdir -p config/package-lists
cat > config/package-lists/omega.list.chroot <<'PKGEOF'
# Core system
bash curl wget git vim nano htop net-tools iputils-ping
# Network & scanning
dnsutils whois nmap netcat-openbsd tcpdump traceroute
# Python
python3 python3-pip python3-venv python3-dev pipx
# Build tools
build-essential libffi-dev libssl-dev
# SSL/TLS
openssl ca-certificates sslyze
# Terminal
tmux screen less file unzip jq tree
# Network
openssh-client tor proxychains4
# Desktop (MATE)
mate-desktop-environment-core mate-terminal mate-themes
lightdm lightdm-gtk-greeter plymouth plymouth-themes
# Security tools
nikto dirb gobuster sqlmap hydra john
exiftool foremost binwalk steghide
PKGEOF

# ── Hooks: install omega-cli + Ollama ────────────────────────────────────────
mkdir -p config/hooks/live
cat > config/hooks/live/0100-omega-install.hook.chroot <<'HOOKEOF'
#!/bin/bash
set -e

# Create omega user
useradd -m -s /bin/bash -G sudo omega || true
echo "omega:omega" | chpasswd

# Auto-login (TTY)
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin omega --noclear %I \$TERM
EOF

# Auto-login (LightDM)
mkdir -p /etc/lightdm
cat > /etc/lightdm/lightdm.conf <<EOF
[Seat:*]
autologin-user=omega
autologin-user-timeout=0
user-session=mate
EOF

# Install omega-cli + MCP server
cd /opt/omega-cli && python3 -m venv /opt/omega-venv
/opt/omega-venv/bin/pip install --no-cache-dir -U pip
/opt/omega-venv/bin/pip install --no-cache-dir /opt/omega-cli/
/opt/omega-venv/bin/pip install --no-cache-dir /opt/omega-mcp-server/
ln -sf /opt/omega-venv/bin/omega /usr/local/bin/omega
ln -sf /opt/omega-venv/bin/omega-mcp /usr/local/bin/omega-mcp

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh || true

# Ollama systemd service
cat > /etc/systemd/system/ollama.service <<EOF
[Unit]
Description=Ollama AI Server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
Restart=always
Environment=OLLAMA_HOST=0.0.0.0:11434

[Install]
WantedBy=multi-user.target
EOF
systemctl enable ollama.service || true

# MCP server systemd service
cat > /etc/systemd/system/omega-mcp.service <<EOF
[Unit]
Description=OMEGA MCP Server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/omega-mcp --transport sse
Restart=always
User=omega

[Install]
WantedBy=multi-user.target
EOF
systemctl enable omega-mcp.service || true
HOOKEOF
chmod +x config/hooks/live/0100-omega-install.hook.chroot

# ── Copy sources into chroot ─────────────────────────────────────────────────
mkdir -p config/includes.chroot/opt/omega-cli
mkdir -p config/includes.chroot/opt/omega-mcp-server

if [ -d "$OMEGA_CLI_SRC" ]; then
    cp -r "$OMEGA_CLI_SRC/." config/includes.chroot/opt/omega-cli/
    echo -e "${GREEN}[✓] omega-cli source copied${NC}"
fi
if [ -d "$OMEGA_MCP_SRC" ]; then
    cp -r "$OMEGA_MCP_SRC/." config/includes.chroot/opt/omega-mcp-server/
    echo -e "${GREEN}[✓] omega-mcp-server source copied${NC}"
fi

# ── Desktop theme ────────────────────────────────────────────────────────────
if [ -d "$SCRIPT_DIR/desktop" ]; then
    # GSchema override for MATE theme
    mkdir -p config/includes.chroot/usr/share/glib-2.0/schemas
    cp "$SCRIPT_DIR/desktop/omega-desktop.gschema.override" \
       config/includes.chroot/usr/share/glib-2.0/schemas/ 2>/dev/null || true

    # Wallpaper
    mkdir -p config/includes.chroot/usr/share/backgrounds
    cp "$SCRIPT_DIR/desktop/omega-wallpaper.svg" \
       config/includes.chroot/usr/share/backgrounds/ 2>/dev/null || true

    # Plymouth splash
    mkdir -p config/includes.chroot/usr/share/plymouth/themes/omega
    cp "$SCRIPT_DIR/desktop/omega-plymouth.script" \
       config/includes.chroot/usr/share/plymouth/themes/omega/ 2>/dev/null || true

    # Autostart
    mkdir -p config/includes.chroot/etc/xdg/autostart
    cp "$SCRIPT_DIR/desktop/omega.desktop" \
       config/includes.chroot/etc/xdg/autostart/ 2>/dev/null || true

    echo -e "${GREEN}[✓] Desktop theme installed${NC}"
fi

# ── GRUB theme ───────────────────────────────────────────────────────────────
mkdir -p config/includes.binary/boot/grub/themes/omega
cat > config/includes.binary/boot/grub/themes/omega/theme.txt <<'GRUBTHEME'
# OMEGA-OS GRUB Theme
title-text: ""
desktop-color: "#0d1117"
desktop-image: ""

+ boot_menu {
    left = 25%
    top = 30%
    width = 50%
    height = 40%
    item_font = "Monospace Regular 14"
    item_color = "#c9d1d9"
    selected_item_font = "Monospace Bold 14"
    selected_item_color = "#ff2d78"
    item_height = 28
    item_padding = 8
    item_spacing = 4
    selected_item_pixmap_style = "select_*.png"
}

+ label {
    left = 25%
    top = 15%
    width = 50%
    align = "center"
    color = "#ff2d78"
    font = "Monospace Bold 24"
    text = "OMEGA-OS v2.0"
}

+ label {
    left = 25%
    top = 22%
    width = 50%
    align = "center"
    color = "#484f58"
    font = "Monospace Regular 12"
    text = "AI-Powered OSINT & Security Toolkit"
}

+ label {
    left = 25%
    top = 80%
    width = 50%
    align = "center"
    color = "#484f58"
    font = "Monospace Regular 10"
    text = "Select boot mode and press Enter"
}
GRUBTHEME

# GRUB configuration with menu entries
mkdir -p config/includes.binary/boot/grub
cat > config/includes.binary/boot/grub/grub.cfg <<'GRUBCFG'
set default=0
set timeout=5
set gfxmode=1024x768,auto
set theme=/boot/grub/themes/omega/theme.txt

insmod gfxterm
terminal_output gfxterm

menuentry "OMEGA-OS v2.0 Live" {
    linux /live/vmlinuz boot=live components quiet splash
    initrd /live/initrd.img
}

menuentry "OMEGA-OS v2.0 Live (Persistent)" {
    linux /live/vmlinuz boot=live components persistence quiet splash
    initrd /live/initrd.img
}

menuentry "OMEGA-OS v2.0 (Safe Mode)" {
    linux /live/vmlinuz boot=live components nomodeset
    initrd /live/initrd.img
}

menuentry "OMEGA-OS v2.0 (RAM Only — Forensics)" {
    linux /live/vmlinuz boot=live components toram quiet splash
    initrd /live/initrd.img
}
GRUBCFG

echo -e "${GREEN}[✓] GRUB theme configured${NC}"

# ── User bashrc ──────────────────────────────────────────────────────────────
mkdir -p config/includes.chroot/home/omega
cat > config/includes.chroot/home/omega/.bashrc <<'RCEOF'
export PATH="/opt/omega-venv/bin:$PATH:/home/omega/.local/bin"
export PS1='\[\033[38;2;255;45;120m\][omega-os]\[\033[0m\] \w \$ '

# Show banner on login
omega 2>/dev/null || true
echo -e "\033[38;2;255;45;120mOMEGA-OS v2.0\033[0m — AI-Powered OSINT & Security Toolkit"
echo -e "\033[0;37mRun: omega --help  |  omega chat  |  omega autopilot <target>  |  omega agents\033[0m"
echo ""

alias ll='ls -lah --color=auto'
alias cls='clear'
RCEOF

# ── Build ────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}[*] Running lb build (this takes 15-30 minutes)...${NC}"
lb build 2>&1 | tee /tmp/omega-lb-build.log

BUILT_ISO=$(find "$BUILD_DIR" -name "*.iso" | head -1)
if [ -f "$BUILT_ISO" ]; then
    cp "$BUILT_ISO" "$OUTPUT_ISO"
    ISO_SIZE=$(du -sh "$OUTPUT_ISO" | cut -f1)
    echo -e "\n${GREEN}[✓] ISO built: $OUTPUT_ISO ($ISO_SIZE)${NC}"
    echo -e "${GREEN}[✓] Flash: sudo bash make-bootable.sh /dev/sdX${NC}"
else
    echo -e "${RED}[!] Build failed. Check /tmp/omega-lb-build.log${NC}"
    exit 1
fi
