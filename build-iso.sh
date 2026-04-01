#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  build-iso.sh — build omega-live.iso using live-build (Debian-based)
#
#  Produces a bootable ISO (~800MB) with:
#    - Debian 12 (Bookworm) base
#    - Python 3.11 + pipx
#    - omega-cli v0.3.0 pre-installed
#    - GRUB (UEFI + BIOS), persistent storage support
#    - Auto-login to 'omega' user
#    - MOTD with omega banner
#
#  Run as root on a Debian/Ubuntu host:
#    sudo bash build-iso.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="/tmp/omega-live-build"
OUTPUT_ISO="$SCRIPT_DIR/omega-live.iso"
OMEGA_SRC="$SCRIPT_DIR/omega-cli-bundle/omega-cli"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}[*] Building omega-live ISO...${NC}"
echo -e "${CYAN}[*] Build dir: $BUILD_DIR${NC}"

# ── Install live-build ───────────────────────────────────────────────────────
if ! command -v lb &>/dev/null; then
    apt-get install -y live-build debootstrap squashfs-tools
fi

# ── Setup build dir ──────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ── Configure live-build ─────────────────────────────────────────────────────
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
    --hostname omega-live \
    --image-name omega-live

# ── Package list ─────────────────────────────────────────────────────────────
mkdir -p config/package-lists
cat > config/package-lists/omega.list.chroot <<'PKGEOF'
# Core system
bash
curl
wget
git
vim
nano
htop
net-tools
iputils-ping
dnsutils
whois
nmap
netcat-openbsd
tcpdump
traceroute
# Python
python3
python3-pip
python3-venv
pipx
# SSL/TLS tools
openssl
ca-certificates
# Terminal tools
tmux
screen
less
file
unzip
# Network
openssh-client
tor
proxychains4
PKGEOF

# ── Hooks: install omega-cli ─────────────────────────────────────────────────
mkdir -p config/hooks/live

cat > config/hooks/live/0100-omega-install.hook.chroot <<'HOOKEOF'
#!/bin/bash
set -e
export HOME=/root
export PATH="$PATH:/root/.local/bin"

# Create omega user with sudo
useradd -m -s /bin/bash omega || true
echo "omega:omega" | chpasswd
usermod -aG sudo omega

# Auto-login setup
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat > /etc/systemd/system/getty@tty1.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin omega --noclear %I $TERM
EOF

# Install pipx for omega user
sudo -u omega bash -c '
    export HOME=/home/omega
    python3 -m pip install --user pipx 2>/dev/null || true
    python3 -m pipx ensurepath 2>/dev/null || true
'

echo "omega-cli install pending — will complete on first boot"
HOOKEOF

chmod +x config/hooks/live/0100-omega-install.hook.chroot

# ── Copy omega-cli source into chroot ────────────────────────────────────────
mkdir -p config/includes.chroot/opt/omega-cli
if [ -d "$OMEGA_SRC" ]; then
    cp -r "$OMEGA_SRC/." config/includes.chroot/opt/omega-cli/
else
    echo -e "${YELLOW}[!] omega-cli source not found at $OMEGA_SRC — will download from current host${NC}"
    cp -r /home/*/.local/share/pipx/venvs/omega-cli 2>/dev/null \
        config/includes.chroot/opt/omega-cli/ || true
fi

# ── First-boot service: install omega-cli ────────────────────────────────────
mkdir -p config/includes.chroot/etc/systemd/system
cat > config/includes.chroot/etc/systemd/system/omega-firstboot.service <<'SVCEOF'
[Unit]
Description=omega-cli first-boot installer
After=network-online.target
Wants=network-online.target
ConditionPathExists=!/var/lib/omega-installed

[Service]
Type=oneshot
User=omega
Environment=HOME=/home/omega
ExecStart=/bin/bash -c 'cd /opt/omega-cli && python3 -m pip install --user pipx && python3 -m pipx install /opt/omega-cli && touch /var/lib/omega-installed'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF

mkdir -p config/includes.chroot/etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/omega-firstboot.service \
    config/includes.chroot/etc/systemd/system/multi-user.target.wants/omega-firstboot.service

# ── MOTD / bashrc ────────────────────────────────────────────────────────────
mkdir -p config/includes.chroot/home/omega
cat > config/includes.chroot/home/omega/.bashrc <<'RCEOF'
export PATH="$PATH:/home/omega/.local/bin"
export PS1='\[\033[1;35m\][omega]\[\033[0m\] \w \$ '

# Show banner on login
if [ -f /home/omega/.local/bin/omega ]; then
    omega banner 2>/dev/null || true
fi

echo -e "\033[1;36momega-cli v0.3.0 — OSINT Toolkit\033[0m"
echo -e "\033[0;37mRun: omega scan <target>  |  omega --help\033[0m\n"

alias ll='ls -lah --color=auto'
alias cls='clear'
RCEOF

# ── Build ─────────────────────────────────────────────────────────────────────
echo -e "${CYAN}[*] Running lb build (this takes 10-20 minutes)...${NC}"
lb build 2>&1 | tee /tmp/omega-lb-build.log

# Find and copy the ISO
BUILT_ISO=$(find "$BUILD_DIR" -name "*.iso" | head -1)
if [ -f "$BUILT_ISO" ]; then
    cp "$BUILT_ISO" "$OUTPUT_ISO"
    ISO_SIZE=$(du -sh "$OUTPUT_ISO" | cut -f1)
    echo -e "\n${GREEN}[✓] ISO built: $OUTPUT_ISO ($ISO_SIZE)${NC}"
    echo -e "${GREEN}[✓] Run: sudo bash make-bootable.sh /dev/sdX${NC}"
else
    echo -e "${RED}[!] Build failed. Check /tmp/omega-lb-build.log${NC}"
    exit 1
fi
