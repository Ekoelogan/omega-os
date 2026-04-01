#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  omega-install: bootstrap omega-cli onto any Linux machine FROM this drive
#  Usage: bash /path/to/passport/install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OMEGA_SRC="$SCRIPT_DIR/omega-cli-bundle/omega-cli"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${CYAN}"
cat <<'EOF'
  ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  Installer — installing omega-cli onto this machine
EOF
echo -e "${NC}"

# Detect package manager
install_deps() {
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y python3 python3-pip python3-venv pipx 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3 python3-pip pipx 2>/dev/null || true
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm python python-pip python-pipx 2>/dev/null || true
    elif command -v brew &>/dev/null; then
        brew install python pipx 2>/dev/null || true
    fi
}

echo -e "${CYAN}[*] Checking dependencies...${NC}"
install_deps

if command -v pipx &>/dev/null; then
    echo -e "${CYAN}[*] Installing omega-cli via pipx...${NC}"
    pipx install "$OMEGA_SRC"
    pipx ensurepath
    echo -e "${GREEN}[✓] Done! Run: omega --help${NC}"
    echo -e "${YELLOW}[!] You may need to restart your shell or run: source ~/.bashrc${NC}"
elif command -v pip3 &>/dev/null; then
    echo -e "${CYAN}[*] Installing omega-cli via pip (user)...${NC}"
    pip3 install --user -e "$OMEGA_SRC"
    echo -e "${GREEN}[✓] Done! Run: omega --help${NC}"
else
    echo -e "${YELLOW}[!] No pip/pipx found. Running from drive instead...${NC}"
    "$SCRIPT_DIR/omega" --help
fi
