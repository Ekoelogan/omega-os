#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  make-bootable.sh — write omega-cli bootable system to WD Passport
#
#  Creates a TWO-PARTITION layout on the drive:
#    Part 1: FAT32 EFI/boot  (512MB)
#    Part 2: ext4 persistent Linux (rest of drive)
#
#  Boots a minimal Debian live system with omega-cli pre-installed.
#  Supports BOTH UEFI and Legacy BIOS.
#
#  Usage:
#    sudo bash make-bootable.sh /dev/sdX
#
#  WARNING: ALL DATA ON THE TARGET DRIVE WILL BE ERASED.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ISO_PATH="$(dirname "$0")/omega-live.iso"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

# ── Banner ───────────────────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat <<'EOF'
  ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗ 
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  Bootable Drive Builder — WD Passport Edition
EOF
echo -e "${NC}"

# ── Arg check ────────────────────────────────────────────────────────────────
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: sudo bash make-bootable.sh /dev/sdX${NC}"
    echo ""
    echo "Available drives:"
    lsblk -d -o NAME,SIZE,MODEL,TRAN | grep -v loop
    exit 1
fi

DRIVE="$1"

if [ ! -b "$DRIVE" ]; then
    echo -e "${RED}[!] $DRIVE is not a block device.${NC}"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Must be run as root: sudo bash make-bootable.sh $DRIVE${NC}"
    exit 1
fi

# Safety check — prevent wiping system drive
ROOT_DRIVE=$(lsblk -no PKNAME "$(findmnt -n -o SOURCE /)" 2>/dev/null | head -1)
ROOT_DRIVE="/dev/${ROOT_DRIVE}"
if [ "$DRIVE" = "$ROOT_DRIVE" ]; then
    echo -e "${RED}[!] REFUSING: $DRIVE appears to be your system drive ($ROOT_DRIVE).${NC}"
    exit 1
fi

DRIVE_INFO=$(lsblk -d -o NAME,SIZE,MODEL "$DRIVE" 2>/dev/null | tail -1)
echo -e "${YELLOW}${BOLD}⚠  TARGET DRIVE: $DRIVE_INFO${NC}"
echo -e "${RED}${BOLD}   ALL DATA ON $DRIVE WILL BE PERMANENTLY ERASED.${NC}"
echo ""
read -rp "Type YES to confirm: " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
    echo "Aborted."
    exit 0
fi

# ── Build ISO first ──────────────────────────────────────────────────────────
if [ ! -f "$ISO_PATH" ]; then
    echo -e "\n${CYAN}[*] Building omega-live ISO (this takes ~10-20 min)...${NC}"
    bash "$SCRIPT_DIR/build-iso.sh"
fi

if [ ! -f "$ISO_PATH" ]; then
    echo -e "${RED}[!] ISO not found at $ISO_PATH. Run build-iso.sh first.${NC}"
    exit 1
fi

ISO_SIZE=$(du -sh "$ISO_PATH" | cut -f1)
echo -e "\n${CYAN}[*] Writing $ISO_PATH ($ISO_SIZE) to $DRIVE ...${NC}"
echo    "    This will take several minutes. Do not unplug the drive."
echo ""

# Write ISO to drive
dd if="$ISO_PATH" of="$DRIVE" bs=4M status=progress oflag=sync conv=fsync

sync

echo -e "\n${GREEN}${BOLD}[✓] Done! $DRIVE is now bootable.${NC}"
echo ""
echo -e "${CYAN}Boot instructions:${NC}"
echo "  1. Safely eject the drive"
echo "  2. Plug into target machine"
echo "  3. At boot: press F12/F2/Del/Esc to open boot menu"
echo "  4. Select your WD Passport / USB drive"
echo "  5. Select 'omega Live (persistent)' from GRUB menu"
echo "  6. Login: user=omega  password=omega"
echo "  7. Run: omega scan <target>"
echo ""
echo -e "${YELLOW}Tip: For UEFI-only machines, select the UEFI entry in your boot menu.${NC}"
