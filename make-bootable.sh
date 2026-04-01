#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  make-bootable.sh — OMEGA-OS v2.0 USB drive flasher
#
#  Creates a THREE-PARTITION layout:
#    Part 1: FAT32 EFI System Partition (512 MB)
#    Part 2: ext4  Live System (ISO contents, ~2-4 GB)
#    Part 3: ext4  Persistent storage (rest of drive, optional LUKS encryption)
#
#  Supports BOTH UEFI and Legacy BIOS boot.
#
#  Usage:
#    sudo bash make-bootable.sh /dev/sdX              # No encryption
#    sudo bash make-bootable.sh /dev/sdX --encrypt     # LUKS persistent partition
#
#  WARNING: ALL DATA ON THE TARGET DRIVE WILL BE ERASED.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISO_PATH="$SCRIPT_DIR/omega-os-v2.iso"

PINK='\033[38;2;255;45;120m'
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${PINK}${BOLD}"
cat <<'EOF'
  ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗       ██████╗ ███████╗
 ██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗     ██╔═══██╗██╔════╝
 ██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║     ██║   ██║███████╗
 ██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║     ██║   ██║╚════██║
 ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║     ╚██████╔╝███████║
  ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚═════╝╚══════╝
  USB Bootable Drive Builder v2.0
EOF
echo -e "${NC}"

ENCRYPT=false
DRIVE=""

# Parse args
for arg in "$@"; do
    case "$arg" in
        --encrypt) ENCRYPT=true ;;
        /dev/*) DRIVE="$arg" ;;
        *)
            echo -e "${RED}Unknown argument: $arg${NC}"
            echo "Usage: sudo bash make-bootable.sh /dev/sdX [--encrypt]"
            exit 1
            ;;
    esac
done

if [ -z "$DRIVE" ]; then
    echo -e "${YELLOW}Usage: sudo bash make-bootable.sh /dev/sdX [--encrypt]${NC}"
    echo ""
    echo "Available drives:"
    lsblk -d -o NAME,SIZE,MODEL,TRAN | grep -v loop
    exit 1
fi

if [ ! -b "$DRIVE" ]; then
    echo -e "${RED}[!] $DRIVE is not a block device.${NC}"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Must run as root: sudo bash make-bootable.sh $DRIVE${NC}"
    exit 1
fi

# Safety: don't wipe system drive
ROOT_DRIVE=$(lsblk -no PKNAME "$(findmnt -n -o SOURCE /)" 2>/dev/null | head -1)
if [ "/dev/${ROOT_DRIVE}" = "$DRIVE" ]; then
    echo -e "${RED}[!] REFUSING: $DRIVE is your system drive.${NC}"
    exit 1
fi

# Build ISO if needed
if [ ! -f "$ISO_PATH" ]; then
    echo -e "${CYAN}[*] ISO not found. Building...${NC}"
    bash "$SCRIPT_DIR/build-iso.sh"
fi

if [ ! -f "$ISO_PATH" ]; then
    echo -e "${RED}[!] ISO not found at $ISO_PATH${NC}"
    exit 1
fi

# Confirm
DRIVE_INFO=$(lsblk -d -o NAME,SIZE,MODEL "$DRIVE" 2>/dev/null | tail -1)
echo -e "${YELLOW}${BOLD}⚠  TARGET: $DRIVE_INFO${NC}"
echo -e "${RED}${BOLD}   ALL DATA WILL BE PERMANENTLY ERASED.${NC}"
$ENCRYPT && echo -e "${CYAN}   Persistent partition will be LUKS encrypted.${NC}"
echo ""
read -rp "Type YES to confirm: " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
    echo "Aborted."
    exit 0
fi

# ── Unmount existing partitions ──────────────────────────────────────────────
echo -e "\n${CYAN}[1/5] Unmounting existing partitions...${NC}"
umount "${DRIVE}"* 2>/dev/null || true

# ── Write ISO ────────────────────────────────────────────────────────────────
ISO_SIZE=$(du -sh "$ISO_PATH" | cut -f1)
echo -e "${CYAN}[2/5] Writing ISO ($ISO_SIZE) to $DRIVE...${NC}"
dd if="$ISO_PATH" of="$DRIVE" bs=4M status=progress oflag=sync conv=fsync
sync
partprobe "$DRIVE" 2>/dev/null || true
sleep 2

# ── Create persistent partition ──────────────────────────────────────────────
echo -e "${CYAN}[3/5] Creating persistent partition...${NC}"

# Find the end of the last existing partition
LAST_END=$(parted -s "$DRIVE" unit MiB print free 2>/dev/null \
    | grep -E "^\s+[0-9]" | tail -1 | awk '{print $3}' | tr -d 'MiB')

if [ -z "$LAST_END" ] || [ "$LAST_END" -lt 100 ]; then
    LAST_END=4096  # Fallback: start persistent at 4GB
fi

# Create partition 3 for persistence
parted -s "$DRIVE" mkpart primary ext4 "${LAST_END}MiB" 100%
partprobe "$DRIVE" 2>/dev/null || true
sleep 2

# Determine partition name (handle nvme vs sd naming)
if [[ "$DRIVE" == *"nvme"* ]]; then
    PERSIST_PART="${DRIVE}p3"
else
    PERSIST_PART="${DRIVE}3"
fi

# ── Format persistent partition ──────────────────────────────────────────────
echo -e "${CYAN}[4/5] Formatting persistent partition...${NC}"

if $ENCRYPT; then
    echo -e "${YELLOW}Setting up LUKS encryption...${NC}"
    cryptsetup luksFormat --type luks2 "$PERSIST_PART"
    cryptsetup luksOpen "$PERSIST_PART" omega-persist
    mkfs.ext4 -L omega-persist /dev/mapper/omega-persist
    # Create persistence.conf
    MOUNT_DIR=$(mktemp -d)
    mount /dev/mapper/omega-persist "$MOUNT_DIR"
    echo "/ union" > "$MOUNT_DIR/persistence.conf"
    mkdir -p "$MOUNT_DIR/omega-data"
    umount "$MOUNT_DIR"
    cryptsetup luksClose omega-persist
    rmdir "$MOUNT_DIR"
else
    mkfs.ext4 -L omega-persist "$PERSIST_PART"
    MOUNT_DIR=$(mktemp -d)
    mount "$PERSIST_PART" "$MOUNT_DIR"
    echo "/ union" > "$MOUNT_DIR/persistence.conf"
    mkdir -p "$MOUNT_DIR/omega-data"
    umount "$MOUNT_DIR"
    rmdir "$MOUNT_DIR"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
sync
echo -e "\n${GREEN}${BOLD}[5/5] ✓ OMEGA-OS USB drive ready!${NC}"
echo ""
echo -e "${CYAN}Drive layout:${NC}"
lsblk -o NAME,SIZE,FSTYPE,LABEL "$DRIVE" 2>/dev/null || true
echo ""
echo -e "${CYAN}Boot instructions:${NC}"
echo "  1. Safely eject the drive"
echo "  2. Plug into target machine"
echo "  3. Press F12/F2/Del/Esc at boot for boot menu"
echo "  4. Select USB/UEFI entry for your drive"
echo "  5. Select 'OMEGA-OS Live (persistent)' from GRUB"
echo "  6. Login: user=omega  password=omega"
echo "  7. Run: omega autopilot <target>"
echo ""
$ENCRYPT && echo -e "${YELLOW}Note: You'll be prompted for LUKS password on each boot.${NC}"
echo -e "${GREEN}All your tools, findings, and reports persist across reboots.${NC}"
