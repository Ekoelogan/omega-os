#!/usr/bin/env bash
# ============================================================================
#  OMEGA-OS v2.0 Build & Run Script
#  Build:   ./build.sh
#  Run:     ./build.sh run
#  Shell:   ./build.sh shell
#  MCP:     ./build.sh mcp
# ============================================================================
set -euo pipefail

IMAGE_NAME="omega-os"
CONTAINER_NAME="omega-os-live"
REPORTS_DIR="${HOME}/omega-reports"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OMEGA_CLI_SRC="$(cd "${SCRIPT_DIR}/../omega-cli" && pwd)"
OMEGA_MCP_SRC="$(cd "${SCRIPT_DIR}/../omega-mcp-server" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
PINK='\033[38;2;255;45;120m'
NC='\033[0m'

banner() {
    echo -e "${PINK}"
    echo " ██████╗ ███╗   ███╗███████╗ ██████╗  █████╗       ██████╗ ███████╗"
    echo "██╔═══██╗████╗ ████║██╔════╝██╔════╝ ██╔══██╗     ██╔═══██╗██╔════╝"
    echo "██║   ██║██╔████╔██║█████╗  ██║  ███╗███████║     ██║   ██║███████╗"
    echo "██║   ██║██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██║     ██║   ██║╚════██║"
    echo "╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝██║  ██║     ╚██████╔╝███████║"
    echo " ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚═════╝╚══════╝"
    echo -e "${NC}"
    echo "  OMEGA-OS v2.0.0 — AI-Powered OSINT & Recon System"
    echo ""
}

build() {
    banner
    echo -e "${GREEN}[*] Building Omega-OS v2.0.0...${NC}"
    echo "[*] Omega-CLI source:       ${OMEGA_CLI_SRC}"
    echo "[*] Omega-MCP-Server source: ${OMEGA_MCP_SRC}"
    echo "[*] Image name: ${IMAGE_NAME}"
    echo ""

    # Copy sources into build context
    rm -rf omega-cli-build omega-mcp-server-build
    cp -r "${OMEGA_CLI_SRC}" omega-cli-build
    cp -r "${OMEGA_MCP_SRC}" omega-mcp-server-build

    docker build \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        -t "${IMAGE_NAME}" \
        -f Dockerfile \
        --build-context omega-cli=omega-cli-build \
        --build-context omega-mcp-server=omega-mcp-server-build \
        . 2>&1

    rm -rf omega-cli-build omega-mcp-server-build

    echo ""
    echo -e "${GREEN}[✓] Omega-OS v2.0.0 built successfully!${NC}"
    echo "[*] Image size: $(docker image inspect ${IMAGE_NAME} --format='{{.Size}}' | numfmt --to=iec 2>/dev/null || docker images ${IMAGE_NAME} --format '{{.Size}}')"
    echo ""
    echo "Run with:  docker run -it --rm -v ~/omega-reports:/reports ${IMAGE_NAME}"
    echo "MCP mode:  ./build.sh mcp"
}

run() {
    banner
    mkdir -p "${REPORTS_DIR}"
    echo -e "${GREEN}[*] Launching Omega-OS v2.0.0...${NC}"
    echo "[*] Reports will be saved to: ${REPORTS_DIR}"
    echo ""
    docker run -it --rm \
        --name "${CONTAINER_NAME}" \
        --hostname omega-os \
        -v "${REPORTS_DIR}:/reports" \
        -v "${HOME}/.config/omega-cli:/root/.config/omega-cli" \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        "${IMAGE_NAME}"
}

mcp() {
    echo -e "${GREEN}[*] Starting Omega MCP server (stdio mode)...${NC}"
    docker run -i --rm \
        --name "${CONTAINER_NAME}-mcp" \
        --hostname omega-os \
        -v "${HOME}/.config/omega-cli:/root/.config/omega-cli" \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        "${IMAGE_NAME}" \
        omega-mcp
}

save_usb() {
    banner
    if [ -z "${1:-}" ]; then
        echo -e "${RED}[!] Usage: ./build.sh save-usb /path/to/usb${NC}"
        echo "    Example: ./build.sh save-usb /media/mypassport"
        exit 1
    fi
    USB_PATH="$1"
    echo -e "${GREEN}[*] Saving Omega-OS image to USB: ${USB_PATH}${NC}"
    docker save "${IMAGE_NAME}" | gzip > "${USB_PATH}/omega-os.tar.gz"
    cp "$0" "${USB_PATH}/omega-os.sh"
    chmod +x "${USB_PATH}/omega-os.sh"
    cat > "${USB_PATH}/README.md" << 'USBREADME'
# Omega-OS v2.0 — AI-Powered Portable OSINT System

## Load from USB:
```bash
docker load < omega-os.tar.gz
./omega-os.sh run
```

## Requirements:
- Docker installed on host machine
- That's it!
USBREADME
    echo -e "${GREEN}[✓] Saved! Plug USB into any machine with Docker and run:${NC}"
    echo "    docker load < ${USB_PATH}/omega-os.tar.gz"
    echo "    ${USB_PATH}/omega-os.sh run"
}

case "${1:-build}" in
    build)    build ;;
    run)      run ;;
    shell)    run ;;
    mcp)      mcp ;;
    save-usb) save_usb "${2:-}" ;;
    *)
        echo "Usage: $0 {build|run|shell|mcp|save-usb /path}"
        exit 1
        ;;
esac
