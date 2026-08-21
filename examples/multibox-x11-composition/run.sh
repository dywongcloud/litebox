#!/bin/bash
# Multi-box X11 composition launcher

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $0 {server|client|setup|cleanup}"
    echo ""
    echo "Commands:"
    echo "  setup    - Create TUN devices (requires root)"
    echo "  cleanup  - Remove TUN devices (requires root)"
    echo "  server   - Start X11 server box"
    echo "  client   - Start X11 client box"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}✗ This command requires root${NC}"
        exit 1
    fi
}

setup_tun_devices() {
    echo -e "${YELLOW}Setting up TUN devices${NC}"

    # Check if tun-setup.sh is available
    if ! command -v tun-setup.sh &> /dev/null; then
        echo -e "${RED}✗ tun-setup.sh not found in PATH${NC}"
        echo "Make sure boxer is properly installed with tun-setup.sh available"
        exit 1
    fi

    # Create server TUN device
    echo "Creating TUN device tun98 with gateway 10.0.1.1..."
    tun-setup.sh -t tun98 -i 10.0.1.1 || {
        echo -e "${YELLOW}Note: tun98 may already exist${NC}"
    }

    # Create client TUN device
    echo "Creating TUN device tun99 with gateway 10.0.2.1..."
    tun-setup.sh -t tun99 -i 10.0.2.1 || {
        echo -e "${YELLOW}Note: tun99 may already exist${NC}"
    }

    echo -e "${GREEN}✓ TUN devices ready${NC}"
    echo ""
    echo "Devices:"
    ip link show tun98 tun99 2>/dev/null || true
    echo ""
    echo "Addresses:"
    ip addr show tun98 tun99 2>/dev/null || true
}

cleanup_tun_devices() {
    echo -e "${YELLOW}Cleaning up TUN devices${NC}"

    # Device cleanup is typically handled by the system
    # But we can document the commands here
    echo "To manually remove TUN devices, run:"
    echo "  sudo ip link del tun98"
    echo "  sudo ip link del tun99"
}

build_images() {
    echo -e "${YELLOW}Building Docker images${NC}"

    if ! command -v docker &> /dev/null; then
        echo -e "${RED}✗ Docker not found in PATH${NC}"
        exit 1
    fi

    cd "$SCRIPT_DIR"
    docker build -f Dockerfile.x11-server -t multibox-x11-server . || {
        echo -e "${RED}✗ Failed to build server image${NC}"
        exit 1
    }

    docker build -f Dockerfile.x11-client -t multibox-x11-client . || {
        echo -e "${RED}✗ Failed to build client image${NC}"
        exit 1
    }

    echo -e "${GREEN}✓ Images built${NC}"
}

run_server() {
    echo -e "${YELLOW}Starting X11 server box${NC}"
    echo "Server will listen on display :0 (TCP port 6000)"
    echo "Press Ctrl+C to stop"
    echo ""

    if ! command -v boxer &> /dev/null; then
        echo -e "${RED}✗ boxer not found in PATH${NC}"
        exit 1
    fi

    build_images

    sudo boxer \
        --net tun98 \
        --net-guest-ip 10.0.1.2 \
        --net-host-ip 10.0.1.1 \
        docker run \
            --rm \
            multibox-x11-server
}

run_client() {
    echo -e "${YELLOW}Starting X11 client box${NC}"
    echo "Client will connect to server at 10.0.1.2:0"
    echo "Press Ctrl+C to stop"
    echo ""

    if ! command -v boxer &> /dev/null; then
        echo -e "${RED}✗ boxer not found in PATH${NC}"
        exit 1
    fi

    build_images

    sudo boxer \
        --net tun99 \
        --net-guest-ip 10.0.2.2 \
        --net-host-ip 10.0.2.1 \
        docker run \
            --rm \
            -e DISPLAY=10.0.1.2:0 \
            multibox-x11-client
}

if [[ $# -eq 0 ]]; then
    usage
fi

case "$1" in
    setup)
        check_root
        setup_tun_devices
        ;;
    cleanup)
        check_root
        cleanup_tun_devices
        ;;
    server)
        run_server
        ;;
    client)
        run_client
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        usage
        ;;
esac
