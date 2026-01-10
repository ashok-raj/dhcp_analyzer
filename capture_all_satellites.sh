#!/bin/bash
#
# Multi-Satellite DHCP Capture Orchestrator
# Captures DHCP traffic from main router + 6 satellites simultaneously
# Usage: sudo ./capture_all_satellites.sh [duration_in_seconds] [--stagger N | --sequential]
#

set -e

# Configuration
PASSWORD="Password1"
TFTP_SERVER="192.168.88.32"
DEFAULT_DURATION=900  # 15 minutes
STAGGER_DELAY=0      # Seconds between each TFTP transfer
CONFIG_FILE="satellites.conf"

# Show usage
show_usage() {
    echo "Usage: sudo $0 [duration] [--stagger N | --sequential | --scan | --dry-run]"
    echo ""
    echo "Options:"
    echo "  duration        Capture duration in seconds (default: 900 = 15 minutes)"
    echo "  --stagger N     Stagger TFTP transfers by N seconds between each device"
    echo "  --sequential    Sequential TFTP transfers (equivalent to --stagger 15)"
    echo "  --scan          Discover satellites and create configuration file"
    echo "  --dry-run       Test configuration file parsing without capturing"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --scan             # Discover satellites and save to config"
    echo "  sudo $0 --dry-run          # Test config file parsing"
    echo "  sudo $0                    # 15 minute capture using saved config"
    echo "  sudo $0 300                # 5 minute capture, all TFTP at once"
    echo "  sudo $0 900 --stagger 10   # 15 min capture, 10s delay between TFTPs"
    echo "  sudo $0 900 --sequential   # 15 min capture, 15s delay between TFTPs"
    echo ""
    echo "Configuration:"
    echo "  Devices are loaded from satellites.conf if it exists."
    echo "  Run with --scan to auto-discover and create the configuration file."
    echo ""
    exit 1
}

# Parse arguments
DURATION=$DEFAULT_DURATION
RUN_SCAN=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            ;;
        --scan)
            RUN_SCAN=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --stagger)
            if [[ -z "$2" ]] || [[ "$2" =~ ^- ]]; then
                echo "Error: --stagger requires a numeric argument"
                show_usage
            fi
            STAGGER_DELAY=$2
            shift 2
            ;;
        --sequential)
            STAGGER_DELAY=15
            shift
            ;;
        [0-9]*)
            DURATION=$1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# If --scan option is specified, run discovery and exit
if [ "$RUN_SCAN" = true ]; then
    if [ ! -f "scan_satellites.sh" ]; then
        echo -e "${RED}ERROR: scan_satellites.sh not found${NC}"
        exit 1
    fi
    chmod +x scan_satellites.sh
    ./scan_satellites.sh
    exit 0
fi

# Load devices from config file or use defaults
declare -a DEVICES=()
declare -a UNREACHABLE_DEVICES=()

if [ -f "$CONFIG_FILE" ]; then
    echo -e "${BLUE}Loading devices from $CONFIG_FILE...${NC}"

    # Read devices from config file (skip comments and empty lines)
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip comments and empty lines
        if [[ "$line" =~ ^#.*$ ]] || [[ -z "$line" ]]; then
            continue
        fi

        # Parse IP:Name format (strip any comments after #)
        if [[ "$line" =~ ^([0-9.]+):(.+)$ ]]; then
            ip="${BASH_REMATCH[1]}"
            name_with_comment="${BASH_REMATCH[2]}"

            # Remove comment (everything after #) and trim whitespace
            name="${name_with_comment%%#*}"
            name="${name//[[:space:]]/}"  # Remove all whitespace

            # Quick ping check (1 second timeout)
            if ping -c 1 -W 1 "$ip" &> /dev/null; then
                DEVICES+=("$ip:$name")
                echo -e "  ${GREEN}✓${NC} $name ($ip) - reachable"
            else
                UNREACHABLE_DEVICES+=("$ip:$name")
                echo -e "  ${RED}✗${NC} $name ($ip) - unreachable"
            fi
        fi
    done < "$CONFIG_FILE"

    echo ""

    if [ ${#DEVICES[@]} -eq 0 ]; then
        echo -e "${RED}ERROR: No reachable devices found in $CONFIG_FILE${NC}"
        echo ""
        echo "Options:"
        echo "  1. Check that devices are powered on"
        echo "  2. Run: sudo $0 --scan   (to re-discover devices)"
        exit 1
    fi

    if [ ${#UNREACHABLE_DEVICES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: ${#UNREACHABLE_DEVICES[@]} device(s) unreachable and will be skipped${NC}"
        echo ""
    fi

    echo -e "${GREEN}Loaded ${#DEVICES[@]} device(s) from configuration${NC}"
    echo ""
else
    echo -e "${YELLOW}No configuration file found: $CONFIG_FILE${NC}"
    echo ""
    echo -e "${YELLOW}Using default device list...${NC}"
    echo ""

    # Default device list (fallback)
    declare -a DEFAULT_DEVICES=(
        "192.168.88.1:main_router"
        "192.168.88.27:satellite_27"
        "192.168.88.58:satellite_58"
        "192.168.88.59:satellite_59"
        "192.168.88.79:satellite_79"
        "192.168.88.80:satellite_80"
        "192.168.88.87:satellite_87"
    )

    # Validate default devices
    for device in "${DEFAULT_DEVICES[@]}"; do
        IFS=':' read -r ip name <<< "$device"
        if ping -c 1 -W 1 "$ip" &> /dev/null; then
            DEVICES+=("$device")
            echo -e "  ${GREEN}✓${NC} $name ($ip) - reachable"
        else
            UNREACHABLE_DEVICES+=("$device")
            echo -e "  ${RED}✗${NC} $name ($ip) - unreachable"
        fi
    done

    echo ""

    if [ ${#DEVICES[@]} -eq 0 ]; then
        echo -e "${RED}ERROR: No reachable devices found${NC}"
        echo ""
        echo "Options:"
        echo "  1. Check that devices are powered on"
        echo "  2. Run: sudo $0 --scan   (to auto-discover devices)"
        exit 1
    fi

    if [ ${#UNREACHABLE_DEVICES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: ${#UNREACHABLE_DEVICES[@]} device(s) unreachable and will be skipped${NC}"
        echo ""
    fi

    echo -e "${YELLOW}Tip: Run 'sudo $0 --scan' to auto-discover and save devices${NC}"
    echo ""
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Dry-run mode - show what would be captured and exit
if [ "$DRY_RUN" = true ]; then
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}DRY RUN - Configuration Test${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
    echo -e "Configuration file: ${GREEN}${CONFIG_FILE}${NC}"
    echo -e "Reachable devices: ${GREEN}${#DEVICES[@]}${NC}"
    echo -e "Unreachable devices: ${RED}${#UNREACHABLE_DEVICES[@]}${NC}"
    echo ""
    echo -e "${YELLOW}Devices that would be captured:${NC}"
    echo ""

    for device in "${DEVICES[@]}"; do
        IFS=':' read -r ip name <<< "$device"
        echo -e "  ${GREEN}✓${NC} ${name}"
        echo -e "      IP Address: ${ip}"

        # Try to extract MAC from config file if it exists
        if [ -f "$CONFIG_FILE" ]; then
            mac=$(grep "^${ip}:" "$CONFIG_FILE" | sed -n 's/.*# MAC: \([0-9a-fA-F:]*\).*/\1/p')
            if [ -n "$mac" ]; then
                echo -e "      MAC Address: ${mac}"
            fi
        fi

        echo -e "      Capture file: dhcp_${name}_TIMESTAMP.pcap"
        echo ""
    done

    if [ ${#UNREACHABLE_DEVICES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Unreachable devices (would be skipped):${NC}"
        echo ""
        for device in "${UNREACHABLE_DEVICES[@]}"; do
            IFS=':' read -r ip name <<< "$device"
            echo -e "  ${RED}✗${NC} ${name} (${ip})"
        done
        echo ""
    fi

    echo -e "${BLUE}============================================${NC}"
    echo -e "${GREEN}Configuration parsing successful!${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
    echo "To run actual capture:"
    echo -e "  ${BLUE}sudo $0 [duration]${NC}"
    echo ""
    exit 0
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (for TFTP receiver on port 69)${NC}"
    echo "Usage: sudo $0 [duration_in_seconds]"
    exit 1
fi

# Check for required scripts
if [ ! -f "tplink_multi_capture.exp" ]; then
    echo -e "${RED}ERROR: tplink_multi_capture.exp not found${NC}"
    exit 1
fi

if [ ! -f "tftp_receiver.py" ]; then
    echo -e "${RED}ERROR: tftp_receiver.py not found${NC}"
    exit 1
fi

# Make expect script executable
chmod +x tplink_multi_capture.exp

# Create timestamp for this capture session
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SESSION_DIR="capture_session_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}Multi-Satellite DHCP Capture${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Session directory: ${GREEN}${SESSION_DIR}${NC}"
echo -e "Capture duration: ${GREEN}${DURATION}s${NC} ($(($DURATION / 60))m)"
echo -e "Devices to capture: ${GREEN}${#DEVICES[@]}${NC}"
echo -e "TFTP server: ${GREEN}${TFTP_SERVER}${NC}"

if [ "$STAGGER_DELAY" -gt 0 ]; then
    echo -e "TFTP transfer mode: ${YELLOW}Staggered (${STAGGER_DELAY}s delay between devices)${NC}"
    total_transfer_time=$((STAGGER_DELAY * (${#DEVICES[@]} - 1)))
    echo -e "Estimated transfer time: ${YELLOW}~${total_transfer_time}s${NC}"
else
    echo -e "TFTP transfer mode: ${YELLOW}Simultaneous (all at once)${NC}"
fi

echo ""
echo -e "${YELLOW}Press Ctrl+C at any time to stop all captures early${NC}"
echo -e "${BLUE}============================================${NC}\n"

# Array to store background PIDs
declare -a PIDS=()
TFTP_PID=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Received interrupt signal - stopping all captures...${NC}"

    # Kill all capture processes
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping capture process $pid..."
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Wait for capture processes to finish
    echo "Waiting for captures to finish transferring..."
    for pid in "${PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Stop TFTP server
    if [ -n "$TFTP_PID" ] && kill -0 "$TFTP_PID" 2>/dev/null; then
        echo "Stopping TFTP receiver..."
        kill -TERM "$TFTP_PID" 2>/dev/null || true
        wait "$TFTP_PID" 2>/dev/null || true
    fi

    echo -e "${GREEN}All captures stopped.${NC}"
    show_summary
    exit 0
}

# Show summary function
show_summary() {
    echo -e "\n${BLUE}============================================${NC}"
    echo -e "${BLUE}Capture Session Summary${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo -e "Session directory: ${GREEN}${SESSION_DIR}${NC}"
    echo ""
    echo "Captured files:"

    count=0
    for device in "${DEVICES[@]}"; do
        IFS=':' read -r ip name <<< "$device"
        pcap_file="${SESSION_DIR}/dhcp_${name}_${TIMESTAMP}.pcap"
        if [ -f "$pcap_file" ]; then
            size=$(du -h "$pcap_file" | cut -f1)
            echo -e "  ${GREEN}✓${NC} $name ($ip): $size"
            ((count++))
        else
            echo -e "  ${RED}✗${NC} $name ($ip): File not found"
        fi
    done

    echo ""
    echo -e "Successfully captured: ${GREEN}${count}/${#DEVICES[@]}${NC} devices"

    # Show log files
    echo ""
    echo "Log files:"
    ls -1 capture_*_${TIMESTAMP}.log 2>/dev/null | while read log; do
        echo "  - $log"
    done

    echo -e "${BLUE}============================================${NC}"
}

# Trap Ctrl+C and other termination signals
trap cleanup SIGINT SIGTERM

# Start TFTP receiver
echo -e "${YELLOW}Starting TFTP receiver...${NC}"
cd "$SESSION_DIR"
python3 ../tftp_receiver.py > tftp_receiver.log 2>&1 &
TFTP_PID=$!
cd ..
sleep 2

# Verify TFTP receiver started
if ! kill -0 "$TFTP_PID" 2>/dev/null; then
    echo -e "${RED}ERROR: TFTP receiver failed to start${NC}"
    echo "Check tftp_receiver.log for details"
    exit 1
fi
echo -e "${GREEN}✓ TFTP receiver started (PID: $TFTP_PID)${NC}\n"

# Launch capture on each device
echo -e "${YELLOW}Launching captures on all devices...${NC}\n"

device_index=0
for device in "${DEVICES[@]}"; do
    IFS=':' read -r ip name <<< "$device"

    # Unique capture filename for this device
    capture_file="dhcp_${name}_${TIMESTAMP}.pcap"

    # Calculate TFTP delay for this device (staggered mode)
    tftp_delay=$((device_index * STAGGER_DELAY))

    echo -e "${BLUE}Starting capture on $name ($ip)${NC}"
    if [ "$STAGGER_DELAY" -gt 0 ] && [ $device_index -gt 0 ]; then
        echo -e "  TFTP delay: ${YELLOW}${tftp_delay}s${NC}"
    fi

    # Launch expect script in background
    ./tplink_multi_capture.exp "$ip" "$PASSWORD" "$name" "$DURATION" "$capture_file" "$tftp_delay" &

    pid=$!
    PIDS+=("$pid")
    echo -e "  Process ID: $pid"

    # Small delay between launches to avoid overwhelming the network
    sleep 1
    ((device_index++))
done

echo -e "\n${GREEN}All captures launched successfully!${NC}"
echo -e "${YELLOW}Monitoring progress... (Press Ctrl+C to stop early)${NC}\n"

# Wait for all capture processes to complete
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# Stop TFTP server
if [ -n "$TFTP_PID" ] && kill -0 "$TFTP_PID" 2>/dev/null; then
    echo -e "\n${YELLOW}Stopping TFTP receiver...${NC}"
    kill -TERM "$TFTP_PID" 2>/dev/null || true
    wait "$TFTP_PID" 2>/dev/null || true
fi

echo -e "\n${GREEN}All captures completed successfully!${NC}"
show_summary
