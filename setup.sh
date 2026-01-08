#!/bin/bash
#
# DHCP Debugging Toolkit Setup Script
# Installs all required dependencies for DHCP packet analysis
#

set -e  # Exit on error

echo "================================================================================"
echo "  DHCP Debugging Toolkit - Setup"
echo "================================================================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running with sudo
if [ "$EUID" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS. /etc/os-release not found.${NC}"
    echo "Please install dependencies manually."
    exit 1
fi

echo "Detected OS: $OS $OS_VERSION"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a Python package is installed
python_package_exists() {
    python3 -c "import $1" >/dev/null 2>&1
}

echo "================================================================================"
echo "  Checking System Requirements"
echo "================================================================================"
echo ""

# Check Python 3
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Python 3 found: $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} Python 3 not found"
    echo "Please install Python 3.6 or later"
    exit 1
fi

# Check tcpdump
if command_exists tcpdump; then
    echo -e "${GREEN}✓${NC} tcpdump found"
else
    echo -e "${YELLOW}!${NC} tcpdump not found (optional, recommended for packet capture)"
fi

# Check tshark
if command_exists tshark; then
    echo -e "${GREEN}✓${NC} tshark found"
else
    echo -e "${YELLOW}!${NC} tshark not found (optional, useful for advanced filtering)"
fi

echo ""
echo "================================================================================"
echo "  Installing Python Dependencies"
echo "================================================================================"
echo ""

# Install scapy for packet analysis
if python_package_exists scapy; then
    echo -e "${GREEN}✓${NC} scapy already installed"
else
    echo "Installing scapy..."

    # Try system package manager first (preferred for system Python)
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        echo "Using apt package manager..."
        $SUDO apt-get update -qq
        $SUDO apt-get install -y python3-scapy
    elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
        echo "Using dnf/yum package manager..."
        $SUDO dnf install -y python3-scapy || $SUDO yum install -y python3-scapy
    elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
        echo "Using pacman package manager..."
        $SUDO pacman -S --noconfirm python-scapy
    else
        # Fall back to pip if OS not recognized
        echo "Using pip..."
        python3 -m pip install --user scapy
    fi

    if python_package_exists scapy; then
        echo -e "${GREEN}✓${NC} scapy installed successfully"
    else
        echo -e "${RED}✗${NC} Failed to install scapy"
        echo "Please install manually with: pip3 install scapy"
        exit 1
    fi
fi

# Install tftpy for TFTP receiver (optional)
if python_package_exists tftpy; then
    echo -e "${GREEN}✓${NC} tftpy already installed"
else
    echo "tftpy not installed (optional, needed for tftp_receiver.py)"
    read -p "Install tftpy now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Installing tftpy..."
        python3 -m pip install --user tftpy
        if python_package_exists tftpy; then
            echo -e "${GREEN}✓${NC} tftpy installed successfully"
        else
            echo -e "${YELLOW}!${NC} Failed to install tftpy (you can install it later with: pip3 install tftpy)"
        fi
    fi
fi

echo ""
echo "================================================================================"
echo "  Making Scripts Executable"
echo "================================================================================"
echo ""

# Make all Python scripts executable
chmod +x dhcp_interactive.py 2>/dev/null && echo -e "${GREEN}✓${NC} dhcp_interactive.py" || echo -e "${YELLOW}!${NC} dhcp_interactive.py not found"
chmod +x dhcp_analyzer.py 2>/dev/null && echo -e "${GREEN}✓${NC} dhcp_analyzer.py" || echo -e "${YELLOW}!${NC} dhcp_analyzer.py not found"
chmod +x tplink_log_analyzer.py 2>/dev/null && echo -e "${GREEN}✓${NC} tplink_log_analyzer.py" || echo -e "${YELLOW}!${NC} tplink_log_analyzer.py not found"
chmod +x tftp_receiver.py 2>/dev/null && echo -e "${GREEN}✓${NC} tftp_receiver.py" || echo -e "${YELLOW}!${NC} tftp_receiver.py not found"
chmod +x identify_icmp_dhcp.py 2>/dev/null && echo -e "${GREEN}✓${NC} identify_icmp_dhcp.py" || echo -e "${YELLOW}!${NC} identify_icmp_dhcp.py not found"

echo ""
echo "================================================================================"
echo "  Optional Tools"
echo "================================================================================"
echo ""

echo "The following tools are optional but recommended:"
echo ""
echo "1. tcpdump - For capturing DHCP traffic"
echo "   Install: sudo apt-get install tcpdump"
echo ""
echo "2. tshark (Wireshark CLI) - For advanced packet filtering"
echo "   Install: sudo apt-get install tshark"
echo ""
echo "3. Wireshark - For GUI packet analysis"
echo "   Install: sudo apt-get install wireshark"
echo ""

if ! command_exists tcpdump; then
    read -p "Install tcpdump now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
            $SUDO apt-get install -y tcpdump
        elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
            $SUDO dnf install -y tcpdump || $SUDO yum install -y tcpdump
        elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
            $SUDO pacman -S --noconfirm tcpdump
        fi
    fi
fi

if ! command_exists tshark; then
    read -p "Install tshark now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
            $SUDO apt-get install -y tshark
        elif [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "centos" ]; then
            $SUDO dnf install -y wireshark-cli || $SUDO yum install -y wireshark
        elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
            $SUDO pacman -S --noconfirm wireshark-cli
        fi
    fi
fi

echo ""
echo "================================================================================"
echo "  Setup Complete!"
echo "================================================================================"
echo ""
echo -e "${GREEN}All required dependencies are installed.${NC}"
echo ""
echo "Quick start:"
echo ""
echo "  1. Get logs from HB810 router:"
echo "     sudo ./tftp_receiver.py"
echo "     (Then export logs from router web interface)"
echo ""
echo "  2. Capture DHCP traffic:"
echo "     sudo tcpdump -i eth0 -w capture.pcap port 67 or port 68"
echo ""
echo "  3. Analyze with interactive tool (RECOMMENDED):"
echo "     ./dhcp_interactive.py capture.pcap"
echo ""
echo "  4. Or use batch analyzer:"
echo "     ./dhcp_analyzer.py capture.pcap"
echo ""
echo "  5. For TPLink router logs:"
echo "     ./tplink_log_analyzer.py router.log"
echo ""
echo "For more information, see README.md"
echo ""
