#!/usr/bin/env python3
"""
TP-Link Satellite Discovery Tool
Scans network for TP-Link HB610V2 satellites and HB810 routers
"""

import subprocess
import re
import sys
import os
import asyncio
from dataclasses import dataclass
from typing import List, Optional, Set
from datetime import datetime
import socket


# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


@dataclass
class TPLinkDevice:
    """Represents a discovered TP-Link device"""
    ip: str
    mac: str
    device_type: str = "unknown"

    # TP-Link MAC prefixes
    MAC_PREFIXES = {
        '78:20:51': 'HB610V2',  # Satellite
        '50:3d:d1': 'HB810',    # Router
    }

    def __post_init__(self):
        """Identify device type based on MAC prefix"""
        if self.device_type == "unknown":
            mac_prefix = ':'.join(self.mac.split(':')[:3]).lower()
            self.device_type = self.MAC_PREFIXES.get(mac_prefix, "unknown")

            # Special case for main router
            if self.ip == "192.168.88.1":
                self.device_type = "HB810"

    @classmethod
    def is_tplink_mac(cls, mac: str) -> bool:
        """Check if MAC address belongs to TP-Link"""
        mac_prefix = ':'.join(mac.split(':')[:3]).lower()
        return mac_prefix in cls.MAC_PREFIXES

    def get_device_name(self) -> str:
        """Generate device name based on IP and type"""
        last_octet = self.ip.split('.')[-1]

        if self.device_type == "HB810" or self.ip == "192.168.88.1":
            return "main_router"
        elif self.device_type == "HB610V2":
            return f"satellite_{last_octet}"
        else:
            return f"device_{last_octet}"

    def __hash__(self):
        return hash((self.ip, self.mac))

    def __eq__(self, other):
        if not isinstance(other, TPLinkDevice):
            return False
        return self.ip == other.ip and self.mac == other.mac


class DeviceDiscovery:
    """Handles device discovery using various methods"""

    def __init__(self, network: str = "192.168.88.0/24"):
        self.network = network
        self.devices: Set[TPLinkDevice] = set()

    def is_root(self) -> bool:
        """Check if running as root"""
        return os.geteuid() == 0

    def command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run(['which', command],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    async def discover_with_arp_scan(self) -> int:
        """Discover devices using arp-scan (requires root)"""
        if not self.is_root():
            return 0

        if not self.command_exists('arp-scan'):
            return 0

        print(f"{Colors.YELLOW}Using arp-scan for discovery...{Colors.NC}")

        try:
            # Try with interface first, fallback to without
            try:
                result = subprocess.run(['arp-scan', '--interface=eth0', '--localnet'],
                                      capture_output=True, text=True, timeout=10)
            except:
                result = subprocess.run(['arp-scan', '--localnet'],
                                      capture_output=True, text=True, timeout=10)

            count = 0
            for line in result.stdout.split('\n'):
                # Parse arp-scan output: IP\tMAC\tVendor
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1].lower()

                    # Validate IP format
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                        continue

                    # Check if it's a TP-Link device
                    if TPLinkDevice.is_tplink_mac(mac):
                        device = TPLinkDevice(ip=ip, mac=mac)
                        if device not in self.devices:
                            self.devices.add(device)
                            print(f"  {Colors.GREEN}✓{Colors.NC} Found: {ip} (MAC: {mac}) - {device.device_type}")
                            count += 1

            return count

        except Exception as e:
            print(f"{Colors.YELLOW}arp-scan failed: {e}{Colors.NC}")
            return 0

    async def discover_with_nmap(self) -> int:
        """Discover devices using nmap"""
        if not self.command_exists('nmap'):
            return 0

        print(f"{Colors.YELLOW}Using nmap for discovery...{Colors.NC}")

        try:
            # First, do a ping scan to find live hosts
            result = subprocess.run(['nmap', '-sn', self.network],
                                  capture_output=True, text=True, timeout=30)

            count = 0
            current_ip = None

            for line in result.stdout.split('\n'):
                # Look for IP addresses
                if 'Nmap scan report for' in line:
                    # Extract IP (could be at end in parentheses or just the address)
                    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if ip_match:
                        current_ip = ip_match.group(1)

                # Look for MAC address
                elif 'MAC Address:' in line and current_ip:
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac_match:
                        mac = mac_match.group(0).lower().replace('-', ':')

                        # Check if it's a TP-Link device
                        if TPLinkDevice.is_tplink_mac(mac):
                            device = TPLinkDevice(ip=current_ip, mac=mac)
                            if device not in self.devices:
                                self.devices.add(device)
                                print(f"  {Colors.GREEN}✓{Colors.NC} Found: {current_ip} (MAC: {mac}) - {device.device_type}")
                                count += 1

                    current_ip = None

            return count

        except Exception as e:
            print(f"{Colors.YELLOW}nmap failed: {e}{Colors.NC}")
            return 0

    async def ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            result = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await result.wait()
            return result.returncode == 0
        except:
            return False

    async def discover_with_ping_sweep(self) -> int:
        """Discover devices using ping sweep + ARP table"""
        print(f"{Colors.YELLOW}Using ping sweep + ARP table...{Colors.NC}")
        print(f"{Colors.YELLOW}(Install arp-scan or nmap for better results){Colors.NC}")
        print()

        # Extract network prefix (assuming /24)
        prefix = '.'.join(self.network.split('.')[:3])

        # Ping sweep all IPs in parallel
        print("Pinging hosts", end='', flush=True)
        tasks = []
        for i in range(1, 255):
            ip = f"{prefix}.{i}"
            tasks.append(self.ping_host(ip))

        # Run pings in batches to avoid overwhelming the system
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch)
            print('.', end='', flush=True)

        print()
        print()

        # Now check ARP table
        count = 0
        try:
            # Try 'ip neigh' first (modern), fallback to 'arp'
            try:
                result = subprocess.run(['ip', 'neigh'],
                                      capture_output=True, text=True, timeout=5)
            except:
                result = subprocess.run(['arp', '-n'],
                                      capture_output=True, text=True, timeout=5)

            for line in result.stdout.split('\n'):
                # Parse ARP/neighbor table
                parts = line.split()
                if len(parts) >= 3:
                    # ip neigh format: IP dev IFACE lladdr MAC
                    # arp format: IP type hwaddr MAC
                    ip = parts[0]

                    # Find MAC address in the line
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if not mac_match:
                        continue

                    mac = mac_match.group(0).lower().replace('-', ':')

                    # Validate IP format
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                        continue

                    # Check if it's a TP-Link device
                    if TPLinkDevice.is_tplink_mac(mac):
                        device = TPLinkDevice(ip=ip, mac=mac)
                        if device not in self.devices:
                            self.devices.add(device)
                            print(f"  {Colors.GREEN}✓{Colors.NC} Found: {ip} (MAC: {mac}) - {device.device_type}")
                            count += 1

            return count

        except Exception as e:
            print(f"{Colors.YELLOW}ARP table check failed: {e}{Colors.NC}")
            return 0

    async def discover_all(self) -> List[TPLinkDevice]:
        """Run all available discovery methods"""
        print(f"{Colors.BLUE}============================================{Colors.NC}")
        print(f"{Colors.BLUE}TP-Link Satellite Discovery{Colors.NC}")
        print(f"{Colors.BLUE}============================================{Colors.NC}")
        print()

        if not self.is_root():
            print(f"{Colors.YELLOW}Note: Running without root. Some discovery methods may not work.{Colors.NC}")
            print(f"{Colors.YELLOW}      For best results, run: sudo {sys.argv[0]}{Colors.NC}")
            print()

        print(f"Scanning network: {Colors.GREEN}{self.network}{Colors.NC}")
        print(f"Looking for TP-Link devices (MAC prefix: {', '.join(TPLinkDevice.MAC_PREFIXES.keys())})...")
        print()

        # Try methods in order of reliability
        if self.is_root() and self.command_exists('arp-scan'):
            await self.discover_with_arp_scan()
        elif self.command_exists('nmap'):
            await self.discover_with_nmap()
        else:
            await self.discover_with_ping_sweep()

        print()
        print(f"{Colors.BLUE}============================================{Colors.NC}")
        print(f"Discovery complete: Found {Colors.GREEN}{len(self.devices)}{Colors.NC} device(s)")
        print(f"{Colors.BLUE}============================================{Colors.NC}")
        print()

        return sorted(self.devices, key=lambda d: [int(x) for x in d.ip.split('.')])


def save_config(devices: List[TPLinkDevice], config_file: str = "satellites.conf"):
    """Save discovered devices to configuration file"""

    if not devices:
        print(f"{Colors.RED}No TP-Link devices found!{Colors.NC}")
        print()
        print("Troubleshooting:")
        print("  - Ensure devices are powered on and connected")
        print("  - Check that you're on the same network (192.168.88.0/24)")
        print("  - Try running with sudo for better discovery")
        print("  - Install arp-scan: sudo apt-get install arp-scan")
        return False

    # Display discovered devices
    print("Discovered devices:")
    print()

    device_map = {}
    for idx, device in enumerate(devices, 1):
        name = device.get_device_name()
        device_map[idx] = (device.ip, name)
        print(f"  {Colors.BLUE}[{idx}]{Colors.NC} {device.ip} - {name} (Type: {device.device_type}, MAC: {device.mac})")

    print()

    # Ask to save
    try:
        response = input(f"Save these devices to {config_file}? (y/n) ")
        if response.lower() not in ['y', 'yes']:
            print(f"{Colors.YELLOW}Configuration not saved.{Colors.NC}")
            print(f"You can manually create {config_file} with format:")
            print("  192.168.88.1:main_router")
            print("  192.168.88.27:satellite_27")
            print("  ...")
            return False
    except (KeyboardInterrupt, EOFError):
        print()
        print(f"{Colors.YELLOW}Configuration not saved.{Colors.NC}")
        return False

    # Create backup if file exists
    if os.path.exists(config_file):
        backup_file = f"{config_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        print(f"{Colors.YELLOW}Backing up existing config to: {backup_file}{Colors.NC}")
        try:
            with open(config_file, 'r') as src:
                with open(backup_file, 'w') as dst:
                    dst.write(src.read())
        except Exception as e:
            print(f"{Colors.RED}Warning: Could not create backup: {e}{Colors.NC}")

    # Write config file
    try:
        with open(config_file, 'w') as f:
            f.write("# TP-Link Satellite Configuration\n")
            f.write("# Format: IP:DeviceName\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#\n")

            for ip, name in device_map.values():
                f.write(f"{ip}:{name}\n")

        print(f"{Colors.GREEN}✓ Configuration saved to {config_file}{Colors.NC}")
        print()
        print("You can now run:")
        print(f"  {Colors.BLUE}sudo ./capture_all_satellites.sh{Colors.NC}")
        print()
        return True

    except Exception as e:
        print(f"{Colors.RED}Error saving configuration: {e}{Colors.NC}")
        return False


async def main():
    """Main entry point"""
    try:
        discovery = DeviceDiscovery(network="192.168.88.0/24")
        devices = await discovery.discover_all()
        save_config(devices)

        print()
        print(f"{Colors.BLUE}============================================{Colors.NC}")

    except KeyboardInterrupt:
        print()
        print(f"{Colors.YELLOW}Scan interrupted by user{Colors.NC}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.NC}")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
