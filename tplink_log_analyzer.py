#!/usr/bin/env python3
"""
TPLink Log Analyzer
Analyzes TPLink router log files for DHCP and Mesh events
"""

import re
import argparse
import json
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Optional
from pathlib import Path


class LogEntry:
    """Represents a single log entry"""
    def __init__(self, timestamp, level, component, message, raw_line):
        self.timestamp = timestamp
        self.level = level
        self.component = component
        self.message = message
        self.raw_line = raw_line

    def __repr__(self):
        return f"[{self.timestamp}] [{self.level}] {self.component}: {self.message}"


class TPLinkLogAnalyzer:
    """Analyzes TPLink router logs"""

    # Log line pattern: 2025-12-22 06:17:29 [5] Httpd: Clear log.
    LOG_PATTERN = re.compile(
        r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\d+)\]\s+([^:]+):\s+(.*)$'
    )

    # MAC address pattern
    MAC_PATTERN = re.compile(r'([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})')

    # IP address pattern
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def __init__(self, log_file, known_devices_file=None):
        self.log_file = log_file
        self.entries = []
        self.mesh_events = []
        self.dhcpd_events = []
        self.dhcpc_events = []
        self.errors = []
        self.known_devices = {}

        # Load known devices if file provided
        if known_devices_file:
            self.load_known_devices(known_devices_file)

    def parse_logs(self):
        """Parse the log file"""
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('BBA Platform'):
                    continue

                match = self.LOG_PATTERN.match(line)
                if match:
                    timestamp_str, level, component, message = match.groups()
                    try:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        timestamp = None

                    entry = LogEntry(timestamp, level, component, message, line)
                    self.entries.append(entry)

                    # Categorize by component
                    if component == 'Mesh':
                        self.mesh_events.append(entry)
                    elif component == 'DHCPD':
                        self.dhcpd_events.append(entry)
                    elif component == 'DHCPC':
                        self.dhcpc_events.append(entry)

                    # Track errors
                    if 'Fail' in message or 'fail' in message or 'Wrong' in message or 'NAK' in message:
                        self.errors.append(entry)

    def load_known_devices(self, known_devices_file):
        """Load known devices from JSON file"""
        try:
            with open(known_devices_file, 'r', encoding='utf-8') as f:
                self.known_devices = json.load(f)
            print(f"Loaded {len(self.known_devices)} known devices from {known_devices_file}")
        except FileNotFoundError:
            print(f"⚠ Warning: Known devices file not found: {known_devices_file}")
        except json.JSONDecodeError as e:
            print(f"⚠ Warning: Error parsing known devices file: {e}")

    def get_device_alias(self, mac: str) -> Optional[str]:
        """Get device alias for a MAC address"""
        mac = mac.upper()
        if mac in self.known_devices:
            return self.known_devices[mac].get('alias', None)
        return None

    def format_mac_with_alias(self, mac: str) -> str:
        """Format MAC address with alias if available"""
        alias = self.get_device_alias(mac)
        if alias:
            return f"{mac} ({alias})"
        return mac

    def analyze_mesh_events(self):
        """Analyze Mesh client events"""
        add_events = [e for e in self.mesh_events if 'Add Client' in e.message]
        del_events = [e for e in self.mesh_events if 'Del Client' in e.message]

        # Extract MAC addresses
        add_macs = []
        del_macs = []

        for event in add_events:
            mac_match = self.MAC_PATTERN.search(event.message)
            if mac_match:
                add_macs.append((event.timestamp, mac_match.group(1).upper()))

        for event in del_events:
            mac_match = self.MAC_PATTERN.search(event.message)
            if mac_match:
                del_macs.append((event.timestamp, mac_match.group(1).upper()))

        # Count events per MAC
        add_counter = Counter([mac for _, mac in add_macs])
        del_counter = Counter([mac for _, mac in del_macs])

        # Find clients with high churn (many add/del cycles)
        all_macs = set(add_counter.keys()) | set(del_counter.keys())
        churn_data = []
        for mac in all_macs:
            adds = add_counter.get(mac, 0)
            dels = del_counter.get(mac, 0)
            total = adds + dels
            churn_data.append((mac, adds, dels, total))

        churn_data.sort(key=lambda x: x[3], reverse=True)

        return {
            'total_add': len(add_events),
            'total_del': len(del_events),
            'unique_macs': len(all_macs),
            'add_counter': add_counter,
            'del_counter': del_counter,
            'churn_data': churn_data,
            'add_events': add_macs,
            'del_events': del_macs
        }

    def analyze_dhcp_server_events(self):
        """Analyze DHCP server (DHCPD) events"""
        discover = [e for e in self.dhcpd_events if 'DISCOVER' in e.message]
        offer = [e for e in self.dhcpd_events if 'OFFER' in e.message]
        request = [e for e in self.dhcpd_events if 'REQUEST' in e.message]
        ack = [e for e in self.dhcpd_events if 'ACK' in e.message and 'NAK' not in e.message]
        nak = [e for e in self.dhcpd_events if 'NAK' in e.message]
        release = [e for e in self.dhcpd_events if 'RELEASE' in e.message]

        # Track IP assignments
        ip_assignments = defaultdict(list)  # MAC -> [(timestamp, IP)]

        for event in offer + ack:
            mac_match = self.MAC_PATTERN.search(event.message)
            ip_match = self.IP_PATTERN.search(event.message)
            if mac_match and ip_match:
                mac = mac_match.group(1).upper()
                ip = ip_match.group(0)
                ip_assignments[mac].append((event.timestamp, ip, 'OFFER' if event in offer else 'ACK'))

        # NAK analysis
        nak_by_mac = defaultdict(list)
        for event in nak:
            mac_match = self.MAC_PATTERN.search(event.message)
            if mac_match:
                mac = mac_match.group(1).upper()
                nak_by_mac[mac].append(event)

        return {
            'discover_count': len(discover),
            'offer_count': len(offer),
            'request_count': len(request),
            'ack_count': len(ack),
            'nak_count': len(nak),
            'release_count': len(release),
            'ip_assignments': dict(ip_assignments),
            'nak_by_mac': dict(nak_by_mac),
            'discover_events': discover,
            'offer_events': offer,
            'nak_events': nak
        }

    def analyze_dhcp_client_events(self):
        """Analyze DHCP client (DHCPC) events - router's WAN interface"""
        wan_renewals = []
        wan_ips = []

        for event in self.dhcpc_events:
            if 'Recv ACK' in event.message:
                ip_matches = self.IP_PATTERN.findall(event.message)
                if len(ip_matches) >= 2:
                    server_ip = ip_matches[0]
                    assigned_ip = ip_matches[1]
                    wan_renewals.append((event.timestamp, server_ip, assigned_ip))
                    wan_ips.append(assigned_ip)

        return {
            'total_events': len(self.dhcpc_events),
            'wan_renewals': wan_renewals,
            'current_wan_ip': wan_ips[-1] if wan_ips else None
        }

    def find_frequent_dhcp_clients(self, threshold=5):
        """Find clients making many DHCP requests"""
        mac_requests = defaultdict(int)

        for event in self.dhcpd_events:
            if 'DISCOVER' in event.message or 'REQUEST' in event.message:
                mac_match = self.MAC_PATTERN.search(event.message)
                if mac_match:
                    mac_requests[mac_match.group(1).upper()] += 1

        # Filter by threshold
        frequent = [(mac, count) for mac, count in mac_requests.items() if count >= threshold]
        frequent.sort(key=lambda x: x[1], reverse=True)

        return frequent

    def get_time_range(self):
        """Get the time range of the logs"""
        if not self.entries:
            return None, None

        timestamps = [e.timestamp for e in self.entries if e.timestamp]
        if not timestamps:
            return None, None

        return min(timestamps), max(timestamps)

    def print_summary(self):
        """Print comprehensive summary"""
        print("=" * 80)
        print("TPLINK LOG ANALYSIS SUMMARY")
        print("=" * 80)
        print(f"Log file: {self.log_file}")

        start_time, end_time = self.get_time_range()
        if start_time and end_time:
            duration = end_time - start_time
            print(f"Time range: {start_time} to {end_time}")
            print(f"Duration: {duration}")

        print(f"\nTotal log entries: {len(self.entries)}")

        # Component breakdown
        component_counts = Counter([e.component for e in self.entries])
        print(f"\nEvents by component:")
        for component, count in component_counts.most_common():
            print(f"  {component:15s}: {count:5d}")

        print(f"\nTotal errors/warnings: {len(self.errors)}")

        # Mesh analysis
        print("\n" + "=" * 80)
        print("MESH CLIENT ANALYSIS")
        print("=" * 80)
        mesh_data = self.analyze_mesh_events()
        print(f"Total client additions: {mesh_data['total_add']}")
        print(f"Total client deletions: {mesh_data['total_del']}")
        print(f"Unique mesh clients: {mesh_data['unique_macs']}")

        print(f"\nTop 10 clients by activity (add + delete events):")
        print(f"{'MAC Address':<20} {'Adds':<8} {'Dels':<8} {'Total':<8} {'Status':<10} {'Device'}")
        print("-" * 100)
        for mac, adds, dels, total in mesh_data['churn_data'][:10]:
            status = "Stable" if abs(adds - dels) <= 1 else "Churning"
            alias = self.get_device_alias(mac) or ""
            print(f"{mac:<20} {adds:<8} {dels:<8} {total:<8} {status:<10} {alias}")

        # DHCP Server analysis
        print("\n" + "=" * 80)
        print("DHCP SERVER ANALYSIS")
        print("=" * 80)
        dhcp_data = self.analyze_dhcp_server_events()
        print(f"DISCOVER messages: {dhcp_data['discover_count']}")
        print(f"OFFER messages:    {dhcp_data['offer_count']}")
        print(f"REQUEST messages:  {dhcp_data['request_count']}")
        print(f"ACK messages:      {dhcp_data['ack_count']}")
        print(f"NAK messages:      {dhcp_data['nak_count']}")
        print(f"RELEASE messages:  {dhcp_data['release_count']}")

        if dhcp_data['discover_count'] > 0:
            success_rate = (dhcp_data['ack_count'] / dhcp_data['discover_count']) * 100
            print(f"\nDHCP Success Rate: {success_rate:.1f}% (ACKs / DISCOVERs)")

        if dhcp_data['nak_count'] > 0:
            print(f"\n⚠ WARNING: {dhcp_data['nak_count']} DHCP NAK(s) detected!")
            print("\nNAKs by client:")
            for mac, nak_events in dhcp_data['nak_by_mac'].items():
                alias = self.get_device_alias(mac)
                if alias:
                    print(f"  {mac} ({alias}): {len(nak_events)} NAK(s)")
                else:
                    print(f"  {mac}: {len(nak_events)} NAK(s)")

        # IP assignments
        if dhcp_data['ip_assignments']:
            print(f"\nIP Assignments (last per client):")
            print(f"{'MAC Address':<20} {'IP Address':<16} {'Type':<8} {'Timestamp':<20} {'Device'}")
            print("-" * 110)
            for mac, assignments in sorted(dhcp_data['ip_assignments'].items()):
                last_assignment = assignments[-1]
                timestamp, ip, msg_type = last_assignment
                alias = self.get_device_alias(mac) or ""
                print(f"{mac:<20} {ip:<16} {msg_type:<8} {str(timestamp):<20} {alias}")

        # Frequent DHCP clients
        frequent = self.find_frequent_dhcp_clients(threshold=5)
        if frequent:
            print(f"\n⚠ High DHCP activity clients (5+ requests):")
            print(f"{'MAC Address':<20} {'Request Count':<15} {'Device'}")
            print("-" * 70)
            for mac, count in frequent:
                alias = self.get_device_alias(mac) or ""
                print(f"{mac:<20} {count:<15} {alias}")

        # DHCP Client (WAN) analysis
        print("\n" + "=" * 80)
        print("DHCP CLIENT (WAN) ANALYSIS")
        print("=" * 80)
        wan_data = self.analyze_dhcp_client_events()
        print(f"Total WAN DHCP events: {wan_data['total_events']}")
        print(f"WAN IP renewals: {len(wan_data['wan_renewals'])}")
        if wan_data['current_wan_ip']:
            print(f"Current WAN IP: {wan_data['current_wan_ip']}")

        # Errors
        if self.errors:
            print("\n" + "=" * 80)
            print(f"ERRORS AND WARNINGS ({len(self.errors)} total)")
            print("=" * 80)
            error_types = Counter([e.message for e in self.errors])
            for error_msg, count in error_types.most_common(10):
                print(f"  [{count:3d}x] {error_msg[:70]}")

    def filter_by_mac(self, mac_filter):
        """Show all events for a specific MAC address"""
        mac_filter = mac_filter.upper()
        matching_events = []

        for entry in self.entries:
            mac_match = self.MAC_PATTERN.search(entry.message)
            if mac_match and mac_filter in mac_match.group(1).upper():
                matching_events.append(entry)

        return matching_events

    def print_mac_timeline(self, mac_filter):
        """Print timeline of events for a specific MAC"""
        events = self.filter_by_mac(mac_filter)

        if not events:
            print(f"No events found for MAC: {mac_filter}")
            return

        print("=" * 80)
        print(f"TIMELINE FOR MAC: {mac_filter}")
        alias = self.get_device_alias(mac_filter.upper())
        if alias:
            print(f"Device: {alias}")
        print("=" * 80)
        print(f"Total events: {len(events)}\n")

        for event in events:
            print(event)

    def detect_dhcp_storms(self, window_seconds=10, threshold=5):
        """Detect DHCP request storms"""
        storms = []

        for i, event in enumerate(self.dhcpd_events):
            if 'DISCOVER' not in event.message:
                continue

            mac_match = self.MAC_PATTERN.search(event.message)
            if not mac_match:
                continue

            mac = mac_match.group(1).upper()
            start_time = event.timestamp

            # Count requests from this MAC in the time window
            count = 1
            end_idx = i + 1

            while end_idx < len(self.dhcpd_events):
                next_event = self.dhcpd_events[end_idx]
                if not next_event.timestamp:
                    break

                time_diff = (next_event.timestamp - start_time).total_seconds()
                if time_diff > window_seconds:
                    break

                next_mac = self.MAC_PATTERN.search(next_event.message)
                if next_mac and next_mac.group(1).upper() == mac:
                    if 'DISCOVER' in next_event.message or 'REQUEST' in next_event.message:
                        count += 1

                end_idx += 1

            if count >= threshold:
                storms.append((start_time, mac, count, window_seconds))

        return storms


def main():
    parser = argparse.ArgumentParser(
        description='Analyze TPLink router log files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s log_tplink-12-31.txt
  %(prog)s log_tplink-12-31.txt --mac 44:67:55
  %(prog)s log_tplink-12-31.txt --storms
        """
    )

    parser.add_argument('log_file', help='TPLink log file to analyze')
    parser.add_argument('-m', '--mac', help='Filter events by MAC address (partial match)')
    parser.add_argument('-d', '--devices', help='Known devices JSON file (default: known_devices.json)',
                        default='known_devices.json')
    parser.add_argument('--storms', action='store_true', help='Detect DHCP storms')
    parser.add_argument('--storm-window', type=int, default=10, help='Storm detection window in seconds (default: 10)')
    parser.add_argument('--storm-threshold', type=int, default=5, help='Storm detection threshold (default: 5)')

    args = parser.parse_args()

    # Parse logs
    # Check if devices file exists before passing it
    devices_file = args.devices if Path(args.devices).exists() else None
    analyzer = TPLinkLogAnalyzer(args.log_file, known_devices_file=devices_file)
    print(f"Parsing log file: {args.log_file}...")
    analyzer.parse_logs()

    if args.mac:
        # MAC-specific timeline
        analyzer.print_mac_timeline(args.mac)
    else:
        # Full summary
        analyzer.print_summary()

    # Storm detection
    if args.storms:
        print("\n" + "=" * 80)
        print("DHCP STORM DETECTION")
        print("=" * 80)
        storms = analyzer.detect_dhcp_storms(
            window_seconds=args.storm_window,
            threshold=args.storm_threshold
        )

        if storms:
            print(f"⚠ Detected {len(storms)} potential DHCP storm(s):")
            print(f"{'Timestamp':<20} {'MAC Address':<20} {'Requests':<10} {'Window':<8} {'Device'}")
            print("-" * 100)
            for timestamp, mac, count, window in storms[:20]:  # Show top 20
                alias = analyzer.get_device_alias(mac) or ""
                print(f"{timestamp!s:<20} {mac:<20} {count:<10} {window}s{' '*6}{alias}")
        else:
            print("✓ No DHCP storms detected")


if __name__ == '__main__':
    main()
