#!/usr/bin/env python3
"""
DHCP Packet Analyzer for Wireshark Captures
Analyzes DHCP traffic, filters by MAC address, detects NAKs and DHCP storms
"""

import sys
import argparse
from datetime import datetime
from collections import defaultdict, Counter
try:
    from scapy.all import rdpcap, DHCP, BOOTP, Ether
    from scapy.layers.inet import IP, UDP
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)


# DHCP Message Types
DHCP_MESSAGE_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM"
}


class DHCPAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.dhcp_packets = []

    def load_packets(self):
        """Load packets from pcap file"""
        print(f"Loading packets from {self.pcap_file}...")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(self.packets)} packets")
        except Exception as e:
            print(f"Error loading pcap file: {e}")
            sys.exit(1)

    def extract_dhcp_packets(self):
        """Extract all DHCP packets"""
        for idx, pkt in enumerate(self.packets):
            if DHCP in pkt:
                dhcp_info = self.parse_dhcp_packet(pkt, idx)
                if dhcp_info:
                    self.dhcp_packets.append(dhcp_info)
        print(f"Found {len(self.dhcp_packets)} DHCP packets")

    def parse_dhcp_packet(self, pkt, idx):
        """Parse DHCP packet and extract relevant information"""
        try:
            dhcp_info = {
                'index': idx,
                'packet': pkt,
                'timestamp': float(pkt.time) if hasattr(pkt, 'time') else 0,
                'src_mac': pkt[Ether].src if Ether in pkt else None,
                'dst_mac': pkt[Ether].dst if Ether in pkt else None,
                'client_mac': pkt[BOOTP].chaddr.hex(':')[0:17] if BOOTP in pkt else None,
                'src_ip': pkt[IP].src if IP in pkt else None,
                'dst_ip': pkt[IP].dst if IP in pkt else None,
                'transaction_id': pkt[BOOTP].xid if BOOTP in pkt else None,
                'client_ip': pkt[BOOTP].ciaddr if BOOTP in pkt else None,
                'your_ip': pkt[BOOTP].yiaddr if BOOTP in pkt else None,
                'server_ip': pkt[BOOTP].siaddr if BOOTP in pkt else None,
                'message_type': None,
                'message_type_name': 'UNKNOWN'
            }

            # Extract DHCP message type
            if DHCP in pkt:
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type':
                        dhcp_info['message_type'] = opt[1]
                        dhcp_info['message_type_name'] = DHCP_MESSAGE_TYPES.get(opt[1], 'UNKNOWN')
                        break

            return dhcp_info
        except Exception as e:
            print(f"Error parsing packet {idx}: {e}")
            return None

    def filter_by_mac(self, mac_address):
        """Filter DHCP packets by MAC address"""
        mac_lower = mac_address.lower()
        filtered = []
        for pkt_info in self.dhcp_packets:
            client_mac = pkt_info['client_mac']
            src_mac = pkt_info['src_mac']
            dst_mac = pkt_info['dst_mac']

            if (client_mac and mac_lower in client_mac.lower()) or \
               (src_mac and mac_lower in src_mac.lower()) or \
               (dst_mac and mac_lower in dst_mac.lower()):
                filtered.append(pkt_info)

        return filtered

    def find_naks(self, packets=None):
        """Find all DHCP NAK messages"""
        if packets is None:
            packets = self.dhcp_packets

        naks = []
        for pkt_info in packets:
            if pkt_info['message_type'] == 6:  # NAK
                naks.append(pkt_info)

        return naks

    def get_context_packets(self, nak_info, packets, before=5, after=3):
        """Get packets before and after a NAK for the same MAC"""
        mac = nak_info['client_mac']
        nak_idx = nak_info['index']

        context = {'before': [], 'nak': nak_info, 'after': []}

        # Get packets before NAK
        for pkt_info in reversed(packets):
            if pkt_info['index'] < nak_idx and pkt_info['client_mac'] == mac:
                context['before'].insert(0, pkt_info)
                if len(context['before']) >= before:
                    break

        # Get packets after NAK
        for pkt_info in packets:
            if pkt_info['index'] > nak_idx and pkt_info['client_mac'] == mac:
                context['after'].append(pkt_info)
                if len(context['after']) >= after:
                    break

        return context

    def detect_storm(self, packets, time_window=10, threshold=10):
        """Detect DHCP storm patterns"""
        storms = []

        # Group by MAC and message type
        mac_messages = defaultdict(list)
        for pkt_info in packets:
            mac = pkt_info['client_mac']
            msg_type = pkt_info['message_type_name']
            if msg_type in ['DISCOVER', 'REQUEST']:
                mac_messages[mac].append(pkt_info)

        # Check for storms (excessive messages in time window)
        for mac, messages in mac_messages.items():
            if len(messages) < threshold:
                continue

            # Sort by timestamp
            messages.sort(key=lambda x: x['timestamp'])

            # Check sliding window
            for i in range(len(messages) - threshold + 1):
                window_start = messages[i]['timestamp']
                window_end = messages[i + threshold - 1]['timestamp']

                if window_end - window_start <= time_window:
                    msg_types = Counter([m['message_type_name'] for m in messages[i:i+threshold]])
                    storms.append({
                        'mac': mac,
                        'start_time': window_start,
                        'end_time': window_end,
                        'count': threshold,
                        'message_types': dict(msg_types),
                        'packets': messages[i:i+threshold]
                    })
                    break

        return storms

    def format_timestamp(self, ts):
        """Format timestamp for display"""
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    def print_packet_info(self, pkt_info, verbose=False):
        """Print formatted packet information"""
        ts = self.format_timestamp(pkt_info['timestamp'])
        msg_type = pkt_info['message_type_name']
        client_mac = pkt_info['client_mac'] or 'N/A'

        print(f"  [{ts}] {msg_type:10s} | MAC: {client_mac}")

        if verbose:
            print(f"    Src IP: {pkt_info['src_ip']:15s} -> Dst IP: {pkt_info['dst_ip']}")
            print(f"    Client IP: {pkt_info['client_ip']:15s} | Your IP: {pkt_info['your_ip']}")
            print(f"    Server IP: {pkt_info['server_ip']:15s} | XID: 0x{pkt_info['transaction_id']:08x}")
            print()

    def generate_report(self, mac_address=None, show_naks=True, detect_storms=True, verbose=False):
        """Generate analysis report"""
        print("\n" + "="*80)
        print("DHCP PACKET ANALYSIS REPORT")
        print("="*80)

        # Filter by MAC if specified
        packets = self.dhcp_packets
        if mac_address:
            print(f"\nFiltering by MAC address: {mac_address}")
            packets = self.filter_by_mac(mac_address)
            print(f"Found {len(packets)} packets for this MAC")

        if not packets:
            print("No packets found matching criteria")
            return

        # Summary statistics
        print(f"\n--- Summary ---")
        msg_type_counts = Counter([p['message_type_name'] for p in packets])
        for msg_type, count in sorted(msg_type_counts.items()):
            print(f"  {msg_type:10s}: {count}")

        # Show all packets if verbose
        if verbose:
            print(f"\n--- All DHCP Packets ---")
            for pkt_info in packets:
                self.print_packet_info(pkt_info, verbose=True)

        # Find and display NAKs
        if show_naks:
            naks = self.find_naks(packets)
            if naks:
                print(f"\n--- DHCP NAK Messages Found: {len(naks)} ---")
                for nak in naks:
                    print(f"\n** NAK at packet #{nak['index']} **")
                    self.print_packet_info(nak, verbose=True)

                    # Show context
                    context = self.get_context_packets(nak, packets)
                    if context['before']:
                        print("  Packets BEFORE NAK:")
                        for pkt in context['before']:
                            self.print_packet_info(pkt, verbose=verbose)

                    if context['after']:
                        print("  Packets AFTER NAK:")
                        for pkt in context['after']:
                            self.print_packet_info(pkt, verbose=verbose)
            else:
                print(f"\n--- No NAK messages found ---")

        # Detect storms
        if detect_storms:
            storms = self.detect_storm(packets)
            if storms:
                print(f"\n--- DHCP STORM DETECTED: {len(storms)} instance(s) ---")
                for idx, storm in enumerate(storms, 1):
                    print(f"\nStorm #{idx}:")
                    print(f"  MAC: {storm['mac']}")
                    print(f"  Time: {self.format_timestamp(storm['start_time'])} -> {self.format_timestamp(storm['end_time'])}")
                    print(f"  Duration: {storm['end_time'] - storm['start_time']:.2f} seconds")
                    print(f"  Messages: {storm['message_types']}")
                    print(f"  Sample packets:")
                    for pkt in storm['packets'][:5]:
                        self.print_packet_info(pkt)
            else:
                print(f"\n--- No DHCP storm detected ---")

        print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(
        description='DHCP Packet Analyzer for Wireshark Captures',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcap -m aa:bb:cc:dd:ee:ff
  %(prog)s capture.pcap -m aa:bb:cc:dd:ee:ff --verbose
  %(prog)s capture.pcap --no-storm-detection
        '''
    )

    parser.add_argument('pcap_file', help='Path to pcap/pcapng file')
    parser.add_argument('-m', '--mac', help='Filter by MAC address (partial match supported)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed packet information')
    parser.add_argument('--no-naks', action='store_true', help='Disable NAK detection')
    parser.add_argument('--no-storm-detection', action='store_true', help='Disable DHCP storm detection')
    parser.add_argument('--storm-window', type=int, default=10, help='Storm detection time window in seconds (default: 10)')
    parser.add_argument('--storm-threshold', type=int, default=10, help='Storm detection message threshold (default: 10)')

    args = parser.parse_args()

    # Create analyzer
    analyzer = DHCPAnalyzer(args.pcap_file)

    # Load and analyze packets
    analyzer.load_packets()
    analyzer.extract_dhcp_packets()

    # Generate report
    analyzer.generate_report(
        mac_address=args.mac,
        show_naks=not args.no_naks,
        detect_storms=not args.no_storm_detection,
        verbose=args.verbose
    )


if __name__ == '__main__':
    main()
