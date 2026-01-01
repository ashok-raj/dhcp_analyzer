#!/usr/bin/env python3
"""
Interactive DHCP Packet Analyzer
Provides a command-line interface for analyzing DHCP traffic
"""

import sys
import cmd
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


class DHCPInteractive(cmd.Cmd):
    intro = """
================================================================================
    Interactive DHCP Analyzer
================================================================================
Type 'help' or '?' to list commands.
Type 'summary' for overall analysis.
Type 'exit' or 'quit' to exit.
================================================================================
"""
    prompt = 'dhcp> '

    def __init__(self, pcap_file):
        super().__init__()
        self.pcap_file = pcap_file
        self.packets = []
        self.dhcp_packets = []
        self.load_and_parse()

    def load_and_parse(self):
        """Load and parse DHCP packets"""
        print(f"\nLoading packets from {self.pcap_file}...")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(self.packets)} total packets")
        except Exception as e:
            print(f"Error loading pcap file: {e}")
            sys.exit(1)

        print("Parsing DHCP packets...")
        for idx, pkt in enumerate(self.packets):
            if DHCP in pkt:
                dhcp_info = self.parse_dhcp_packet(pkt, idx)
                if dhcp_info:
                    self.dhcp_packets.append(dhcp_info)

        print(f"Found {len(self.dhcp_packets)} DHCP packets\n")

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
            return None

    def format_timestamp(self, ts):
        """Format timestamp for display"""
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    def print_packet(self, pkt_info, verbose=False):
        """Print formatted packet information"""
        ts = self.format_timestamp(pkt_info['timestamp'])
        msg_type = pkt_info['message_type_name']
        client_mac = pkt_info['client_mac'] or 'N/A'

        print(f"  [{ts}] {msg_type:10s} | MAC: {client_mac} | Pkt: #{pkt_info['index']}")

        if verbose:
            print(f"    Src IP: {pkt_info['src_ip']:15s} -> Dst IP: {pkt_info['dst_ip']}")
            print(f"    Client IP: {pkt_info['client_ip']:15s} | Your IP: {pkt_info['your_ip']}")
            print(f"    Server IP: {pkt_info['server_ip']:15s} | XID: 0x{pkt_info['transaction_id']:08x}")

    def do_summary(self, arg):
        """Show summary of all DHCP packets"""
        print("\n" + "="*80)
        print("DHCP PACKET SUMMARY")
        print("="*80)

        # Overall stats
        print(f"\nTotal DHCP packets: {len(self.dhcp_packets)}")

        # Message type counts
        print("\nMessage type breakdown:")
        msg_counts = Counter([p['message_type_name'] for p in self.dhcp_packets])
        for msg_type, count in sorted(msg_counts.items()):
            print(f"  {msg_type:10s}: {count:4d}")

        # Unique MACs
        unique_macs = set([p['client_mac'] for p in self.dhcp_packets if p['client_mac']])
        print(f"\nUnique client MACs: {len(unique_macs)}")

        # MACs with most activity
        mac_counts = Counter([p['client_mac'] for p in self.dhcp_packets if p['client_mac']])
        print("\nTop 5 most active MACs:")
        for mac, count in mac_counts.most_common(5):
            # Find last successful ACK for this MAC
            last_ip = None
            last_ack_time = None
            for pkt in sorted([p for p in self.dhcp_packets if p['client_mac'] == mac],
                            key=lambda x: x['timestamp'], reverse=True):
                if pkt['message_type'] == 5:  # ACK
                    last_ip = pkt['your_ip']
                    last_ack_time = pkt['timestamp']
                    break

            if last_ip and last_ip != '0.0.0.0':
                time_str = self.format_timestamp(last_ack_time)
                print(f"  {mac}: {count} packets | Last IP: {last_ip} ({time_str})")
            else:
                print(f"  {mac}: {count} packets | No successful lease")

        # Time range
        if self.dhcp_packets:
            start_time = min(p['timestamp'] for p in self.dhcp_packets)
            end_time = max(p['timestamp'] for p in self.dhcp_packets)
            duration = end_time - start_time
            print(f"\nCapture time range:")
            print(f"  Start: {self.format_timestamp(start_time)}")
            print(f"  End:   {self.format_timestamp(end_time)}")
            print(f"  Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")

        print("="*80 + "\n")

    def do_naks(self, arg):
        """Find and display all DHCP NAK messages
        Usage: naks [mac_address]
        """
        print("\n" + "="*80)
        print("DHCP NAK MESSAGES")
        print("="*80)

        naks = [p for p in self.dhcp_packets if p['message_type'] == 6]

        # Filter by MAC if provided
        if arg.strip():
            mac_filter = arg.strip().lower()
            naks = [p for p in naks if mac_filter in (p['client_mac'] or '').lower()]
            print(f"\nFiltered by MAC: {mac_filter}")

        if not naks:
            print("\nNo NAK messages found")
            print("="*80 + "\n")
            return

        print(f"\nFound {len(naks)} NAK message(s)\n")

        # Group by MAC
        naks_by_mac = defaultdict(list)
        for nak in naks:
            naks_by_mac[nak['client_mac']].append(nak)

        for mac, mac_naks in sorted(naks_by_mac.items()):
            print(f"\nMAC: {mac} ({len(mac_naks)} NAK(s))")
            print("-" * 80)
            for nak in mac_naks:
                self.print_packet(nak, verbose=True)
                print()

        print("="*80 + "\n")

    def do_dor_nak(self, arg):
        """Find NAKs that follow a complete DISCOVER->OFFER->REQUEST sequence
        Usage: dor_nak [mac_address]
        """
        print("\n" + "="*80)
        print("DISCOVER-OFFER-REQUEST-NAK SEQUENCES")
        print("="*80)

        # Group packets by MAC and transaction ID
        sequences = defaultdict(lambda: defaultdict(list))
        for pkt in self.dhcp_packets:
            mac = pkt['client_mac']
            xid = pkt['transaction_id']
            sequences[mac][xid].append(pkt)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        dor_nak_found = False

        for mac, xid_groups in sorted(sequences.items()):
            if mac_filter and mac_filter not in (mac or '').lower():
                continue

            for xid, pkts in xid_groups.items():
                # Sort by timestamp
                pkts.sort(key=lambda x: x['timestamp'])

                # Look for DISCOVER -> OFFER -> REQUEST -> NAK pattern
                msg_types = [p['message_type'] for p in pkts]

                # Check if we have the DORA pattern ending in NAK
                has_discover = 1 in msg_types
                has_offer = 2 in msg_types
                has_request = 3 in msg_types
                has_nak = 6 in msg_types

                if has_discover and has_offer and has_request and has_nak:
                    dor_nak_found = True
                    print(f"\n*** DORA-NAK sequence found ***")
                    print(f"MAC: {mac}")
                    print(f"Transaction ID: 0x{xid:08x}")
                    print(f"Sequence:")
                    for pkt in pkts:
                        self.print_packet(pkt, verbose=True)
                        print()

        if not dor_nak_found:
            print("\nNo DISCOVER-OFFER-REQUEST-NAK sequences found")

        print("="*80 + "\n")

    def do_failed_dora(self, arg):
        """Count failed DORA attempts per MAC (no successful ACK)
        Usage: failed_dora [mac_address]
        """
        print("\n" + "="*80)
        print("FAILED DORA SEQUENCES PER MAC")
        print("="*80)

        # Group packets by MAC and transaction ID
        sequences = defaultdict(lambda: defaultdict(list))
        for pkt in self.dhcp_packets:
            mac = pkt['client_mac']
            xid = pkt['transaction_id']
            sequences[mac][xid].append(pkt)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        print("\nAnalyzing DORA sequences...\n")

        results = []

        for mac, xid_groups in sorted(sequences.items()):
            if mac_filter and mac_filter not in (mac or '').lower():
                continue

            total_sequences = 0
            failed_sequences = 0
            successful_sequences = 0
            nak_sequences = 0

            for xid, pkts in xid_groups.items():
                # Sort by timestamp
                pkts.sort(key=lambda x: x['timestamp'])
                msg_types = [p['message_type'] for p in pkts]

                # Check if this is a DORA sequence (has DISCOVER or REQUEST)
                has_discover = 1 in msg_types
                has_request = 3 in msg_types

                if has_discover or has_request:
                    total_sequences += 1

                    # Check outcome
                    has_ack = 5 in msg_types
                    has_nak = 6 in msg_types

                    if has_ack:
                        successful_sequences += 1
                    elif has_nak:
                        nak_sequences += 1
                        failed_sequences += 1
                    else:
                        # No response or incomplete
                        failed_sequences += 1

            if total_sequences > 0:
                success_rate = (successful_sequences / total_sequences) * 100
                results.append({
                    'mac': mac,
                    'total': total_sequences,
                    'failed': failed_sequences,
                    'success': successful_sequences,
                    'naks': nak_sequences,
                    'success_rate': success_rate
                })

        # Sort by number of failures
        results.sort(key=lambda x: x['failed'], reverse=True)

        if not results:
            print("No DORA sequences found")
            print("="*80 + "\n")
            return

        # Display results
        print(f"{'MAC Address':<20} {'Total':<8} {'Failed':<8} {'NAKs':<8} {'Success':<8} {'Success Rate':<12}")
        print("-" * 80)

        for r in results:
            print(f"{r['mac']:<20} {r['total']:<8} {r['failed']:<8} {r['naks']:<8} {r['success']:<8} {r['success_rate']:>10.1f}%")

        print("\nSummary:")
        print(f"  Total MACs analyzed: {len(results)}")
        print(f"  Total DORA sequences: {sum(r['total'] for r in results)}")
        print(f"  Total failed sequences: {sum(r['failed'] for r in results)}")
        print(f"  Total NAKs: {sum(r['naks'] for r in results)}")
        print(f"  Total successful: {sum(r['success'] for r in results)}")

        print("="*80 + "\n")

    def do_filter(self, arg):
        """Filter and show all packets for a specific MAC address
        Usage: filter <mac_address>
        """
        if not arg.strip():
            print("Usage: filter <mac_address>")
            return

        mac_filter = arg.strip().lower()
        print("\n" + "="*80)
        print(f"PACKETS FOR MAC: {mac_filter}")
        print("="*80)

        filtered = [p for p in self.dhcp_packets if mac_filter in (p['client_mac'] or '').lower()]

        if not filtered:
            print("\nNo packets found for this MAC")
            print("="*80 + "\n")
            return

        print(f"\nFound {len(filtered)} packet(s)\n")

        # Message type summary
        msg_counts = Counter([p['message_type_name'] for p in filtered])
        print("Message breakdown:")
        for msg_type, count in sorted(msg_counts.items()):
            print(f"  {msg_type:10s}: {count}")

        print("\nPacket details:")
        for pkt in filtered:
            self.print_packet(pkt, verbose=True)
            print()

        print("="*80 + "\n")

    def do_storms(self, arg):
        """Detect DHCP storms (excessive messages in short time)
        Usage: storms [time_window] [threshold]
        Default: 10 seconds, 10 messages
        """
        time_window = 10
        threshold = 10

        args = arg.strip().split()
        if len(args) >= 1:
            try:
                time_window = int(args[0])
            except ValueError:
                print("Invalid time window, using default (10)")

        if len(args) >= 2:
            try:
                threshold = int(args[1])
            except ValueError:
                print("Invalid threshold, using default (10)")

        print("\n" + "="*80)
        print(f"DHCP STORM DETECTION (>{threshold} msgs in {time_window}s)")
        print("="*80)

        # Group by MAC and message type
        mac_messages = defaultdict(list)
        for pkt_info in self.dhcp_packets:
            mac = pkt_info['client_mac']
            msg_type = pkt_info['message_type_name']
            if msg_type in ['DISCOVER', 'REQUEST']:
                mac_messages[mac].append(pkt_info)

        storms = []

        # Check for storms
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

        if not storms:
            print("\nNo DHCP storms detected")
            print("="*80 + "\n")
            return

        print(f"\nFound {len(storms)} storm(s)\n")

        for idx, storm in enumerate(storms, 1):
            print(f"Storm #{idx}:")
            print(f"  MAC: {storm['mac']}")
            print(f"  Time: {self.format_timestamp(storm['start_time'])} -> {self.format_timestamp(storm['end_time'])}")
            print(f"  Duration: {storm['end_time'] - storm['start_time']:.2f} seconds")
            print(f"  Messages: {storm['message_types']}")
            print(f"  Sample packets:")
            for pkt in storm['packets'][:5]:
                self.print_packet(pkt)
            print()

        print("="*80 + "\n")

    def do_list(self, arg):
        """List all DHCP packets in chronological order
        Usage: list [mac_address] [limit]
        Examples:
          list                    - Show all packets
          list 20                 - Show first 20 packets
          list aa:bb:cc:dd:ee:ff  - Show packets for specific MAC
          list aa:bb:cc 50        - Show first 50 packets for MAC
        """
        print("\n" + "="*80)
        print("DHCP PACKETS IN CHRONOLOGICAL ORDER")
        print("="*80)

        # Parse arguments
        args = arg.strip().split()
        mac_filter = None
        limit = None

        for a in args:
            if a.isdigit():
                limit = int(a)
            elif ':' in a:
                mac_filter = a.lower()

        # Filter packets
        packets = self.dhcp_packets
        if mac_filter:
            packets = [p for p in packets if mac_filter in (p['client_mac'] or '').lower()]
            print(f"\nFiltered by MAC: {mac_filter}")

        if not packets:
            print("\nNo packets found")
            print("="*80 + "\n")
            return

        # Sort by timestamp
        packets = sorted(packets, key=lambda x: x['timestamp'])

        # Apply limit
        total_packets = len(packets)
        if limit:
            packets = packets[:limit]
            print(f"\nShowing {len(packets)} of {total_packets} packets (limited to {limit})")
        else:
            print(f"\nShowing all {len(packets)} packets")

        print()

        # Display packets
        for idx, pkt in enumerate(packets, 1):
            ts = self.format_timestamp(pkt['timestamp'])
            msg_type = pkt['message_type_name']
            mac = pkt['client_mac'] or 'N/A'
            src_ip = pkt['src_ip'] or 'N/A'
            dst_ip = pkt['dst_ip'] or 'N/A'
            your_ip = pkt['your_ip'] or '0.0.0.0'

            # Show IP being offered/assigned for OFFER/ACK
            ip_info = ""
            if pkt['message_type'] in [2, 5]:  # OFFER or ACK
                if your_ip != '0.0.0.0':
                    ip_info = f" -> {your_ip}"

            print(f"{idx:3d}. [{ts}] {msg_type:10s} | {mac:17s} | {src_ip:15s} -> {dst_ip:15s}{ip_info}")

        if limit and total_packets > limit:
            print(f"\n... {total_packets - limit} more packets not shown (use 'list {total_packets}' to see all)")

        print("="*80 + "\n")

    def do_list_mac(self, arg):
        """List all DORA sequences grouped by MAC address
        Usage: list_mac [mac_address]
        Examples:
          list_mac                    - Show all DORA sequences for all MACs
          list_mac aa:bb:cc:dd:ee:ff  - Show DORA sequences for specific MAC
        """
        print("\n" + "="*80)
        print("DORA SEQUENCES BY MAC ADDRESS")
        print("="*80)

        # Parse arguments
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        # Group packets by MAC and transaction ID
        sequences = defaultdict(lambda: defaultdict(list))
        for pkt in self.dhcp_packets:
            mac = pkt['client_mac']
            xid = pkt['transaction_id']
            sequences[mac][xid].append(pkt)

        # Filter by MAC if provided
        macs_to_show = sorted(sequences.keys())
        if mac_filter:
            macs_to_show = [mac for mac in macs_to_show if mac and mac_filter in mac.lower()]

        if not macs_to_show:
            print("\nNo packets found")
            print("="*80 + "\n")
            return

        print(f"\nFound {len(macs_to_show)} MAC(s) with DHCP activity\n")

        # Process each MAC
        for mac in macs_to_show:
            xid_groups = sequences[mac]

            print(f"\n{'='*80}")
            print(f"MAC: {mac}")
            print(f"{'='*80}")
            print(f"Total sequences: {len(xid_groups)}\n")

            # Sort sequences by their first packet timestamp
            sorted_xids = sorted(xid_groups.items(),
                               key=lambda x: min(p['timestamp'] for p in x[1]))

            for seq_num, (xid, pkts) in enumerate(sorted_xids, 1):
                # Sort packets by timestamp
                pkts.sort(key=lambda x: x['timestamp'])

                # Analyze the sequence
                msg_types = [p['message_type'] for p in pkts]
                msg_names = [p['message_type_name'] for p in pkts]

                # Determine sequence status
                has_discover = 1 in msg_types
                has_offer = 2 in msg_types
                has_request = 3 in msg_types
                has_ack = 5 in msg_types
                has_nak = 6 in msg_types

                # Build sequence pattern string
                sequence_pattern = ' -> '.join(msg_names)

                # Determine status
                if has_nak:
                    status = "FAILED (NAK)"
                elif has_ack:
                    status = "SUCCESS"
                elif has_request and not has_offer:
                    status = "INCOMPLETE (Request without Offer)"
                elif has_discover and not has_offer:
                    status = "INCOMPLETE (No Offer)"
                elif has_offer and not has_request:
                    status = "INCOMPLETE (No Request)"
                else:
                    status = "INCOMPLETE"

                print(f"  Sequence #{seq_num} - XID: 0x{xid:08x} - {status}")
                print(f"  Pattern: {sequence_pattern}")
                print(f"  {'─'*76}")

                # Display each packet in the sequence
                for pkt in pkts:
                    ts = self.format_timestamp(pkt['timestamp'])
                    msg_type = pkt['message_type_name']
                    pkt_num = pkt['index']
                    src_ip = pkt['src_ip'] or 'N/A'
                    dst_ip = pkt['dst_ip'] or 'N/A'
                    your_ip = pkt['your_ip'] or '0.0.0.0'

                    # Show IP being offered/assigned for OFFER/ACK
                    ip_info = ""
                    if pkt['message_type'] in [2, 5]:  # OFFER or ACK
                        if your_ip != '0.0.0.0':
                            ip_info = f" (IP: {your_ip})"

                    print(f"    [{ts}] Pkt #{pkt_num:5d} | {msg_type:10s} | {src_ip:15s} -> {dst_ip:15s}{ip_info}")

                print()

        print("="*80 + "\n")

    def do_help(self, arg):
        """Show available commands"""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            print("\n" + "="*80)
            print("AVAILABLE COMMANDS")
            print("="*80)
            print("\nsummary              - Show overall DHCP packet summary")
            print("list [mac] [limit]   - List all DHCP packets in chronological order")
            print("list_mac [mac]       - List all DORA sequences grouped by MAC address")
            print("naks [mac]           - Show all DHCP NAK messages (optionally filter by MAC)")
            print("dor_nak [mac]        - Find DISCOVER-OFFER-REQUEST-NAK sequences")
            print("failed_dora [mac]    - Count failed DORA attempts per MAC")
            print("filter <mac>         - Show all packets for a specific MAC")
            print("storms [time] [cnt]  - Detect DHCP storms (default: 10s, 10 msgs)")
            print("help [cmd]           - Show help for a command")
            print("exit / quit          - Exit the program")
            print("\nType 'help <command>' for more details on a specific command")
            print("="*80 + "\n")

    def do_exit(self, arg):
        """Exit the program"""
        print("\nExiting DHCP analyzer. Goodbye!")
        return True

    def do_quit(self, arg):
        """Exit the program"""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        """Handle Ctrl+D"""
        print()
        return self.do_exit(arg)


def main():
    if len(sys.argv) < 2:
        print("Usage: dhcp_interactive.py <pcap_file>")
        print("\nInteractive DHCP packet analyzer")
        print("Loads a pcap file and provides an interactive command-line interface")
        print("for analyzing DHCP traffic patterns, NAKs, and failed sequences.")
        sys.exit(1)

    pcap_file = sys.argv[1]

    try:
        analyzer = DHCPInteractive(pcap_file)
        analyzer.cmdloop()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting...")
        sys.exit(0)


if __name__ == '__main__':
    main()
