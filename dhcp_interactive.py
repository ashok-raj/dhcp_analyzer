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
            # Extract UDP checksum info if available
            udp_chksum = None
            udp_chksum_valid = None
            if UDP in pkt:
                udp_chksum = pkt[UDP].chksum
                # Check if checksum is valid (scapy marks it)
                udp_chksum_valid = pkt[UDP].chksum == 0 or hasattr(pkt[UDP], 'chksum')

            # Extract IP flags and ID
            ip_flags = None
            ip_id = None
            if IP in pkt:
                ip_flags = pkt[IP].flags
                ip_id = pkt[IP].id

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
                'message_type_name': 'UNKNOWN',
                'udp_chksum': udp_chksum,
                'udp_chksum_valid': udp_chksum_valid,
                'ip_flags': ip_flags,
                'ip_id': ip_id
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
        """Show comprehensive summary with analysis and recommendations"""
        print("\n" + "="*80)
        print("DHCP PACKET ANALYSIS SUMMARY")
        print("="*80)

        # Capture file overview
        if self.dhcp_packets:
            start_time = min(p['timestamp'] for p in self.dhcp_packets)
            end_time = max(p['timestamp'] for p in self.dhcp_packets)
            duration = end_time - start_time

            print(f"\n📊 CAPTURE FILE OVERVIEW")
            print(f"  Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
            print(f"  Total DHCP packets: {len(self.dhcp_packets)}")
            print(f"  Capture period: {self.format_timestamp(start_time)} to {self.format_timestamp(end_time)}")
            if duration > 0:
                packet_rate = len(self.dhcp_packets) / duration
                print(f"  Average rate: {packet_rate:.1f} packets/second")

        # Message type counts
        print(f"\n📨 MESSAGE TYPE BREAKDOWN")
        msg_counts = Counter([p['message_type_name'] for p in self.dhcp_packets])
        discovers = msg_counts.get('DISCOVER', 0)
        offers = msg_counts.get('OFFER', 0)
        requests = msg_counts.get('REQUEST', 0)
        acks = msg_counts.get('ACK', 0)
        naks = msg_counts.get('NAK', 0)

        for msg_type, count in sorted(msg_counts.items()):
            print(f"  {msg_type:10s}: {count:4d}")

        # CRITICAL FINDINGS - Ratio Analysis
        print(f"\n🔍 CRITICAL FINDINGS")

        # Check for duplicate responses
        total_requests = discovers + requests
        if total_requests > 0:
            ack_ratio = acks / total_requests
            if ack_ratio > 1.1:
                duplicates_estimated = acks - total_requests
                print(f"  ⚠️  DUPLICATE DHCP ACK RESPONSES DETECTED!")
                print(f"      Requests: {total_requests}")
                print(f"      ACKs: {acks}")
                print(f"      Ratio: {ack_ratio:.2f}:1 (expected: 1:1)")
                print(f"      Estimated duplicate ACKs: ~{duplicates_estimated}")
                print(f"      This indicates a DHCP server bug or misconfiguration")
            else:
                print(f"  ✓ ACK/REQUEST ratio: {ack_ratio:.2f}:1 (normal)")

        if discovers > 0:
            offer_ratio = offers / discovers
            if offer_ratio > 1.1:
                print(f"  ⚠️  Multiple OFFERs per DISCOVER: {offer_ratio:.2f}:1")
                print(f"      May indicate multiple DHCP servers or duplicate responses")

        # DHCP Server Information
        print(f"\n🖥️  DHCP SERVER(S)")
        server_ips = set()
        server_stats = {}
        lease_times = {}

        for pkt in self.dhcp_packets:
            if pkt['message_type'] in [2, 5]:  # OFFER or ACK
                if pkt['src_ip'] and pkt['src_ip'] != '0.0.0.0':
                    server_ips.add(pkt['src_ip'])
                    if pkt['src_ip'] not in server_stats:
                        server_stats[pkt['src_ip']] = {'offers': 0, 'acks': 0, 'naks': 0}

                    if pkt['message_type'] == 2:
                        server_stats[pkt['src_ip']]['offers'] += 1
                    elif pkt['message_type'] == 5:
                        server_stats[pkt['src_ip']]['acks'] += 1

                        # Extract lease time
                        dhcp_pkt = pkt['packet']
                        if DHCP in dhcp_pkt:
                            for opt in dhcp_pkt[DHCP].options:
                                if isinstance(opt, tuple) and opt[0] == 'lease_time':
                                    lease_times[pkt['src_ip']] = opt[1]
                                    break

            if pkt['message_type'] == 6 and pkt['src_ip']:  # NAK
                if pkt['src_ip'] not in server_stats:
                    server_stats[pkt['src_ip']] = {'offers': 0, 'acks': 0, 'naks': 0}
                server_stats[pkt['src_ip']]['naks'] += 1

        if server_ips:
            for server in sorted(server_ips):
                stats = server_stats[server]
                lease_time = lease_times.get(server, 0)
                print(f"  {server}:")
                print(f"    OFFERs: {stats['offers']}, ACKs: {stats['acks']}, NAKs: {stats['naks']}")
                if lease_time:
                    print(f"    Lease time: {lease_time}s ({lease_time/3600:.1f} hours)")
        else:
            print("  No server responses detected")

        # Network configuration
        if server_ips:
            print(f"\n🌐 NETWORK CONFIGURATION")
            # Determine network from assigned IPs
            assigned_ips = set()
            for pkt in self.dhcp_packets:
                if pkt['message_type'] in [2, 5] and pkt['your_ip'] and pkt['your_ip'] != '0.0.0.0':
                    assigned_ips.add(pkt['your_ip'])

            if assigned_ips:
                sorted_ips = sorted(assigned_ips, key=lambda ip: tuple(map(int, ip.split('.'))))
                first_octets = '.'.join(sorted_ips[0].split('.')[:3])
                print(f"  Network: {first_octets}.0/24 (inferred)")
                print(f"  DHCP Server: {', '.join(sorted(server_ips))}")
                print(f"  Unique IPs assigned: {len(assigned_ips)}")
                if len(assigned_ips) <= 10:
                    print(f"  IPs: {', '.join(sorted_ips)}")
                else:
                    print(f"  Range: {sorted_ips[0]} - {sorted_ips[-1]}")

        # Client analysis
        print(f"\n👥 TOP DHCP ACTIVE CLIENTS")
        mac_counts = Counter([p['client_mac'] for p in self.dhcp_packets if p['client_mac']])

        # Collect vendor info
        mac_vendor_info = {}
        for pkt in self.dhcp_packets:
            mac = pkt['client_mac']
            if mac and mac not in mac_vendor_info:
                dhcp_pkt = pkt['packet']
                if DHCP in dhcp_pkt:
                    for opt in dhcp_pkt[DHCP].options:
                        if isinstance(opt, tuple):
                            if opt[0] == 'vendor_class_id':
                                vendor = opt[1].decode('utf-8', errors='ignore') if isinstance(opt[1], bytes) else str(opt[1])
                                mac_vendor_info[mac] = vendor
                                break
                            elif opt[0] == 'hostname':
                                hostname = opt[1].decode('utf-8', errors='ignore') if isinstance(opt[1], bytes) else str(opt[1])
                                if mac not in mac_vendor_info:
                                    mac_vendor_info[mac] = f"Hostname: {hostname}"

        for mac, count in mac_counts.most_common(5):
            # Find last successful ACK for this MAC
            last_ip = None
            for pkt in sorted([p for p in self.dhcp_packets if p['client_mac'] == mac],
                            key=lambda x: x['timestamp'], reverse=True):
                if pkt['message_type'] == 5:  # ACK
                    last_ip = pkt['your_ip']
                    break

            vendor_info = mac_vendor_info.get(mac, '')
            if vendor_info:
                print(f"  {mac}: {count} packets")
                print(f"    {vendor_info}")
                if last_ip and last_ip != '0.0.0.0':
                    print(f"    Last IP: {last_ip}")
            else:
                if last_ip and last_ip != '0.0.0.0':
                    print(f"  {mac}: {count} packets | Last IP: {last_ip}")
                else:
                    print(f"  {mac}: {count} packets | No successful lease")

        # Success/Failure Analysis
        print(f"\n✅ DORA SEQUENCE ANALYSIS")
        sequences = defaultdict(lambda: defaultdict(list))
        for pkt in self.dhcp_packets:
            mac = pkt['client_mac']
            xid = pkt['transaction_id']
            sequences[mac][xid].append(pkt)

        total_sequences = 0
        successful_sequences = 0
        failed_sequences = 0
        nak_sequences = 0

        for mac, xid_groups in sequences.items():
            for xid, pkts in xid_groups.items():
                msg_types = [p['message_type'] for p in pkts]
                has_discover = 1 in msg_types
                has_request = 3 in msg_types

                if has_discover or has_request:
                    total_sequences += 1
                    has_ack = 5 in msg_types
                    has_nak = 6 in msg_types

                    if has_ack:
                        successful_sequences += 1
                    elif has_nak:
                        nak_sequences += 1
                        failed_sequences += 1
                    else:
                        failed_sequences += 1

        if total_sequences > 0:
            success_rate = (successful_sequences / total_sequences) * 100
            print(f"  Total sequences: {total_sequences}")
            print(f"  Successful: {successful_sequences} ({success_rate:.1f}%)")
            print(f"  Failed: {failed_sequences} ({100-success_rate:.1f}%)")
            if nak_sequences > 0:
                print(f"  NAKs: {nak_sequences}")

            if success_rate < 80:
                print(f"  ⚠️  Low success rate indicates DHCP issues!")

        # KEY OBSERVATIONS
        print(f"\n🔎 KEY OBSERVATIONS")

        # Check for aggressive renewal behavior
        renewals = requests - discovers if requests > discovers else 0
        if renewals > discovers * 2 and lease_times:
            print(f"  ⚠️  High renewal activity detected:")
            print(f"      REQUESTs without DISCOVER: {renewals}")
            print(f"      This may indicate clients renewing too frequently")

            # Calculate average renewal interval for top client
            if mac_counts:
                top_mac = mac_counts.most_common(1)[0][0]
                mac_requests = [p['timestamp'] for p in self.dhcp_packets
                               if p['client_mac'] == top_mac and p['message_type'] == 3]
                if len(mac_requests) > 1:
                    mac_requests.sort()
                    intervals = [mac_requests[i+1] - mac_requests[i]
                                for i in range(len(mac_requests)-1)]
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        lease_time = list(lease_times.values())[0] if lease_times else 0
                        if lease_time and avg_interval < lease_time * 0.01:
                            print(f"      Average renewal interval: ~{avg_interval:.1f}s")
                            print(f"      Expected (T1 at 50% of lease): {lease_time * 0.5:.0f}s")
                            print(f"      ⚠️  Renewing {(lease_time * 0.5 / avg_interval):.0f}x more frequently than expected!")

        # Vendor-specific observations
        tplink_clients = [mac for mac, vendor in mac_vendor_info.items() if 'TP-Link' in vendor]
        if tplink_clients:
            print(f"  • TP-Link devices detected: {len(tplink_clients)}")
            print(f"      Using vendor class: TP-Link,dslforum.org")
            print(f"      May exhibit vendor-specific DHCP behavior")

        # Duplicate detection hint
        if acks > total_requests * 1.5:
            print(f"  • Multiple server responses per request detected")
            print(f"      Run 'duplicates' command for detailed analysis")

        # RECOMMENDATIONS
        print(f"\n💡 RECOMMENDATIONS")

        issues_found = []

        if total_requests > 0 and acks / total_requests > 1.1:
            issues_found.append("duplicate_acks")
            print(f"  1. Investigate DHCP server for duplicate ACK bug")
            print(f"     • Check router firmware version")
            print(f"     • Look for known issues with duplicate responses")
            print(f"     • Run 'checksums' to check for UDP checksum corruption")
            print(f"     • Run 'duplicates' for detailed duplicate analysis")

        if renewals > discovers * 2:
            issues_found.append("aggressive_renewals")
            print(f"  2. Review client DHCP renewal behavior")
            print(f"     • Clients renewing too frequently")
            print(f"     • Run 'renewals' for detailed renewal analysis")
            print(f"     • Check client firmware for bugs")

        if tplink_clients:
            issues_found.append("tplink_devices")
            print(f"  3. TP-Link device-specific recommendations")
            print(f"     • Update TP-Link firmware to latest version")
            print(f"     • Run 'vendor' to analyze vendor-specific options")
            print(f"     • Monitor for 10-second renewal intervals")

        if success_rate < 80 and total_sequences > 0:
            issues_found.append("low_success")
            print(f"  4. Address low DHCP success rate ({success_rate:.1f}%)")
            print(f"     • Run 'failed_dora' to identify problematic clients")
            print(f"     • Check for IP pool exhaustion")
            print(f"     • Review NAK messages with 'naks' command")

        if not issues_found:
            print(f"  ✓ No critical issues detected")
            print(f"  • DHCP server appears to be functioning normally")
            print(f"  • Success rate: {success_rate:.1f}%")

        # Next steps
        print(f"\n📋 SUGGESTED NEXT STEPS")
        print(f"  • Run 'ratios' for quick ratio analysis")
        print(f"  • Run 'duplicates' to detect duplicate responses")
        print(f"  • Run 'renewals' to analyze renewal patterns")
        print(f"  • Run 'vendor' to check vendor-specific options")
        print(f"  • Run 'list_mac <mac>' to see detailed sequences for specific client")
        print(f"  • Run 'help' to see all available commands")

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

    def do_timings(self, arg):
        """Analyze timing between DHCP messages
        Usage: timings [mac_address]
        """
        print("\n" + "="*80)
        print("DHCP MESSAGE TIMING ANALYSIS")
        print("="*80)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        # Group packets by MAC and transaction ID
        sequences = defaultdict(lambda: defaultdict(list))
        for pkt in self.dhcp_packets:
            mac = pkt['client_mac']
            if mac_filter and mac_filter not in (mac or '').lower():
                continue
            xid = pkt['transaction_id']
            sequences[mac][xid].append(pkt)

        # Collect timing statistics
        discover_to_offer = []
        offer_to_request = []
        request_to_ack = []
        request_to_nak = []
        full_dora = []

        for mac, xid_groups in sequences.items():
            for xid, pkts in xid_groups.items():
                pkts_sorted = sorted(pkts, key=lambda x: x['timestamp'])

                discover_pkt = next((p for p in pkts_sorted if p['message_type'] == 1), None)
                offer_pkt = next((p for p in pkts_sorted if p['message_type'] == 2), None)
                request_pkt = next((p for p in pkts_sorted if p['message_type'] == 3), None)
                ack_pkt = next((p for p in pkts_sorted if p['message_type'] == 5), None)
                nak_pkt = next((p for p in pkts_sorted if p['message_type'] == 6), None)

                if discover_pkt and offer_pkt:
                    discover_to_offer.append(offer_pkt['timestamp'] - discover_pkt['timestamp'])

                if offer_pkt and request_pkt:
                    offer_to_request.append(request_pkt['timestamp'] - offer_pkt['timestamp'])

                if request_pkt and ack_pkt:
                    request_to_ack.append(ack_pkt['timestamp'] - request_pkt['timestamp'])

                if request_pkt and nak_pkt:
                    request_to_nak.append(nak_pkt['timestamp'] - request_pkt['timestamp'])

                if discover_pkt and ack_pkt:
                    full_dora.append(ack_pkt['timestamp'] - discover_pkt['timestamp'])

        # Display results
        def print_timing_stats(name, timings):
            if timings:
                avg = sum(timings) / len(timings)
                min_t = min(timings)
                max_t = max(timings)
                print(f"\n{name}:")
                print(f"  Count: {len(timings)}")
                print(f"  Average: {avg*1000:.1f}ms")
                print(f"  Min: {min_t*1000:.1f}ms")
                print(f"  Max: {max_t*1000:.1f}ms")
            else:
                print(f"\n{name}:")
                print(f"  No data available")

        print_timing_stats("DISCOVER → OFFER (Server Response Time)", discover_to_offer)
        print_timing_stats("OFFER → REQUEST (Client Decision Time)", offer_to_request)
        print_timing_stats("REQUEST → ACK (Server Processing Time)", request_to_ack)
        print_timing_stats("REQUEST → NAK (Server Rejection Time)", request_to_nak)
        print_timing_stats("Full DORA (DISCOVER → ACK)", full_dora)

        print("\n" + "="*80 + "\n")

    def do_servers(self, arg):
        """List all DHCP servers and their statistics
        Usage: servers
        """
        print("\n" + "="*80)
        print("DHCP SERVER ANALYSIS")
        print("="*80)

        # Collect server statistics
        server_stats = defaultdict(lambda: {
            'offers': 0,
            'acks': 0,
            'naks': 0,
            'discovers_seen': 0,
            'requests_seen': 0
        })

        # Count messages
        for pkt in self.dhcp_packets:
            if pkt['message_type'] == 1:  # DISCOVER
                # Count discovers to calculate response rate
                pass
            elif pkt['message_type'] == 2:  # OFFER
                server = pkt['src_ip']
                if server and server != '0.0.0.0':
                    server_stats[server]['offers'] += 1
            elif pkt['message_type'] == 5:  # ACK
                server = pkt['src_ip']
                if server and server != '0.0.0.0':
                    server_stats[server]['acks'] += 1
            elif pkt['message_type'] == 6:  # NAK
                server = pkt['src_ip']
                if server and server != '0.0.0.0':
                    server_stats[server]['naks'] += 1

        if not server_stats:
            print("\nNo DHCP servers detected")
            print("="*80 + "\n")
            return

        print(f"\nFound {len(server_stats)} DHCP server(s)\n")

        # Display server statistics
        for server in sorted(server_stats.keys()):
            stats = server_stats[server]
            total_responses = stats['offers'] + stats['acks'] + stats['naks']

            print(f"Server: {server}")
            print(f"  OFFERs: {stats['offers']}")
            print(f"  ACKs: {stats['acks']}")
            print(f"  NAKs: {stats['naks']}")
            print(f"  Total responses: {total_responses}")

            if stats['acks'] + stats['naks'] > 0:
                success_rate = (stats['acks'] / (stats['acks'] + stats['naks'])) * 100
                print(f"  Success rate (ACK vs NAK): {success_rate:.1f}%")

            print()

        print("="*80 + "\n")

    def do_ips(self, arg):
        """Show IP address assignments and usage
        Usage: ips [mac_address]
        """
        print("\n" + "="*80)
        print("IP ADDRESS ASSIGNMENTS")
        print("="*80)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        # Collect IP assignments
        ip_assignments = defaultdict(list)  # ip -> [(mac, timestamp, msg_type)]

        for pkt in self.dhcp_packets:
            if pkt['message_type'] in [2, 5]:  # OFFER or ACK
                mac = pkt['client_mac']
                if mac_filter and mac_filter not in (mac or '').lower():
                    continue

                ip = pkt['your_ip']
                if ip and ip != '0.0.0.0':
                    msg_type = 'OFFER' if pkt['message_type'] == 2 else 'ACK'
                    ip_assignments[ip].append((mac, pkt['timestamp'], msg_type))

        if not ip_assignments:
            print("\nNo IP assignments found")
            print("="*80 + "\n")
            return

        print(f"\nTotal unique IPs: {len(ip_assignments)}\n")

        # Sort IPs
        sorted_ips = sorted(ip_assignments.keys(), key=lambda ip: tuple(map(int, ip.split('.'))))

        for ip in sorted_ips:
            assignments = ip_assignments[ip]
            unique_macs = set([a[0] for a in assignments])

            print(f"IP: {ip}")
            print(f"  Assigned to {len(unique_macs)} MAC(s): {', '.join(unique_macs)}")
            print(f"  Total assignments: {len(assignments)} (OFFERs + ACKs)")

            if len(unique_macs) > 1:
                print(f"  ⚠️  WARNING: Multiple MACs assigned same IP (potential conflict)")

            # Show recent assignments
            recent = sorted(assignments, key=lambda x: x[1], reverse=True)[:3]
            print(f"  Recent assignments:")
            for mac, ts, msg_type in recent:
                time_str = self.format_timestamp(ts)
                print(f"    [{time_str}] {msg_type} to {mac}")

            print()

        print("="*80 + "\n")

    def do_retries(self, arg):
        """Find retransmission patterns and duplicate messages
        Usage: retries [mac_address]
        """
        print("\n" + "="*80)
        print("DHCP RETRANSMISSION ANALYSIS")
        print("="*80)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        # Group by MAC and XID
        sequences = defaultdict(lambda: defaultdict(list))
        for pkt in self.dhcp_packets:
            mac = pkt['client_mac']
            if mac_filter and mac_filter not in (mac or '').lower():
                continue
            xid = pkt['transaction_id']
            sequences[mac][xid].append(pkt)

        retries_found = False

        for mac in sorted(sequences.keys()):
            xid_groups = sequences[mac]

            mac_has_retries = False

            for xid, pkts in sorted(xid_groups.items()):
                pkts_sorted = sorted(pkts, key=lambda x: x['timestamp'])

                # Count message types
                msg_type_counts = Counter([p['message_type'] for p in pkts_sorted])

                # Check for retries (multiple messages of same type with same XID)
                discovers = [p for p in pkts_sorted if p['message_type'] == 1]
                requests = [p for p in pkts_sorted if p['message_type'] == 3]

                if len(discovers) > 1 or len(requests) > 1:
                    if not mac_has_retries:
                        print(f"\nMAC: {mac}")
                        print("-" * 80)
                        mac_has_retries = True
                        retries_found = True

                    print(f"\n  Transaction ID: 0x{xid:08x}")

                    if len(discovers) > 1:
                        print(f"  DISCOVER retries: {len(discovers)}")
                        for i, pkt in enumerate(discovers):
                            ts = self.format_timestamp(pkt['timestamp'])
                            if i > 0:
                                delta = pkt['timestamp'] - discovers[i-1]['timestamp']
                                print(f"    #{i+1}: [{ts}] (retry after {delta:.3f}s)")
                            else:
                                print(f"    #{i+1}: [{ts}] (initial)")

                    if len(requests) > 1:
                        print(f"  REQUEST retries: {len(requests)}")
                        for i, pkt in enumerate(requests):
                            ts = self.format_timestamp(pkt['timestamp'])
                            if i > 0:
                                delta = pkt['timestamp'] - requests[i-1]['timestamp']
                                print(f"    #{i+1}: [{ts}] (retry after {delta:.3f}s)")
                            else:
                                print(f"    #{i+1}: [{ts}] (initial)")

        if not retries_found:
            print("\nNo retransmissions detected")

        print("\n" + "="*80 + "\n")

    def do_options(self, arg):
        """Parse and display DHCP options
        Usage: options [mac_address]
        """
        print("\n" + "="*80)
        print("DHCP OPTIONS ANALYSIS")
        print("="*80)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        packets_to_analyze = self.dhcp_packets
        if mac_filter:
            packets_to_analyze = [p for p in packets_to_analyze
                                 if mac_filter in (p['client_mac'] or '').lower()]

        if not packets_to_analyze:
            print("\nNo packets found")
            print("="*80 + "\n")
            return

        print(f"\nAnalyzing {len(packets_to_analyze)} packet(s)\n")

        # Collect options from packets
        options_by_type = defaultdict(lambda: defaultdict(set))

        for pkt_info in packets_to_analyze:
            pkt = pkt_info['packet']
            msg_type_name = pkt_info['message_type_name']

            if DHCP in pkt:
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple):
                        opt_name = opt[0]
                        opt_value = opt[1]

                        # Skip message-type as it's already displayed
                        if opt_name == 'message-type':
                            continue

                        # Format value for display
                        if isinstance(opt_value, bytes):
                            opt_value = opt_value.hex(':')
                        elif isinstance(opt_value, list):
                            opt_value = ', '.join(str(v) for v in opt_value)

                        options_by_type[msg_type_name][opt_name].add(str(opt_value))

        # Display options grouped by message type
        for msg_type in sorted(options_by_type.keys()):
            options = options_by_type[msg_type]

            print(f"\n{msg_type} Messages:")
            print("-" * 80)

            for opt_name in sorted(options.keys()):
                values = options[opt_name]
                if len(values) == 1:
                    print(f"  {opt_name:30s}: {list(values)[0]}")
                else:
                    print(f"  {opt_name:30s}: (multiple values)")
                    for val in sorted(values):
                        print(f"    - {val}")

        print("\n" + "="*80 + "\n")

    def do_conflicts(self, arg):
        """Detect IP address conflicts
        Usage: conflicts
        """
        print("\n" + "="*80)
        print("IP ADDRESS CONFLICT DETECTION")
        print("="*80)

        # Collect IP assignments with timestamps
        ip_to_macs = defaultdict(list)  # ip -> [(mac, timestamp, msg_type)]

        for pkt in self.dhcp_packets:
            if pkt['message_type'] in [2, 5]:  # OFFER or ACK
                ip = pkt['your_ip']
                mac = pkt['client_mac']
                if ip and ip != '0.0.0.0' and mac:
                    msg_type = 'OFFER' if pkt['message_type'] == 2 else 'ACK'
                    ip_to_macs[ip].append((mac, pkt['timestamp'], msg_type))

        # Find DECLINE messages (indicate conflict detection by client)
        declines = [p for p in self.dhcp_packets if p['message_type'] == 4]

        # Check for conflicts
        conflicts_found = False

        # Check for same IP to multiple MACs
        print("\nChecking for IPs assigned to multiple MACs...\n")
        for ip in sorted(ip_to_macs.keys(), key=lambda x: tuple(map(int, x.split('.')))):
            assignments = ip_to_macs[ip]
            unique_macs = set([a[0] for a in assignments])

            if len(unique_macs) > 1:
                conflicts_found = True
                print(f"⚠️  CONFLICT DETECTED: IP {ip}")
                print(f"   Assigned to {len(unique_macs)} different MACs:")

                for mac in sorted(unique_macs):
                    mac_assignments = [a for a in assignments if a[0] == mac]
                    latest = max(mac_assignments, key=lambda x: x[1])
                    time_str = self.format_timestamp(latest[1])
                    print(f"   - {mac}: {len(mac_assignments)} times (last: {latest[2]} at {time_str})")

                print()

        if not conflicts_found:
            print("  No IP conflicts detected (no IP assigned to multiple MACs)")

        # Check for DECLINE messages
        if declines:
            print(f"\nDECLINE messages detected ({len(declines)}):")
            print("(Client detected IP conflict and declined the offer)\n")

            for decline in declines:
                ts = self.format_timestamp(decline['timestamp'])
                mac = decline['client_mac']
                ip = decline['client_ip'] or decline['your_ip'] or 'N/A'
                print(f"  [{ts}] MAC: {mac} declined IP: {ip}")

            conflicts_found = True
        else:
            print("\n  No DECLINE messages found")

        if not conflicts_found:
            print("\n✓ No conflicts detected")

        print("\n" + "="*80 + "\n")

    def do_duplicates(self, arg):
        """Detect duplicate server responses (same XID, close timing)
        Usage: duplicates [time_threshold_ms]
        Default: 1000ms (1 second)
        """
        time_threshold = 1.0  # seconds

        args = arg.strip().split()
        if len(args) >= 1:
            try:
                time_threshold = float(args[0]) / 1000.0  # convert ms to seconds
            except ValueError:
                print("Invalid time threshold, using default (1000ms)")

        print("\n" + "="*80)
        print(f"DUPLICATE DHCP RESPONSE DETECTION (within {time_threshold*1000:.0f}ms)")
        print("="*80)

        # Group by transaction ID and message type
        xid_groups = defaultdict(list)
        for pkt in self.dhcp_packets:
            if pkt['message_type'] in [2, 5, 6]:  # OFFER, ACK, NAK
                key = (pkt['transaction_id'], pkt['message_type'])
                xid_groups[key].append(pkt)

        duplicates_found = False
        total_duplicates = 0

        for (xid, msg_type), pkts in sorted(xid_groups.items()):
            if len(pkts) < 2:
                continue

            # Sort by timestamp
            pkts_sorted = sorted(pkts, key=lambda x: x['timestamp'])

            # Check for duplicates within time threshold
            for i in range(len(pkts_sorted) - 1):
                time_delta = pkts_sorted[i+1]['timestamp'] - pkts_sorted[i]['timestamp']

                if time_delta <= time_threshold:
                    if not duplicates_found:
                        duplicates_found = True

                    total_duplicates += 1
                    msg_type_name = DHCP_MESSAGE_TYPES.get(msg_type, 'UNKNOWN')

                    print(f"\n⚠️  DUPLICATE {msg_type_name} DETECTED")
                    print(f"Transaction ID: 0x{xid:08x}")
                    print(f"Time between duplicates: {time_delta*1000:.3f}ms")
                    print(f"Client MAC: {pkts_sorted[i]['client_mac']}")
                    print()

                    # Show details of duplicate packets
                    for idx, pkt in enumerate([pkts_sorted[i], pkts_sorted[i+1]], 1):
                        ts = self.format_timestamp(pkt['timestamp'])
                        ip_id = pkt.get('ip_id', 'N/A')
                        ip_flags = pkt.get('ip_flags', 'N/A')
                        chksum = pkt.get('udp_chksum', 'N/A')

                        print(f"  Packet #{idx} (pkt index {pkt['index']}):")
                        print(f"    Timestamp: {ts}")
                        print(f"    Source: {pkt['src_ip']} -> Dest: {pkt['dst_ip']}")
                        print(f"    IP ID: {ip_id}, IP Flags: {ip_flags}")
                        print(f"    UDP Checksum: 0x{chksum:04x}" if isinstance(chksum, int) else f"    UDP Checksum: {chksum}")
                        print(f"    Your IP: {pkt['your_ip']}")
                    print()

        if not duplicates_found:
            print("\nNo duplicate responses detected")
        else:
            print(f"\nTotal duplicate response pairs found: {total_duplicates}")

        print("="*80 + "\n")

    def do_checksums(self, arg):
        """Analyze UDP checksum issues
        Usage: checksums
        """
        print("\n" + "="*80)
        print("UDP CHECKSUM ANALYSIS")
        print("="*80)

        # Count packets by checksum status
        total_packets = len(self.dhcp_packets)
        checksum_issues = []
        zero_checksums = 0

        print("\nAnalyzing UDP checksums (this may take a moment)...\n")

        for pkt_info in self.dhcp_packets:
            pkt = pkt_info['packet']
            if UDP in pkt:
                try:
                    # Store original checksum
                    original_chksum = pkt[UDP].chksum

                    # Skip packets with checksum 0 (checksum disabled)
                    if original_chksum == 0:
                        zero_checksums += 1
                        continue

                    # Create a copy to avoid modifying original
                    from scapy.all import Raw
                    pkt_copy = pkt.copy()

                    # Delete checksum to force recalculation
                    if UDP in pkt_copy:
                        del pkt_copy[UDP].chksum
                        if IP in pkt_copy:
                            del pkt_copy[IP].chksum

                        # Rebuild packet to recalculate checksum
                        pkt_rebuilt = pkt_copy.__class__(bytes(pkt_copy))

                        if UDP in pkt_rebuilt:
                            calculated_chksum = pkt_rebuilt[UDP].chksum

                            # Compare checksums
                            if calculated_chksum and original_chksum != calculated_chksum:
                                checksum_issues.append({
                                    'pkt_info': pkt_info,
                                    'original': original_chksum,
                                    'calculated': calculated_chksum
                                })
                except Exception as e:
                    # Skip packets that cause issues during recalculation
                    pass

        print(f"Total DHCP packets analyzed: {total_packets}")
        print(f"Packets with checksum = 0 (disabled): {zero_checksums}")
        print(f"Packets with checksum mismatches: {len(checksum_issues)}")

        if checksum_issues:
            print("\n⚠️  Packets with BAD checksums detected!\n")
            print("These packets have UDP checksum corruption, likely due to:")
            print("  • Hardware checksum offloading bugs")
            print("  • Router firmware issues")
            print("  • Network interface card problems\n")

            # Categorize by origin (server vs client)
            server_bad = []
            client_bad = []
            unknown_origin = []

            for issue in checksum_issues:
                pkt_info = issue['pkt_info']
                msg_type = pkt_info['message_type']
                src_ip = pkt_info['src_ip']

                # Determine origin based on message type (most reliable)
                # Server → Client: OFFER (2), ACK (5), NAK (6)
                # Client → Server: DISCOVER (1), REQUEST (3), DECLINE (4), RELEASE (7), INFORM (8)
                if msg_type in [2, 5, 6]:  # Server messages
                    server_bad.append(issue)
                elif msg_type in [1, 3, 4, 7, 8]:  # Client messages
                    client_bad.append(issue)
                else:
                    unknown_origin.append(issue)

            print(f"📊 CHECKSUM ISSUES BY ORIGIN:\n")
            print(f"  Server → Client: {len(server_bad)} packets ({len(server_bad)/len(checksum_issues)*100:.1f}%)")
            print(f"  Client → Server: {len(client_bad)} packets ({len(client_bad)/len(checksum_issues)*100:.1f}%)")
            if unknown_origin:
                print(f"  Unknown origin:  {len(unknown_origin)} packets\n")
            else:
                print()

            # Show server-originated bad checksums
            if server_bad:
                print(f"⚠️  SERVER-ORIGINATED BAD CHECKSUMS ({len(server_bad)} packets):\n")
                print("These packets were sent BY the DHCP server (192.168.88.1)")
                print("This indicates a router/server firmware or hardware issue.\n")

                display_count = min(len(server_bad), 10)
                for issue in server_bad[:display_count]:
                    pkt_info = issue['pkt_info']
                    ts = self.format_timestamp(pkt_info['timestamp'])
                    msg_type = pkt_info['message_type_name']

                    print(f"  Packet #{pkt_info['index']} [{ts}] {msg_type}")
                    print(f"    Direction: SERVER → Client")
                    print(f"    Server IP: {pkt_info['src_ip']} (port 67)")
                    print(f"    Client IP: {pkt_info['dst_ip']} (port 68)")
                    print(f"    Original checksum:   0x{issue['original']:04x}")
                    print(f"    Calculated checksum: 0x{issue['calculated']:04x}")
                    print(f"    Transaction ID: 0x{pkt_info['transaction_id']:08x}")
                    print()

                if len(server_bad) > display_count:
                    print(f"  ... and {len(server_bad) - display_count} more server packets with bad checksums\n")

            # Show client-originated bad checksums
            if client_bad:
                print(f"⚠️  CLIENT-ORIGINATED BAD CHECKSUMS ({len(client_bad)} packets):\n")
                print("These packets were sent BY DHCP clients")
                print("This may indicate client NIC issues or client-side bugs.\n")

                display_count = min(len(client_bad), 10)
                for issue in client_bad[:display_count]:
                    pkt_info = issue['pkt_info']
                    ts = self.format_timestamp(pkt_info['timestamp'])
                    msg_type = pkt_info['message_type_name']
                    client_mac = pkt_info['client_mac']

                    print(f"  Packet #{pkt_info['index']} [{ts}] {msg_type}")
                    print(f"    Direction: Client → SERVER")
                    print(f"    Client MAC: {client_mac}")
                    print(f"    Client IP: {pkt_info['src_ip']} (port 68)")
                    print(f"    Server IP: {pkt_info['dst_ip']} (port 67)")
                    print(f"    Original checksum:   0x{issue['original']:04x}")
                    print(f"    Calculated checksum: 0x{issue['calculated']:04x}")
                    print(f"    Transaction ID: 0x{pkt_info['transaction_id']:08x}")
                    print()

                if len(client_bad) > display_count:
                    print(f"  ... and {len(client_bad) - display_count} more client packets with bad checksums\n")

            # Analyze pattern by message type
            print("📋 BREAKDOWN BY MESSAGE TYPE:\n")
            bad_msg_types = Counter([issue['pkt_info']['message_type_name'] for issue in checksum_issues])
            for msg_type, count in bad_msg_types.most_common():
                percentage = (count / len(checksum_issues)) * 100

                # Determine if server or client message
                if msg_type in ['OFFER', 'ACK', 'NAK']:
                    origin = "Server → Client"
                elif msg_type in ['DISCOVER', 'REQUEST', 'DECLINE', 'RELEASE', 'INFORM']:
                    origin = "Client → Server"
                else:
                    origin = "Unknown"

                print(f"  {msg_type:10s}: {count:4d} packets ({percentage:5.1f}%) [{origin}]")

            # Conclusion
            print(f"\n💡 DIAGNOSIS:\n")
            if len(server_bad) > len(client_bad) * 2:
                print(f"  PRIMARY ISSUE: DHCP Server (router) hardware/firmware bug")
                print(f"  • {len(server_bad)} bad checksums from server vs {len(client_bad)} from clients")
                print(f"  • Likely hardware checksum offloading issue in router")
                print(f"  • Recommendation: Update router firmware or disable offloading")
            elif len(client_bad) > len(server_bad) * 2:
                print(f"  PRIMARY ISSUE: Client-side network interface issues")
                print(f"  • {len(client_bad)} bad checksums from clients vs {len(server_bad)} from server")
                print(f"  • Check client network adapters")
                print(f"  • May indicate faulty NICs or driver issues")
            else:
                print(f"  MIXED ISSUE: Both server and clients have checksum problems")
                print(f"  • Server: {len(server_bad)} packets")
                print(f"  • Clients: {len(client_bad)} packets")
                print(f"  • May indicate network infrastructure issues")

        else:
            print("\n✓ All checksums are valid (or disabled)")

        print("\n" + "="*80 + "\n")

    def do_vendor(self, arg):
        """Analyze vendor-specific DHCP options (60, 125)
        Usage: vendor [mac_address]
        """
        print("\n" + "="*80)
        print("VENDOR-SPECIFIC OPTIONS ANALYSIS")
        print("="*80)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        packets_to_analyze = self.dhcp_packets
        if mac_filter:
            packets_to_analyze = [p for p in packets_to_analyze
                                 if mac_filter in (p['client_mac'] or '').lower()]

        # Collect vendor information
        vendor_class_ids = defaultdict(set)  # Option 60
        vendor_specific = defaultdict(list)  # Option 125
        hostnames = defaultdict(set)

        for pkt_info in packets_to_analyze:
            pkt = pkt_info['packet']
            mac = pkt_info['client_mac']

            if DHCP in pkt:
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple):
                        opt_name = opt[0]
                        opt_value = opt[1]

                        if opt_name == 'vendor_class_id':  # Option 60
                            if isinstance(opt_value, bytes):
                                vendor_class_ids[mac].add(opt_value.decode('utf-8', errors='ignore'))
                            else:
                                vendor_class_ids[mac].add(str(opt_value))

                        elif opt_name == 'vendor_specific':  # Option 125
                            if isinstance(opt_value, bytes):
                                vendor_specific[mac].append({
                                    'raw': opt_value.hex(':'),
                                    'decoded': opt_value.decode('utf-8', errors='ignore'),
                                    'timestamp': pkt_info['timestamp'],
                                    'msg_type': pkt_info['message_type_name']
                                })

                        elif opt_name == 'hostname':  # Option 12
                            if isinstance(opt_value, bytes):
                                hostnames[mac].add(opt_value.decode('utf-8', errors='ignore'))
                            else:
                                hostnames[mac].add(str(opt_value))

        # Display results
        if not vendor_class_ids and not vendor_specific and not hostnames:
            print("\nNo vendor-specific options found")
            print("="*80 + "\n")
            return

        print(f"\nAnalyzing {len(packets_to_analyze)} packet(s)\n")

        # Get all unique MACs
        all_macs = set(vendor_class_ids.keys()) | set(vendor_specific.keys()) | set(hostnames.keys())

        for mac in sorted(all_macs):
            print(f"\nMAC: {mac}")
            print("-" * 80)

            if mac in hostnames:
                print(f"  Hostname(s): {', '.join(sorted(hostnames[mac]))}")

            if mac in vendor_class_ids:
                print(f"  Vendor Class ID (Option 60):")
                for vcid in sorted(vendor_class_ids[mac]):
                    print(f"    - {vcid}")

            if mac in vendor_specific:
                print(f"  Vendor-Specific Info (Option 125):")
                for vs in vendor_specific[mac][:5]:  # Show first 5
                    print(f"    [{vs['msg_type']}] Decoded: {vs['decoded']}")
                    print(f"    [{vs['msg_type']}] Raw Hex: {vs['raw']}")
                if len(vendor_specific[mac]) > 5:
                    print(f"    ... and {len(vendor_specific[mac]) - 5} more")

            print()

        print("="*80 + "\n")

    def do_renewals(self, arg):
        """Analyze DHCP renewal patterns vs lease times
        Usage: renewals [mac_address]
        """
        print("\n" + "="*80)
        print("DHCP RENEWAL PATTERN ANALYSIS")
        print("="*80)

        # Filter by MAC if provided
        mac_filter = None
        if arg.strip():
            mac_filter = arg.strip().lower()
            print(f"\nFiltered by MAC: {mac_filter}")

        # Collect renewal information per MAC
        mac_renewals = defaultdict(lambda: {'requests': [], 'lease_time': None})

        for pkt_info in self.dhcp_packets:
            mac = pkt_info['client_mac']
            if mac_filter and mac_filter not in (mac or '').lower():
                continue

            # Track REQUEST messages (renewals)
            if pkt_info['message_type'] == 3:  # REQUEST
                mac_renewals[mac]['requests'].append(pkt_info['timestamp'])

            # Extract lease time from ACK messages
            if pkt_info['message_type'] == 5:  # ACK
                pkt = pkt_info['packet']
                if DHCP in pkt:
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == 'lease_time':
                            mac_renewals[mac]['lease_time'] = opt[1]
                            break

        if not mac_renewals:
            print("\nNo renewal data found")
            print("="*80 + "\n")
            return

        print(f"\nAnalyzing renewal patterns for {len(mac_renewals)} MAC(s)\n")

        for mac in sorted(mac_renewals.keys()):
            data = mac_renewals[mac]
            requests = sorted(data['requests'])
            lease_time = data['lease_time']

            if len(requests) < 2:
                continue

            print(f"\nMAC: {mac}")
            print("-" * 80)

            # Calculate intervals between requests
            intervals = []
            for i in range(1, len(requests)):
                interval = requests[i] - requests[i-1]
                intervals.append(interval)

            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                min_interval = min(intervals)
                max_interval = max(intervals)

                print(f"  Total renewal requests: {len(requests)}")
                print(f"  Average renewal interval: {avg_interval:.1f}s ({avg_interval/60:.1f} minutes)")
                print(f"  Min interval: {min_interval:.1f}s")
                print(f"  Max interval: {max_interval:.1f}s")

                if lease_time:
                    print(f"  Lease time from server: {lease_time}s ({lease_time/3600:.1f} hours)")

                    # Calculate expected renewal times (typically T1 = 50% of lease, T2 = 87.5%)
                    expected_t1 = lease_time * 0.5
                    expected_t2 = lease_time * 0.875

                    print(f"  Expected T1 (50% of lease): {expected_t1:.1f}s ({expected_t1/3600:.1f} hours)")
                    print(f"  Expected T2 (87.5% of lease): {expected_t2:.1f}s ({expected_t2/3600:.1f} hours)")

                    # Check if renewal interval is suspicious
                    if avg_interval < lease_time * 0.01:  # Less than 1% of lease time
                        print(f"  ⚠️  WARNING: Renewal interval ({avg_interval:.1f}s) is abnormally short!")
                        print(f"      Expected around {expected_t1:.1f}s, got {avg_interval:.1f}s")
                        print(f"      This is {(expected_t1/avg_interval):.0f}x more frequent than expected!")
                else:
                    print(f"  Lease time: Not captured in this trace")

                # Show some sample intervals
                print(f"  Sample renewal intervals:")
                for i, interval in enumerate(intervals[:5], 1):
                    print(f"    Renewal #{i}: {interval:.1f}s after previous")
                if len(intervals) > 5:
                    print(f"    ... and {len(intervals) - 5} more renewals")

        print("\n" + "="*80 + "\n")

    def do_ratios(self, arg):
        """Analyze request/reply ratios for anomaly detection
        Usage: ratios
        """
        print("\n" + "="*80)
        print("REQUEST/REPLY RATIO ANALYSIS")
        print("="*80)

        # Count message types
        discovers = sum(1 for p in self.dhcp_packets if p['message_type'] == 1)
        offers = sum(1 for p in self.dhcp_packets if p['message_type'] == 2)
        requests = sum(1 for p in self.dhcp_packets if p['message_type'] == 3)
        acks = sum(1 for p in self.dhcp_packets if p['message_type'] == 5)
        naks = sum(1 for p in self.dhcp_packets if p['message_type'] == 6)

        print(f"\nMessage Counts:")
        print(f"  DISCOVERs:  {discovers:4d}")
        print(f"  OFFERs:     {offers:4d}")
        print(f"  REQUESTs:   {requests:4d}")
        print(f"  ACKs:       {acks:4d}")
        print(f"  NAKs:       {naks:4d}")

        print(f"\nRatio Analysis:")

        # DISCOVER to OFFER ratio
        if discovers > 0:
            ratio = offers / discovers
            print(f"  OFFER/DISCOVER ratio: {ratio:.2f}")
            if ratio < 0.9:
                print(f"    ⚠️  Low ratio! Some DISCOVERs not getting OFFERs")
            elif ratio > 1.1:
                print(f"    ⚠️  High ratio! Multiple servers or duplicate OFFERs")
            else:
                print(f"    ✓  Normal ratio")

        # REQUEST to ACK ratio
        total_requests = discovers + requests
        total_acks = acks
        if total_requests > 0:
            ratio = total_acks / total_requests
            print(f"  ACK/REQUEST ratio: {ratio:.2f}")
            if ratio < 0.9:
                print(f"    ⚠️  Low ratio! Some REQUESTs not getting ACKs")
            elif ratio > 1.1:
                print(f"    ⚠️  High ratio ({ratio:.2f})! Duplicate ACKs detected!")
                duplicates = total_acks - total_requests
                print(f"    Estimated duplicate ACKs: ~{duplicates}")
                print(f"    This suggests the DHCP server is sending multiple ACKs per request")
            else:
                print(f"    ✓  Normal ratio")

        # Check for REQUEST without DISCOVER (renewals)
        if requests > discovers:
            renewals = requests - discovers
            print(f"\nRenewal Activity:")
            print(f"  REQUESTs without DISCOVER: {renewals}")
            print(f"  (These are likely lease renewals)")
            if renewals > discovers * 2:
                print(f"    ⚠️  High renewal activity detected!")

        print("\n" + "="*80 + "\n")

    def do_transaction(self, arg):
        """Show detailed view of a specific transaction
        Usage: transaction <xid_hex>
        Example: transaction fe07547a
        """
        if not arg.strip():
            print("Usage: transaction <xid_hex>")
            print("Example: transaction fe07547a")
            return

        # Parse XID
        try:
            xid_str = arg.strip().lower().replace('0x', '')
            xid = int(xid_str, 16)
        except ValueError:
            print(f"Invalid transaction ID: {arg}")
            print("Please provide a hexadecimal value (e.g., fe07547a)")
            return

        print("\n" + "="*80)
        print(f"TRANSACTION DETAILS - XID: 0x{xid:08x}")
        print("="*80)

        # Find all packets with this XID
        matching_pkts = [p for p in self.dhcp_packets if p['transaction_id'] == xid]

        if not matching_pkts:
            print(f"\nNo packets found with transaction ID 0x{xid:08x}")
            print("="*80 + "\n")
            return

        # Sort by timestamp
        matching_pkts.sort(key=lambda x: x['timestamp'])

        print(f"\nFound {len(matching_pkts)} packet(s) in this transaction")
        print(f"Client MAC: {matching_pkts[0]['client_mac']}\n")

        # Display each packet in detail
        for idx, pkt_info in enumerate(matching_pkts, 1):
            ts = self.format_timestamp(pkt_info['timestamp'])
            msg_type = pkt_info['message_type_name']

            print(f"Packet #{idx} - {msg_type}")
            print(f"{'─'*80}")
            print(f"  Timestamp:       {ts}")
            print(f"  Packet Index:    #{pkt_info['index']}")
            print(f"  Source:          {pkt_info['src_ip']}:{67 if pkt_info['message_type'] in [2,5,6] else 68}")
            print(f"  Destination:     {pkt_info['dst_ip']}:{68 if pkt_info['message_type'] in [2,5,6] else 67}")
            print(f"  Client IP:       {pkt_info['client_ip']}")
            print(f"  Your IP:         {pkt_info['your_ip']}")
            print(f"  Server IP:       {pkt_info['server_ip']}")

            # Show IP and UDP details
            ip_id = pkt_info.get('ip_id', 'N/A')
            ip_flags = pkt_info.get('ip_flags', 'N/A')
            udp_chksum = pkt_info.get('udp_chksum', 'N/A')

            print(f"  IP ID:           {ip_id}")
            print(f"  IP Flags:        {ip_flags}")
            if isinstance(udp_chksum, int):
                print(f"  UDP Checksum:    0x{udp_chksum:04x}")
            else:
                print(f"  UDP Checksum:    {udp_chksum}")

            # Show timing delta if not first packet
            if idx > 1:
                time_delta = pkt_info['timestamp'] - matching_pkts[idx-2]['timestamp']
                print(f"  Time from prev:  {time_delta*1000:.3f}ms")

            # Extract and show DHCP options
            pkt = pkt_info['packet']
            if DHCP in pkt:
                print(f"  DHCP Options:")
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple):
                        opt_name = opt[0]
                        opt_value = opt[1]

                        # Format value
                        if isinstance(opt_value, bytes):
                            if opt_name in ['vendor_class_id', 'hostname']:
                                opt_value = opt_value.decode('utf-8', errors='ignore')
                            else:
                                opt_value = opt_value.hex(':')
                        elif isinstance(opt_value, list):
                            opt_value = ', '.join(str(v) for v in opt_value)

                        # Special formatting for common options
                        if opt_name == 'lease_time':
                            print(f"    {opt_name:20s}: {opt_value}s ({opt_value/3600:.1f} hours)")
                        else:
                            value_str = str(opt_value)
                            if len(value_str) > 60:
                                value_str = value_str[:60] + "..."
                            print(f"    {opt_name:20s}: {value_str}")

            print()

        # Detect duplicate responses
        msg_type_counts = Counter([p['message_type'] for p in matching_pkts])
        if any(count > 1 for count in msg_type_counts.values()):
            print("⚠️  WARNING: Duplicate message types detected in this transaction!")
            for msg_type, count in msg_type_counts.items():
                if count > 1:
                    msg_name = DHCP_MESSAGE_TYPES.get(msg_type, 'UNKNOWN')
                    print(f"    {msg_name}: {count} occurrences")

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
            print("\n=== Overview & Statistics ===")
            print("summary              - Show overall DHCP packet summary with statistics")
            print("timings [mac]        - Analyze timing between DHCP messages")
            print("servers              - List all DHCP servers and their statistics")
            print("ips [mac]            - Show IP address assignments and usage")
            print("ratios               - Analyze request/reply ratios for anomalies")
            print("\n=== Packet Listing & Filtering ===")
            print("list [mac] [limit]   - List all DHCP packets in chronological order")
            print("list_mac [mac]       - List all DORA sequences grouped by MAC address")
            print("filter <mac>         - Show all packets for a specific MAC")
            print("transaction <xid>    - Show detailed view of a specific transaction")
            print("\n=== Problem Detection ===")
            print("naks [mac]           - Show all DHCP NAK messages")
            print("dor_nak [mac]        - Find DISCOVER-OFFER-REQUEST-NAK sequences")
            print("failed_dora [mac]    - Count failed DORA attempts per MAC")
            print("storms [time] [cnt]  - Detect DHCP storms (default: 10s, 10 msgs)")
            print("retries [mac]        - Find retransmission patterns")
            print("conflicts            - Detect IP address conflicts")
            print("duplicates [ms]      - Detect duplicate server responses (default: 1000ms)")
            print("checksums            - Analyze UDP checksum issues")
            print("\n=== Advanced Analysis ===")
            print("options [mac]        - Parse and display DHCP options")
            print("vendor [mac]         - Analyze vendor-specific DHCP options (60, 125)")
            print("renewals [mac]       - Analyze DHCP renewal patterns vs lease times")
            print("\n=== Help & Exit ===")
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
