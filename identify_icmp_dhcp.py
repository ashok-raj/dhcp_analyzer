#!/usr/bin/env python3
"""
Utility to distinguish real DHCP packets from DHCP packets embedded in ICMP errors.

This addresses the issue where scapy parses DHCP from ICMP Port Unreachable messages,
making them appear as DHCP packets with source IPs from the device sending the ICMP error.
"""

import sys
from scapy.all import rdpcap, DHCP, BOOTP, UDP, IP, Ether, ICMP

def analyze_dhcp_packets(pcap_file):
    """Analyze DHCP packets and separate real DHCP from ICMP-embedded DHCP."""

    packets = rdpcap(pcap_file)

    real_dhcp = []
    icmp_embedded_dhcp = []

    for pkt in packets:
        if DHCP in pkt and BOOTP in pkt:
            # Check if this is embedded in ICMP
            if ICMP in pkt:
                # This DHCP packet is inside an ICMP error
                icmp_embedded_dhcp.append(pkt)
            else:
                # This is a real DHCP packet
                real_dhcp.append(pkt)

    return real_dhcp, icmp_embedded_dhcp

def print_analysis(real_dhcp, icmp_embedded_dhcp):
    """Print analysis of DHCP packets."""

    print("DHCP PACKET CLASSIFICATION")
    print("="*80)

    print(f"\nReal DHCP packets: {len(real_dhcp)}")
    print(f"DHCP in ICMP errors: {len(icmp_embedded_dhcp)}")
    print(f"Total: {len(real_dhcp) + len(icmp_embedded_dhcp)}")

    # Analyze ICMP embedded DHCP
    if icmp_embedded_dhcp:
        print("\n" + "="*80)
        print("ICMP EMBEDDED DHCP ANALYSIS:")
        print("="*80)

        from collections import defaultdict
        icmp_by_src = defaultdict(list)

        for pkt in icmp_embedded_dhcp:
            src_ip = pkt[IP].src if IP in pkt else "Unknown"
            icmp_type = pkt[ICMP].type if ICMP in pkt else None
            icmp_code = pkt[ICMP].code if ICMP in pkt else None

            icmp_by_src[src_ip].append({
                'icmp_type': icmp_type,
                'icmp_code': icmp_code,
                'pkt': pkt
            })

        print(f"\nDevices sending ICMP errors containing DHCP: {len(icmp_by_src)}")
        for src_ip in sorted(icmp_by_src.keys()):
            errors = icmp_by_src[src_ip]
            sample = errors[0]

            icmp_type = sample['icmp_type']
            icmp_code = sample['icmp_code']

            # Decode ICMP type/code
            if icmp_type == 3:
                type_str = "Destination Unreachable"
                if icmp_code == 3:
                    code_str = "Port Unreachable"
                else:
                    code_str = f"Code {icmp_code}"
            else:
                type_str = f"Type {icmp_type}"
                code_str = f"Code {icmp_code}"

            print(f"\n  {src_ip}:")
            print(f"    ICMP errors: {len(errors)}")
            print(f"    ICMP type: {type_str}")
            print(f"    ICMP code: {code_str}")

            # Get DHCP message type from embedded packet
            dhcp_msg_types = defaultdict(int)
            for error in errors:
                pkt = error['pkt']
                if DHCP in pkt:
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == 'message-type':
                            msg_type = opt[1]
                            dhcp_msg_types[msg_type] += 1
                            break

            if dhcp_msg_types:
                print(f"    Embedded DHCP types:")
                type_names = {1:'DISCOVER', 2:'OFFER', 3:'REQUEST', 5:'ACK', 6:'NAK'}
                for msg_type, count in sorted(dhcp_msg_types.items()):
                    type_name = type_names.get(msg_type, f'Type{msg_type}')
                    print(f"      {type_name}: {count}")

    # Analyze real DHCP by source
    if real_dhcp:
        print("\n" + "="*80)
        print("REAL DHCP PACKET ANALYSIS:")
        print("="*80)

        from collections import defaultdict
        dhcp_by_src = defaultdict(lambda: defaultdict(int))

        for pkt in real_dhcp:
            src_ip = pkt[IP].src if IP in pkt else "Unknown"

            # Get message type
            msg_type = None
            if DHCP in pkt:
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type':
                        msg_type = opt[1]
                        break

            if msg_type:
                dhcp_by_src[src_ip][msg_type] += 1

        print(f"\nDevices sending real DHCP packets: {len(dhcp_by_src)}")
        for src_ip in sorted(dhcp_by_src.keys()):
            msg_counts = dhcp_by_src[src_ip]
            total = sum(msg_counts.values())

            print(f"\n  {src_ip}: {total} packets")

            type_names = {1:'DISCOVER', 2:'OFFER', 3:'REQUEST', 5:'ACK', 6:'NAK',
                         4:'DECLINE', 7:'RELEASE', 8:'INFORM'}

            for msg_type in sorted(msg_counts.keys()):
                count = msg_counts[msg_type]
                type_name = type_names.get(msg_type, f'Type{msg_type}')
                print(f"    {type_name}: {count}")

            # Identify role
            has_offers = 2 in msg_counts or 5 in msg_counts
            has_requests = 1 in msg_counts or 3 in msg_counts

            if has_offers and not has_requests:
                print(f"    → DHCP Server")
            elif has_requests and not has_offers:
                print(f"    → DHCP Client")
            elif has_offers and has_requests:
                print(f"    → Both Server and Client")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    print(f"Analyzing {pcap_file}...\n")

    real_dhcp, icmp_embedded_dhcp = analyze_dhcp_packets(pcap_file)
    print_analysis(real_dhcp, icmp_embedded_dhcp)

    print("\n" + "="*80)
    print("SUMMARY:")
    print("="*80)

    if icmp_embedded_dhcp:
        print("\n⚠️  WARNING: Found DHCP packets embedded in ICMP errors!")
        print("   These are NOT actual DHCP packets being sent.")
        print("   They are ICMP error messages containing the original DHCP packet.")
        print("\n   See: ICMP_PORT_UNREACHABLE_FINDING.md for details")
    else:
        print("\n✓ No DHCP packets embedded in ICMP errors detected.")

    print()
