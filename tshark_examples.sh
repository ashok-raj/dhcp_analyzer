#!/bin/bash
# Quick reference for tshark DHCP analysis commands

PCAP_FILE="capture.pcap"
MAC_ADDR="aa:bb:cc:dd:ee:ff"

echo "=== DHCP Analysis with tshark ==="
echo ""

# 1. Show all DHCP packets
echo "1. All DHCP packets:"
echo "tshark -r $PCAP_FILE -Y \"bootp\""
echo ""

# 2. Filter by client MAC address
echo "2. Filter by client MAC address:"
echo "tshark -r $PCAP_FILE -Y \"bootp.hw.mac_addr == $MAC_ADDR\""
echo ""

# 3. Find DHCP NAK messages
echo "3. Find DHCP NAK messages:"
echo "tshark -r $PCAP_FILE -Y \"bootp.option.dhcp == 6\""
echo ""

# 4. NAKs for specific MAC
echo "4. NAKs for specific MAC:"
echo "tshark -r $PCAP_FILE -Y \"bootp and bootp.hw.mac_addr == $MAC_ADDR and bootp.option.dhcp == 6\""
echo ""

# 5. Show DHCP message types
echo "5. Show all DHCP with message type:"
echo "tshark -r $PCAP_FILE -Y \"bootp\" -T fields -e frame.number -e frame.time -e bootp.hw.mac_addr -e ip.src -e ip.dst -e bootp.option.dhcp -E header=y"
echo ""

# 6. Count DHCP messages by type
echo "6. Count DHCP messages by type:"
echo "tshark -r $PCAP_FILE -Y \"bootp\" -T fields -e bootp.option.dhcp | sort | uniq -c"
echo ""

# 7. Export DHCP packets for specific MAC to new file
echo "7. Export DHCP packets for specific MAC:"
echo "tshark -r $PCAP_FILE -Y \"bootp.hw.mac_addr == $MAC_ADDR\" -w filtered_$MAC_ADDR.pcap"
echo ""

# 8. Show DISCOVER messages (potential storm source)
echo "8. Show DISCOVER messages:"
echo "tshark -r $PCAP_FILE -Y \"bootp.option.dhcp == 1\""
echo ""

# 9. Show REQUEST messages
echo "9. Show REQUEST messages:"
echo "tshark -r $PCAP_FILE -Y \"bootp.option.dhcp == 3\""
echo ""

# 10. Detailed packet view for specific MAC
echo "10. Detailed view for specific MAC:"
echo "tshark -r $PCAP_FILE -Y \"bootp.hw.mac_addr == $MAC_ADDR\" -V"
echo ""

echo "=== DHCP Message Type Reference ==="
echo "1 = DISCOVER"
echo "2 = OFFER"
echo "3 = REQUEST"
echo "4 = DECLINE"
echo "5 = ACK"
echo "6 = NAK"
echo "7 = RELEASE"
echo "8 = INFORM"
