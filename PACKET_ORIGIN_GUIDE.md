# DHCP Packet Origin Detection Guide

## How to Tell if Packets Come from Server or Client

### Method 1: Message Type (Most Reliable) ⭐

DHCP message types definitively indicate packet direction:

```
CLIENT → SERVER Messages:
  Type 1: DISCOVER  - Client looking for DHCP server
  Type 3: REQUEST   - Client requesting IP address
  Type 4: DECLINE   - Client declining offered IP
  Type 7: RELEASE   - Client releasing IP address
  Type 8: INFORM    - Client requesting configuration

SERVER → CLIENT Messages:
  Type 2: OFFER     - Server offering IP address
  Type 5: ACK       - Server acknowledging/confirming lease
  Type 6: NAK       - Server rejecting request
```

**Example from test1.pcap:**
```
Packet #95: ACK (Type 5) → Server → Client
  Source: 192.168.88.1:67
  Dest:   192.168.88.80:68
  ✓ This is definitely from the DHCP server
```

---

### Method 2: UDP Port Numbers

DHCP uses well-known ports:

```
Port 67: DHCP Server
Port 68: DHCP Client

Traffic Direction:
  Client → Server:  source port 68 → dest port 67
  Server → Client:  source port 67 → dest port 68
```

**Example:**
```
192.168.88.80:68 → 192.168.88.1:67   [Client sends REQUEST]
192.168.88.1:67  → 192.168.88.80:68  [Server sends ACK]
         ↑                     ↑
      Server port          Client port
```

---

### Method 3: IP Addresses

In your network (192.168.88.0/24):

```
DHCP Server: 192.168.88.1
Clients:     192.168.88.2 - 192.168.88.254

Traffic Pattern:
  Server → Client:  src_ip = 192.168.88.1
  Client → Server:  dst_ip = 192.168.88.1
```

**Caveat:** This only works when you know the server IP. In some networks, you may not know which device is the server initially.

---

### Method 4: BOOTP Fields

DHCP packets contain BOOTP fields that provide clues:

```
Field: yiaddr (Your IP Address)
  Server → Client: yiaddr = IP being assigned (e.g., 192.168.88.80)
  Client → Server: yiaddr = 0.0.0.0

Field: ciaddr (Client IP Address)
  During renewal:   ciaddr = client's current IP
  During discovery: ciaddr = 0.0.0.0

Field: siaddr (Server IP Address)
  Server → Client: May be set to server IP
  Client → Server: Usually 0.0.0.0
```

---

## Real Example: Bad Checksum Analysis

### From test1.pcap

```
================================================================================
Packet #95 with BAD CHECKSUM
================================================================================

Message Type: ACK (5)                    → Server → Client ✓
Source:       192.168.88.1:67            → Server port ✓
Destination:  192.168.88.80:68           → Client port ✓
Your IP:      192.168.88.80              → Server assigning IP ✓

Original checksum:   0x33e0
Calculated checksum: 0xee36
Difference: Bad checksum!

CONCLUSION: This packet originated from DHCP SERVER (192.168.88.1)
ISSUE: Router hardware/firmware bug causing checksum corruption
```

---

## Enhanced Checksums Command Output

The enhanced `checksums` command now categorizes all bad checksums by origin:

```bash
./dhcp_interactive.py test1.pcap
dhcp> checksums
```

### Output:
```
📊 CHECKSUM ISSUES BY ORIGIN:

  Server → Client: 528 packets (100.0%)
  Client → Server: 0 packets (0.0%)

⚠️  SERVER-ORIGINATED BAD CHECKSUMS (528 packets):

These packets were sent BY the DHCP server (192.168.88.1)
This indicates a router/server firmware or hardware issue.

  Packet #95 [2026-01-06 00:45:53.789] ACK
    Direction: SERVER → Client
    Server IP: 192.168.88.1 (port 67)
    Client IP: 192.168.88.80 (port 68)
    Original checksum:   0x33e0
    Calculated checksum: 0xee36
    Transaction ID: 0xfe07547a

📋 BREAKDOWN BY MESSAGE TYPE:

  ACK       :  518 packets ( 98.1%) [Server → Client]
  OFFER     :   10 packets (  1.9%) [Server → Client]

💡 DIAGNOSIS:

  PRIMARY ISSUE: DHCP Server (router) hardware/firmware bug
  • 528 bad checksums from server vs 0 from clients
  • Likely hardware checksum offloading issue in router
  • Recommendation: Update router firmware or disable offloading
```

---

## Key Findings from test1.pcap

### Checksum Corruption Analysis

**100% of bad checksums originate from the DHCP server!**

| Origin | Bad Checksums | Percentage |
|--------|---------------|------------|
| Server (192.168.88.1) | 528 | 100.0% |
| Clients | 0 | 0.0% |

**Message Type Breakdown:**
- ACK packets: 518 (98.1%)
- OFFER packets: 10 (1.9%)

**Pattern:**
- All bad checksums are in server → client direction
- Primarily affects ACK responses
- Occurs in first ACK of each duplicate pair
- Second ACK has correct checksum

---

## Why This Matters

### Server-side Bad Checksums → Server Hardware/Firmware Bug

**Evidence:**
1. All 528 bad checksums are from server
2. Zero bad checksums from any client
3. Pattern consistent across all transactions
4. Always in first duplicate ACK

**Diagnosis:**
```
Router DHCP Server Bug:
├─ Hardware checksum offloading misconfiguration
├─ Packet duplication in transmission pipeline
├─ First packet: corrupted checksum (from offload bug)
└─ Second packet: correct checksum (recalculated)
```

**Impact on Clients:**
- Clients may reject first ACK (bad checksum)
- Accept second ACK (good checksum)
- May trigger network instability detection
- Could contribute to aggressive renewal behavior

---

## Troubleshooting Decision Tree

```
Bad checksum detected
         ↓
    Check origin?
         ↓
    ┌────┴────┐
    ↓         ↓
  Server    Client
    ↓         ↓
Router bug  NIC issue
    ↓         ↓
Update      Check
firmware    drivers
    ↓         ↓
Disable     Replace
HW offload  adapter
```

### If Server-Originated (Like test1.pcap):
1. Update router firmware
2. Check for known checksum issues
3. Try disabling hardware checksum offloading:
   ```bash
   ethtool -K eth0 tx off
   ethtool -K eth0 rx off
   ```
4. Consider replacing router if unfixable

### If Client-Originated:
1. Check client network adapter
2. Update NIC drivers
3. Disable hardware offloading on client
4. Test with different network cable
5. Replace NIC if faulty

---

## Advanced: Packet Capture Analysis

### Using tcpdump to verify:

```bash
# Show packets with source port 67 (server)
sudo tcpdump -r test1.pcap -n 'src port 67' | head -20

# Show packets with source port 68 (client)
sudo tcpdump -r test1.pcap -n 'src port 68' | head -20

# Show only ACK messages (server → client)
sudo tcpdump -r test1.pcap -n 'port 67 or port 68' -v | grep "DHCP-Message Option 53, length 1: ACK"
```

### Using Wireshark display filters:

```
Server → Client:  bootp.option.dhcp == 5  (ACK)
Client → Server:  bootp.option.dhcp == 3  (REQUEST)
Bad checksums:    udp.checksum.status == "Bad"
```

---

## Summary

**How to determine packet origin (in order of reliability):**

1. **Message Type** - Most reliable, built into DHCP protocol
2. **UDP Ports** - 67 (server) vs 68 (client)
3. **IP Addresses** - Source IP indicates sender
4. **BOOTP Fields** - yiaddr, ciaddr, siaddr provide context

**For test1.pcap:**
- **100% of bad checksums from server (192.168.88.1)**
- **0% from clients**
- **Clear router firmware/hardware bug**
- **Update router firmware recommended**

---

**Last Updated:** 2026-01-07
**Tool:** DHCP Debugging Toolkit v2.0
**Command:** `checksums` (enhanced with origin detection)
