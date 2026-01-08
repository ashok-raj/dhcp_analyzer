# ⚠️ SUPERSEDED ANALYSIS - DO NOT USE

**This document contains an INCORRECT analysis that has been superseded.**

**Please refer to: ICMP_PORT_UNREACHABLE_FINDING.md for the CORRECT analysis**

---

**What this document claimed**: TP-Link HB610V2 satellites were reflecting/relaying DHCP ACK packets back to the server.

**What was actually happening**: Satellites were sending ICMP Port Unreachable errors in response to duplicate DHCP ACKs. Scapy parsed the DHCP packets embedded in ICMP errors, making them appear as ACKs from satellites.

**Discovery date of error**: 2026-01-07
**Corrected analysis**: ICMP_PORT_UNREACHABLE_FINDING.md

---

## Original (Incorrect) Document Below

This document is preserved for historical context only.

---

# DHCP Packet Reflection Bug - TP-Link HB610V2

## Critical Discovery

The TP-Link HB610V2 devices are **reflecting/relaying DHCP ACK packets back to the server** - a serious firmware bug that explains the mysterious "8 DHCP servers."

## Summary

**What appears to be 8 DHCP servers is actually:**
- **1 real DHCP server:** 192.168.88.1 (MAC: 50:3d:d1:25:f5:39)
- **7 TP-Link clients acting as unintentional DHCP relays:**
  - 192.168.88.27 (HB610V2 - MAC: 78:20:51:71:1a:b9)
  - 192.168.88.58 (HB610V2 - MAC: 78:20:51:71:48:79)
  - 192.168.88.59 (HB610V2 - MAC: 78:20:51:70:f5:d1)
  - 192.168.88.78 (Unknown - MAC: f0:f6:c1:94:80:f0)
  - 192.168.88.79 (HB610V2 - MAC: 78:20:51:70:f8:81)
  - 192.168.88.80 (HB610V2 - MAC: 78:20:51:71:14:41)
  - 192.168.88.87 (HB610V2 - MAC: 78:20:51:71:1a:21)

---

## The Abnormal Behavior

### Normal DHCP Flow:

```
1. Client REQUEST:   192.168.88.80:68 → 192.168.88.1:67
2. Server ACK:       192.168.88.1:67  → 192.168.88.80:68
3. [DONE]
```

### TP-Link HB610V2 Actual Behavior:

```
1. Client REQUEST:   192.168.88.80:68 → 192.168.88.1:67
2. Server ACK #1:    192.168.88.1:67  → 192.168.88.80:68
3. Server ACK #2:    192.168.88.1:67  → 192.168.88.80:68  (duplicate from server)

4. ⚠️  Client REFLECTS ACK #1 back:
   Source:           192.168.88.80:67 → 192.168.88.1:68
   [Client using SERVER port 67!]

5. ⚠️  Client REFLECTS ACK #2 back:
   Source:           192.168.88.80:67 → 192.168.88.1:68
   [Client echoing duplicate too!]
```

---

## Packet Analysis - Transaction 0xfe07547a

### Packet Flow Timeline:

| Time | Pkt# | Type | Source | Dest | Direction | Normal? |
|------|------|------|--------|------|-----------|---------|
| 00:45:53.789 | #94 | REQUEST | 192.168.88.80:68 | 192.168.88.1:67 | Client→Server | ✓ |
| 00:45:53.789 | #95 | ACK | 192.168.88.1:67 | 192.168.88.80:68 | Server→Client | ✓ |
| 00:45:53.789 | #96 | ACK | 192.168.88.1:67 | 192.168.88.80:68 | Server→Client | ✓ Duplicate |
| 00:45:53.792 | **#97** | **ACK** | **192.168.88.80:67** | **192.168.88.1:68** | **Client→Server** | **✗ REFLECTED!** |
| 00:45:53.792 | **#98** | **ACK** | **192.168.88.80:67** | **192.168.88.1:68** | **Client→Server** | **✗ REFLECTED!** |

### Packet #97 Details (Reflected ACK):

```
Source:      192.168.88.80:67  ← Client IP with SERVER port!
Destination: 192.168.88.1:68   ← Server IP with CLIENT port!
Message:     ACK (Type 5)      ← Should only come from server!
Client IP:   192.168.88.80
Your IP:     192.168.88.80
XID:         0xfe07547a        ← Same transaction ID

This is the ACK the client received, being ECHOED back to the server!
```

---

## Evidence

### 1. Source MAC Matches Client MAC

All "reflected" ACKs have:
- **Source MAC = Client MAC** (not server MAC)
- This proves the packets originate from the client device, not the server

Example:
```
IP: 192.168.88.80
  Source MAC: 78:20:51:71:14:41  ← TP-Link HB610V2
  Client MAC: 78:20:51:71:14:41  ← Same!
  ⚠️  Source MAC matches client MAC (REFLECTED PACKET)
```

### 2. Port Reversal

Normal ACK: `Server:67 → Client:68`
Reflected:  `Client:67 → Server:68` ← Using wrong ports!

### 3. Packet Count Pattern

For transaction 0xfe07547a (192.168.88.80):
- Server sends: 2 ACKs (duplicates)
- Client reflects: 2 ACKs back
- **Total: 4 ACKs for one REQUEST!**

Across all clients:
- Server (192.168.88.1): 1,045 ACKs sent
- Clients reflected back: 979 ACKs (162+164+164+162+162+164+1)
- **Ratio: Almost 1:1 reflection rate!**

---

## Why This Happens

### Probable TP-Link Firmware Bug:

```c
// Pseudo-code of probable bug in HB610V2 firmware

void handle_dhcp_ack(dhcp_packet *ack) {
    // Process the ACK
    update_lease(ack);

    // BUG: Firmware thinks it should relay/forward the ACK
    // Perhaps leftover code from DHCP relay agent functionality?
    if (should_relay_dhcp_packets) {  // ← Bug: This shouldn't be true!
        // Swap source/dest to "forward" packet
        relay_packet(ack);  // ← This sends it back to server!
    }
}
```

### Possible Causes:

1. **DHCP Relay Agent Code Left Enabled**
   - HB610V2 may have DHCP relay functionality
   - Bug: It's enabled when it shouldn't be
   - Reflects packets back instead of forwarding

2. **Mesh/Bridge Misconfiguration**
   - Devices may be operating in mesh mode
   - Incorrectly bridging/relaying DHCP traffic
   - Not filtering out their own DHCP packets

3. **Firmware State Machine Bug**
   - Confusion between client mode and relay mode
   - Processes packet twice: once as client, once as relay
   - Second processing reflects it back

---

## Impact

### Network Traffic Amplification:

```
Normal DHCP exchange:
  Client REQUEST → Server ACK = 2 packets

With TP-Link bug:
  Client REQUEST → Server ACK (×2 duplicate) → Client reflects (×2) = 5 packets

Traffic amplification: 2.5x for each DHCP exchange
```

### Server Load:

- Server receives reflected ACKs from ALL clients
- ~979 reflected ACKs in 13-minute capture
- Server must process and likely discard these
- Additional CPU cycles wasted

### Confusion in Diagnostics:

- Makes it appear there are 8 DHCP servers
- Complicates network troubleshooting
- Hides the real server (192.168.88.1)

---

## Real vs Reflected Packets

### Real DHCP Server (192.168.88.1):

```
IP: 192.168.88.1
  Source MAC: 50:3d:d1:25:f5:39  ← Router/server MAC
  ACK count: 1,045
  Ports: 67 → 68                 ← Correct direction
  OFFERs: 24                     ← Only server sends OFFERs
  Direction: Normal (Server → Client)
```

### Reflected Packets (e.g., 192.168.88.80):

```
IP: 192.168.88.80
  Source MAC: 78:20:51:71:14:41  ← Client MAC (TP-Link)
  ACK count: 164
  Ports: 67 → 68                 ← WRONG! Client shouldn't use port 67
  OFFERs: 0                      ← Clients never send OFFERs
  Direction: REVERSED (Client → Server)
  ⚠️  Source MAC matches client MAC (REFLECTED PACKET)
```

---

## Verification

Run this to see the pattern yourself:

```bash
./dhcp_interactive.py test1.pcap
dhcp> transaction fe07547a
```

Look for ACK packets with:
- Source: 192.168.88.80:67 (client IP with server port)
- Dest: 192.168.88.1:68 (server IP with client port)

These are the reflected packets!

---

## Solutions

### 1. Update TP-Link Firmware (Primary Fix)

Contact TP-Link support about:
- HB610V2 firmware bug
- DHCP packet reflection issue
- Unnecessary DHCP relay behavior
- Request firmware update

### 2. Disable DHCP Relay (if configurable)

If accessible via TP-Link admin interface:
- Check for "DHCP Relay" settings
- Disable relay functionality
- Device should only be DHCP client

### 3. Network Segmentation

If firmware can't be fixed:
- Isolate TP-Link devices on separate VLAN
- Use firewall rules to block reflected packets:
  ```
  Block: src_ip=192.168.88.27-87 AND src_port=67
  ```

### 4. Replace Devices

If unfixable:
- Consider alternative hardware
- Look for devices without relay bugs
- Ensure DHCP client-only mode

---

## Additional Notes

### Device Identification:

Based on MAC addresses (OUI 78:20:51 = TP-Link):
- 6 confirmed HB610V2 devices
- 1 unknown device (f0:f6:c1:94:80:f0) also reflecting

All TP-Link devices exhibit identical reflection behavior.

### Why the Summary Command Showed 8 "Servers":

The `summary` command originally classified these as servers because:
1. They send ACK messages (type 5)
2. ACKs are normally only sent by servers
3. Code didn't check for port reversal

This has been identified and will be fixed to detect reflected packets.

---

## Recommended Actions

**IMMEDIATE:**
1. Document this finding for TP-Link support
2. Check if firmware updates available
3. Monitor network for impact

**SHORT TERM:**
4. Add firewall rules to block reflected packets
5. Test with firmware updates
6. Consider VLAN segmentation

**LONG TERM:**
7. Replace devices if firmware unfixable
8. Avoid TP-Link HB610V2 for DHCP-critical deployments
9. Test other TP-Link models for same bug

---

## Files Referenced

- test1.pcap - Source capture showing bug
- Transaction 0xfe07547a - Clear example of reflection
- MAC addresses 78:20:51:* - TP-Link HB610V2 devices

---

**Discovery Date:** 2026-01-07
**Affected Devices:** TP-Link HB610V2 (MAC OUI: 78:20:51)
**Firmware Version:** Unknown (should be documented for bug report)
**Severity:** Medium (causes traffic amplification and diagnostic confusion)
