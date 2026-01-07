# Example DHCP Analysis Session

This document shows a real-world analysis of `test1.pcap` using the new diagnostic commands.

## Capture Overview

```
File: test1.pcap
Duration: 13.6 minutes (815 seconds)
Total Packets: 73,192
DHCP Packets: 2,628
```

## Step 1: Quick Ratio Check

```
dhcp> ratios
```

**Output:**
```
Message Counts:
  DISCOVERs:   14
  OFFERs:      24
  REQUESTs:   554
  ACKs:      2024
  NAKs:        12

Ratio Analysis:
  OFFER/DISCOVER ratio: 1.71
    ⚠️  High ratio! Multiple servers or duplicate OFFERs
  ACK/REQUEST ratio: 3.56
    ⚠️  High ratio (3.56)! Duplicate ACKs detected!
    Estimated duplicate ACKs: ~1456
    This suggests the DHCP server is sending multiple ACKs per request

Renewal Activity:
  REQUESTs without DISCOVER: 540
  (These are likely lease renewals)
    ⚠️  High renewal activity detected!
```

**🔍 Finding:** The ACK/REQUEST ratio of 3.56 is highly abnormal! This indicates the DHCP server is sending ~3-4 ACK responses for every REQUEST.

## Step 2: Detect Duplicate Responses

```
dhcp> duplicates
```

**Output (sample):**
```
⚠️  DUPLICATE ACK DETECTED
Transaction ID: 0xfe07547a
Time between duplicates: 0.055ms
Client MAC: 78:20:51:71:14:41

  Packet #1 (pkt index 95):
    Timestamp: 2026-01-06 00:45:53.789
    Source: 192.168.88.1 -> Dest: 192.168.88.80
    IP ID: 56183, IP Flags: DF
    UDP Checksum: 0x33e0
    Your IP: 192.168.88.80

  Packet #2 (pkt index 96):
    Timestamp: 2026-01-06 00:45:53.789
    Source: 192.168.88.1 -> Dest: 192.168.88.80
    IP ID: 43556, IP Flags:
    UDP Checksum: 0xee36
    Your IP: 192.168.88.80

Total duplicate response pairs found: 512
```

**🔍 Findings:**
- Server sends TWO ACK packets for every single REQUEST
- Packets have DIFFERENT IP IDs (56183 vs 43556)
- Packets have DIFFERENT UDP checksums (0x33e0 vs 0xee36)
- First packet has DF (Don't Fragment) flag set
- Second packet has no flags
- Time between duplicates: 55 microseconds

## Step 3: Analyze Specific Transaction

```
dhcp> transaction fe07547a
```

**Output:**
```
Found 3 packet(s) in this transaction
Client MAC: 78:20:51:71:14:41

Packet #1 - REQUEST
────────────────────────────────────────────────────────────────────────────────
  Timestamp:       2026-01-06 00:45:53.789
  Source:          192.168.88.80:68
  Destination:     192.168.88.1:67
  Client IP:       192.168.88.80
  Your IP:         0.0.0.0
  IP ID:           41477
  IP Flags:        DF
  UDP Checksum:    0x7a23
  DHCP Options:
    hostname            : HB610V2
    vendor_class_id     : TP-Link,dslforum.org
    lease_time          : 172800s (48.0 hours)

Packet #2 - ACK (First duplicate)
────────────────────────────────────────────────────────────────────────────────
  Timestamp:       2026-01-06 00:45:53.789
  Source:          192.168.88.1:67
  Destination:     192.168.88.80:68
  IP ID:           56183
  IP Flags:        DF
  UDP Checksum:    0x33e0    ⚠️ BAD CHECKSUM
  Time from prev:  0.394ms
  DHCP Options:
    lease_time          : 172800s (48.0 hours)

Packet #3 - ACK (Second duplicate)
────────────────────────────────────────────────────────────────────────────────
  Timestamp:       2026-01-06 00:45:53.789
  Source:          192.168.88.1:67
  Destination:     192.168.88.80:68
  IP ID:           43556
  IP Flags:
  UDP Checksum:    0xee36    ✓ GOOD CHECKSUM
  Time from prev:  0.055ms

⚠️  WARNING: Duplicate message types detected in this transaction!
    ACK: 2 occurrences
```

## Step 4: Check Vendor Information

```
dhcp> vendor
```

**Output:**
```
MAC: 78:20:51:71:14:41
  Hostname(s): HB610V2
  Vendor Class ID (Option 60):
    - TP-Link,dslforum.org
  Vendor-Specific Info (Option 125):
    [REQUEST] Decoded: 782051Y2572730006920HB610V2
    [ACK] Decoded: 503DD1Y2580330012730HB810
```

**🔍 Findings:**
- All devices are TP-Link HB610V2 devices
- Client sends vendor info: "Y2572730006920" (serial number)
- Server responds with different info: "Y2580330012730" (server's own info?)

## Step 5: Check Renewal Patterns

```
dhcp> renewals
```

**Output:**
```
MAC: 78:20:51:71:14:41
  Total renewal requests: 83
  Average renewal interval: 10.0s (0.2 minutes)
  Min interval: 9.8s
  Max interval: 10.2s
  Lease time from server: 172800s (48.0 hours)
  Expected T1 (50% of lease): 86400.0s (24.0 hours)
  Expected T2 (87.5% of lease): 151200.0s (42.0 hours)

  ⚠️  WARNING: Renewal interval (10.0s) is abnormally short!
      Expected around 86400.0s, got 10.0s
      This is 8640x more frequent than expected!

  Sample renewal intervals:
    Renewal #1: 10.0s after previous
    Renewal #2: 10.0s after previous
    Renewal #3: 10.1s after previous
    Renewal #4: 9.9s after previous
    Renewal #5: 10.0s after previous
```

**🔍 Finding:** Clients are renewing every 10 seconds despite a 48-hour (172,800 seconds) lease time. This is 8,640x more frequent than expected!

## Step 6: UDP Checksum Analysis

```
dhcp> checksums
```

**Output:**
```
Total DHCP packets analyzed: 2628
Packets with checksum issues: 512

Packets with bad checksums:

  Packet #95 [2026-01-06 00:45:53.789] ACK
    192.168.88.1 -> 192.168.88.80
    Original checksum:   0x33e0
    Calculated checksum: 0xee36
    Transaction ID: 0xfe07547a

  [... 511 more packets with bad checksums ...]
```

**🔍 Finding:** Exactly one ACK packet per duplicate pair has a bad checksum. This suggests hardware checksum offloading bugs.

---

## Summary of Issues

### Critical Bugs Identified:

1. **Duplicate DHCP ACK Responses**
   - DHCP server (192.168.88.1) sends 2 ACK packets for every REQUEST
   - Ratio: 3.56:1 (expected: 1:1)
   - Total duplicates: ~1,456 packets

2. **UDP Checksum Corruption**
   - First ACK in each pair has incorrect UDP checksum
   - Second ACK has correct UDP checksum
   - Suggests hardware offloading issue in router firmware

3. **Packet Inconsistencies**
   - Duplicate packets have different IP IDs
   - Different IP flags (DF vs none)
   - Time between duplicates: 50-100 microseconds

4. **Aggressive DHCP Renewal Behavior**
   - TP-Link devices renew every ~10 seconds
   - Expected: every 24 hours (T1 at 50% of 48-hour lease)
   - Frequency: 8,640x higher than normal
   - Causes unnecessary DHCP server load

### Root Cause Analysis:

**Primary Issue:** Router firmware bug in DHCP server implementation
- Likely related to UDP checksum offloading
- Packet duplication in transmission path
- One packet goes through checksum offload (wrong checksum)
- One packet bypasses offload (correct checksum)

**Secondary Issue:** TP-Link client firmware bug
- Abnormal DHCP renewal interval
- Ignoring lease time from server
- May be related to vendor option 125 misconfiguration

### Recommendations:

1. **Immediate:** Update router firmware to latest version
2. **Check:** Router hardware acceleration settings (disable if needed)
3. **Investigate:** TP-Link HB610V2 firmware for renewal bug
4. **Monitor:** Network load from excessive DHCP traffic
5. **Consider:** Alternative DHCP server if router cannot be fixed

### Impact:

- Bandwidth waste from duplicate packets (~50% overhead)
- Increased DHCP server CPU load from 10-second renewals
- Potential network instability in large deployments
- Client-side may be confused by receiving duplicate responses

---

## Commands Used in This Analysis

```bash
# Start interactive analyzer
./dhcp_interactive.py test1.pcap

# Run diagnostic commands
dhcp> ratios        # Quick health check
dhcp> duplicates    # Find duplicate responses
dhcp> checksums     # Verify UDP checksums
dhcp> vendor        # Check device information
dhcp> renewals      # Analyze renewal patterns
dhcp> transaction fe07547a  # Deep dive into specific transaction
```

---

**Analysis Date:** 2026-01-07
**Capture File:** test1.pcap
**Network:** 192.168.88.0/24
**DHCP Server:** 192.168.88.1
**Tools Version:** DHCP Debugging Toolkit v2.0 (with new diagnostic commands)
