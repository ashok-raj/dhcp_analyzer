# Satellite DHCP Behavior Explained

## Two Separate DHCP Networks

Your TP-Link mesh system has **two separate networks** for DHCP:

### 1. Management Network (Satellites as DHCP Clients)
**Who**: The HB610V2 satellite devices themselves
**What**: Each satellite needs its own IP address to communicate with the HB810
**How**: Satellites act as **DHCP clients** requesting IPs from HB810
**IPs assigned**: 192.168.88.27, .58, .59, .79, .80, .87

### 2. WiFi Client Network (Satellites as Layer 2 Bridges)
**Who**: Your phones, laptops, IoT devices connected via WiFi
**What**: End-user devices connected to satellite WiFi
**How**: Satellites **transparently bridge** DHCP traffic to HB810
**IPs assigned**: Various (192.168.88.X for each client device)

---

## The 10-Second Renewal Problem

**YES - The HB610V2 satellites are renewing THEIR OWN management IP addresses every 10 seconds.**

### What's Happening

Each satellite is a **dual-role device**:

```
┌─────────────────────────────────────────┐
│  HB610V2 Satellite Device               │
│                                         │
│  Role 1: DHCP Client (for itself)      │
│  - Requests IP: 192.168.88.27           │
│  - Lease time: 48 hours                 │
│  - BUG: Renews every 10 seconds! ⚠️      │
│                                         │
│  Role 2: WiFi Bridge (for clients)      │
│  - Bridges WiFi client DHCP packets     │
│  - Transparent Layer 2 forwarding       │
│  - Does NOT act as DHCP relay/server    │
└─────────────────────────────────────────┘
```

### Evidence from Packet Capture

**Satellite 192.168.88.27 (MAC: 78:20:51:71:1a:b9)**:

```
Packet analysis shows:
- Client MAC in BOOTP header: 78:20:51:71:1a:b9 (satellite's own MAC)
- Requested IP: 192.168.88.27 (satellite's management IP)
- Source IP in REQUEST: 192.168.88.27 (renewing, not discovering)
- Renewal interval: 10.01 seconds (average)

Timeline:
00:45:53.789 - REQUEST for 192.168.88.27
00:46:03.800 - REQUEST for 192.168.88.27 [+10.011s]
00:46:13.817 - REQUEST for 192.168.88.27 [+10.017s]
00:46:23.825 - REQUEST for 192.168.88.27 [+10.008s]
```

This is the **satellite renewing its own IP address**, not WiFi client traffic!

### Why Satellites Need IP Addresses

The satellites need management IPs for:

1. **Mesh Communication**: Talk to HB810 and other satellites
2. **Backhaul Traffic**: Route data between WiFi clients and HB810
3. **Management Interface**: Web UI, firmware updates, configuration
4. **Monitoring**: Health checks, status reporting to main router

**This is normal** - mesh satellites always need their own IPs.

**What's NOT normal** - renewing every 10 seconds instead of 24 hours!

### Traffic Impact

**6 satellites × 10-second renewals**:
```
Normal behavior:
  6 satellites × 2 renewals/day = 12 DHCP transactions/day

Actual behavior (bug):
  6 satellites × 8,640 renewals/day = 51,840 DHCP transactions/day

Increase: 4,320× more traffic just for satellite management!
```

This is **separate from** any WiFi client DHCP traffic.

---

## WiFi Clients vs Satellite Management

### Verification Script

To see the difference, run:

```bash
./dhcp_interactive.py test1.pcap
```

Then examine a satellite renewal:

```
dhcp> list_mac 78:20:51:71:1a:b9

You'll see:
- All packets have client_mac = 78:20:51:71:1a:b9 (satellite itself)
- All packets request IP 192.168.88.27 (satellite's management IP)
- Pattern: REQUEST → ACK every ~10 seconds
```

Compare with a WiFi client:

```
dhcp> list_mac <some_other_mac>

You'll see:
- Client MAC different from any satellite MAC
- Requests different IP
- Normal renewal pattern (hours, not seconds)
```

### Two Separate Traffic Flows

**Traffic Flow 1: Satellite Management (PROBLEM)**
```
HB610V2 satellite ──[DHCP REQUEST]──> HB810 server
                                      (every 10 seconds! ⚠️)
                   <──[DHCP ACK]────
```

**Traffic Flow 2: WiFi Client (NORMAL)**
```
Phone/Laptop ──[WiFi]──> HB610V2 ──[Bridge]──> HB810
                         satellite              server
             <──[WiFi]── <──[Bridge]── <──
                         (normal intervals ✓)
```

The 10-second renewal bug affects **only the satellites' own IPs**, not WiFi clients.

---

## Real-World Example

Let's say you have:
- 1 HB810 main router
- 6 HB610V2 satellites
- 20 WiFi client devices (phones, laptops, etc.)

**Normal DHCP traffic**:
- Satellites: 6 devices × 2 renewals/day = 12 requests/day
- WiFi clients: 20 devices × 2 renewals/day = 40 requests/day
- **Total: ~52 DHCP transactions/day**

**Actual DHCP traffic (with bug)**:
- Satellites: 6 devices × 8,640 renewals/day = 51,840 requests/day ⚠️
- WiFi clients: 20 devices × 2 renewals/day = 40 requests/day
- **Total: ~51,880 DHCP transactions/day**

**Result**: Satellite management renewals dominate your DHCP traffic!

---

## Why This Matters

### 1. Network Bandwidth

At 400 bytes per DHCP transaction:
```
Normal: 52 × 400 = ~21 KB/day
Actual: 51,880 × 400 = ~20 MB/day

Bandwidth waste: ~20 MB/day just for DHCP!
```

### 2. Router CPU Load

The HB810 must process:
```
Normal: ~52 DHCP packets/day = 0.0006 packets/second
Actual: ~51,880 packets/day = 0.6 packets/second

CPU load: 1,000× increase!
```

### 3. Wireless Airtime

Each DHCP transaction requires:
- REQUEST packet over WiFi backhaul
- ACK packet over WiFi backhaul
- Duplicate ACK (bug) over WiFi backhaul
- ICMP error response over WiFi backhaul

**4 packets per renewal × 6 satellites × 8,640 renewals/day = ~207,360 packets/day**

This consumes valuable wireless airtime on your mesh backhaul!

### 4. Potential Instability

Constant DHCP churn can cause:
- Temporary IP conflicts during renewal
- Race conditions in routing tables
- Mesh handoff issues
- Dropped connections during renewal

---

## The Fix

### Root Cause

**Server side**: HB810 doesn't send T1/T2 options in DHCP ACKs
**Client side**: HB610V2 firmware bug - uses 10-second default instead of calculating from lease time

### Solution

**Option 1: Fix Server (Recommended)**
Configure HB810 to send T1/T2 options:
```
Current ACK contains:
  Option 51 (lease_time): 172800 seconds (48 hours) ✓

Add these:
  Option 58 (T1): 86400 seconds (24 hours)
  Option 59 (T2): 151200 seconds (42 hours)
```

**Option 2: Fix Firmware**
Update HB610V2 firmware to properly calculate T1 when not provided:
```c
// Correct behavior per RFC 2131
if (!T1_provided) {
    T1 = lease_time * 0.5;  // 24 hours
}
```

**Expected result**: Satellites renew every 24 hours instead of 10 seconds

---

## Summary

✅ **Confirmed**: HB610V2 satellites ARE renewing their own management IP addresses every 10 seconds

✅ **Separate from WiFi clients**: WiFi clients get IPs through transparent bridging (normal behavior)

✅ **Major impact**: Satellite renewals generate 99.9% of your DHCP traffic

✅ **Fix available**: Add T1/T2 options to reduce renewals by 8,640×

---

**See also**:
- [ROOT_CAUSE_ANALYSIS.md](ROOT_CAUSE_ANALYSIS.md) - Technical details on the bug
- [COMPLETE_ANALYSIS_SUMMARY.md](COMPLETE_ANALYSIS_SUMMARY.md) - Full network analysis
- [test_hypothesis.sh](test_hypothesis.sh) - How to test the fix
