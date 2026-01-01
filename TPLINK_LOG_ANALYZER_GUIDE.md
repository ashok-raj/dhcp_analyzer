# TPLink Log Analyzer - Quick Guide

## Overview

`tplink_log_analyzer.py` analyzes TPLink router log files to identify:
- Mesh client churn (frequent add/delete cycles)
- DHCP issues (NAKs, failed leases, storms)
- WAN DHCP status
- Network stability problems

## Installation

No installation needed! The script uses only Python standard library.

```bash
chmod +x tplink_log_analyzer.py
```

## Usage

### 1. Basic Analysis (Recommended)

Shows complete summary of the log file:

```bash
./tplink_log_analyzer.py log_tplink-12-31.txt
```

**Output includes:**
- Time range and duration
- Event counts by component (Mesh, DHCPD, DHCPC)
- Mesh client activity (add/del counts, churning clients)
- DHCP statistics (DISCOVER, OFFER, REQUEST, ACK, NAK)
- DHCP success rate
- IP assignments per client
- High-activity DHCP clients
- WAN IP information
- Error summary

### 2. Filter by MAC Address

View timeline of all events for a specific device:

```bash
./tplink_log_analyzer.py log_tplink-12-31.txt --mac 44:67:55
```

Partial MAC addresses work! This shows:
- Chronological list of all events for that MAC
- Mesh add/delete events
- DHCP DISCOVER/REQUEST events
- Helps identify client-specific issues

**Example:**
```bash
./tplink_log_analyzer.py log_tplink-12-31.txt --mac 4E:A2:E7
```

### 3. DHCP Storm Detection

Detect clients making excessive DHCP requests:

```bash
./tplink_log_analyzer.py log_tplink-12-31.txt --storms
```

Customize detection thresholds:

```bash
# Detect 8+ requests within 5 seconds
./tplink_log_analyzer.py log_tplink-12-31.txt --storms --storm-window 5 --storm-threshold 8
```

### 4. Combined Analysis

You can combine options:

```bash
# Full analysis with storm detection
./tplink_log_analyzer.py log_tplink-12-31.txt --storms

# MAC-specific timeline (storm detection doesn't apply with --mac)
./tplink_log_analyzer.py log_tplink-12-31.txt --mac aa:bb:cc
```

## Understanding the Output

### Mesh Client Analysis

```
Top 10 clients by activity (add + delete events):
MAC Address          Adds     Dels     Total    Status
----------------------------------------------------------------------
4E:A2:E7:A6:3F:F2    73       26       99       Churning
96:93:C1:08:9B:1F    42       28       70       Churning
44:67:55:41:B5:7A    21       22       43       Stable
```

- **Churning**: Client frequently disconnecting/reconnecting (unstable)
- **Stable**: Add/Del counts are balanced (normal behavior)
- **High Total**: Indicates connectivity issues

### DHCP Analysis

```
DISCOVER messages: 15
OFFER messages:    51
REQUEST messages:  1
ACK messages:      0
NAK messages:      2
RELEASE messages:  0

DHCP Success Rate: 0.0% (ACKs / DISCOVERs)
```

- **Success Rate**: Percentage of successful DHCP leases
- **Low success rate**: Major DHCP configuration problem
- **NAK messages**: Server rejected the DHCP request
  - Often caused by:
    - IP address already in use
    - Client requesting wrong IP
    - DHCP pool exhaustion
    - Network misconfiguration

### High DHCP Activity

```
⚠ High DHCP activity clients (5+ requests):
MAC Address          Request Count
----------------------------------------
44:67:55:41:B5:7A    16
```

Clients making many DHCP requests may indicate:
- Client stuck in retry loop
- Failed to get valid IP
- Network instability
- DHCP configuration issues

### IP Assignments

```
IP Assignments (last per client):
MAC Address          IP Address       Type     Timestamp
----------------------------------------------------------------------
44:67:55:41:B5:7A    192.168.88.85    OFFER    2025-12-31 15:05:50
90:A8:22:74:64:80    192.168.88.7     OFFER    2025-12-31 14:52:33
```

- **OFFER**: IP was offered but not confirmed (no ACK)
- **ACK**: IP successfully assigned
- Check if clients are getting ACK vs just OFFER

### WAN DHCP (Router's Internet Connection)

```
Current WAN IP: 50.39.254.140
WAN IP renewals: 6
```

This tracks the router's own DHCP client (WAN interface):
- Current public IP address
- How many times it renewed the lease
- Useful for ISP connectivity troubleshooting

## Common Workflows

### 1. Identify Problem Devices

```bash
# Get overview
./tplink_log_analyzer.py log.txt

# Look for:
# - "Churning" clients in Mesh analysis
# - High DHCP activity clients
# - Clients with DHCP NAKs
```

### 2. Deep Dive into Specific Client

```bash
# Once you identify a problem MAC (e.g., 4E:A2:E7:A6:3F:F2)
./tplink_log_analyzer.py log.txt --mac 4E:A2:E7
```

Review the timeline to see:
- How often it connects/disconnects
- DHCP request patterns
- Whether it's getting IP addresses

### 3. Check for DHCP Storms

```bash
./tplink_log_analyzer.py log.txt --storms
```

If storms detected:
1. Note the MAC addresses causing storms
2. Investigate those specific devices
3. Check DHCP pool size
4. Look for IP conflicts

### 4. Monitor DHCP Success Rate

Low success rate (<50%) indicates serious issues:
- Check DHCP pool configuration
- Look for IP conflicts
- Review NAK messages
- Consider expanding DHCP pool

## Real-World Example: Your Logs

### log_tplink-12-31.txt Analysis:

**Problems Identified:**

1. **Mesh Instability**: 3 clients with high churn
   - 4E:A2:E7:A6:3F:F2: 99 events (73 adds, 26 dels)
   - 96:93:C1:08:9B:1F: 70 events (42 adds, 28 dels)
   - A2:B1:5D:B3:59:10: 69 events (46 adds, 23 dels)

2. **DHCP Failure**: 0% success rate
   - 15 DISCOVER messages
   - 0 ACK messages
   - 2 NAK messages
   - Clients not getting IP addresses!

3. **Problem Client**: 44:67:55:41:B5:7A
   - 16 DHCP requests
   - Multiple mesh disconnects
   - Never got successful lease

**Recommended Actions:**
1. Investigate why 44:67:55:41:B5:7A can't get an IP
2. Check DHCP pool configuration
3. Look for IP conflicts on the network
4. Consider mesh network stability issues

## Command Reference

```bash
# Basic usage
./tplink_log_analyzer.py <logfile>

# Filter by MAC
./tplink_log_analyzer.py <logfile> --mac <MAC>

# Storm detection
./tplink_log_analyzer.py <logfile> --storms

# Custom storm thresholds
./tplink_log_analyzer.py <logfile> --storms --storm-window 10 --storm-threshold 5

# Help
./tplink_log_analyzer.py --help
```

## Tips

1. Always start with basic analysis to get the overview
2. Focus on "Churning" clients and high DHCP activity
3. Low DHCP success rate is a red flag
4. Use --mac to investigate specific problem devices
5. Compare logs over time to identify trends
6. NAK messages always deserve investigation

## Log Format

The script parses TPLink logs in this format:
```
YYYY-MM-DD HH:MM:SS [LEVEL] COMPONENT: MESSAGE
```

Supported components:
- **Mesh**: Wireless mesh client events
- **DHCPD**: DHCP server (LAN clients)
- **DHCPC**: DHCP client (WAN/Internet)
- **Httpd**: Web interface events

## Troubleshooting

**Script doesn't parse my log:**
- Verify log format matches the expected pattern
- Check file encoding (should be UTF-8 or ASCII)
- Ensure timestamps are present

**No events found:**
- Check if log file has proper formatting
- Verify component names match (Mesh, DHCPD, DHCPC)

**MAC filter returns nothing:**
- Try shorter MAC prefix (e.g., just "44:67")
- MAC addresses are case-insensitive

## Files in This Directory

- `tplink_log_analyzer.py` - Main analyzer script
- `dhcp_analyzer.py` - Packet capture analyzer (for .pcap files)
- `dhcp_interactive.py` - Interactive packet capture analyzer
- `tshark_examples.sh` - Wireshark/tshark command reference
- `README.md` - DHCP analyzer documentation
- `TPLINK_LOG_ANALYZER_GUIDE.md` - This guide

Use the DHCP analyzers for packet captures (.pcap/.pcapng files) and the TPLink analyzer for router log files.
