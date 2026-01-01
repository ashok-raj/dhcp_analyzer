# DHCP Debugging Toolkit

Comprehensive tools for analyzing DHCP traffic from both packet captures (pcap/pcapng files) and router log files. Designed to debug DHCP storms, mesh instability, and network issues with TPLink WiFi7 products and other networking equipment.

## Tools Included

1. **`dhcp_analyzer.py`** - Batch analysis tool for generating reports from pcap files
2. **`dhcp_interactive.py`** - Interactive shell for exploring DHCP packets from pcap files
3. **`tplink_log_analyzer.py`** - Analyzer for TPLink router log files (text logs)
4. **`tshark_examples.sh`** - Quick reference for tshark commands

## Quick Start

**Have a packet capture (.pcap/.pcapng)?**
```bash
pip install scapy
./dhcp_interactive.py capture.pcap
dhcp> summary
dhcp> failed_dora
dhcp> list_mac <problem_mac>
```

**Have a TPLink router log file?**
```bash
./tplink_log_analyzer.py router.log
./tplink_log_analyzer.py router.log --mac <problem_mac>
./tplink_log_analyzer.py router.log --storms
```

## Installation

### For DHCP Packet Analyzers (pcap files)

```bash
pip install scapy
```

### For TPLink Log Analyzer (text logs)

No installation needed - uses Python standard library only!

---

## Tool 1: Interactive Analyzer (Recommended)

### Quick Start

```bash
./dhcp_interactive.py DHCP_Storm_12_27.pcapng
```

This launches an interactive shell where you can run multiple analyses without reloading the capture file.

### Available Commands

| Command | Description |
|---------|-------------|
| `summary` | Show overall DHCP packet statistics |
| `list [mac] [limit]` | List all DHCP packets in chronological order |
| `list_mac [mac]` | List all DORA sequences grouped by MAC address |
| `naks [mac]` | Find all DHCP NAK messages (optionally filter by MAC) |
| `dor_nak [mac]` | Find DISCOVER→OFFER→REQUEST→NAK sequences |
| `failed_dora [mac]` | Count failed DORA attempts per MAC with success rates |
| `filter <mac>` | Show all packets for a specific MAC address |
| `storms [time] [count]` | Detect DHCP storms (default: 10 msgs in 10s) |
| `help [cmd]` | Show available commands or help for specific command |
| `exit` / `quit` | Exit the analyzer |

### Example Session

```
dhcp> summary

Total DHCP packets: 198
Message type breakdown:
  ACK       :    9
  DISCOVER  :   57
  NAK       :   12
  OFFER     :   18
  REQUEST   :  102

Unique client MACs: 7
Top 5 most active MACs:
  54:2a:1b:1b:96:54: 60 packets | Last IP: 192.168.88.77 (2025-12-27 11:23:22.402)
  90:a8:22:74:64:80: 48 packets | No successful lease
  74:ec:b2:b0:af:2e: 43 packets | No successful lease

dhcp> failed_dora

MAC Address          Total    Failed   NAKs     Success  Success Rate
--------------------------------------------------------------------------------
26:0a:bd:09:99:b5    17       17       0        0               0.0%
44:67:55:41:b5:7a    5        5        1        0               0.0%
96:93:c1:08:9b:1f    3        3        0        0               0.0%
54:2a:1b:1b:96:54    7        2        0        5              71.4%
74:ec:b2:b0:af:2e    2        2        0        0               0.0%
90:a8:22:74:64:80    1        1        0        0               0.0%

Summary:
  Total DORA sequences: 35
  Total failed sequences: 30
  Total successful: 5

dhcp> filter 26:0a:bd:09:99:b5
[Shows all 17 packets for this problematic MAC]

dhcp> naks
[Shows all 12 NAK messages with detailed information]
```

### Command Details

#### `summary`
Shows overall statistics:
- Total DHCP packets
- Message type breakdown
- Unique client MACs
- Most active devices with their last successful IP assignment (if any)
- Capture time range and duration

#### `list [mac] [limit]`
Lists all DHCP packets in chronological order:
- Shows timestamp, message type, MAC address, source/destination IPs
- For OFFER/ACK messages, displays the IP being assigned
- Optional MAC filtering to see timeline for specific device
- Optional limit to show only first N packets

Examples:
```
list              # Show all packets
list 20           # Show first 20 packets
list aa:bb:cc     # Show all packets for MAC containing aa:bb:cc
list aa:bb:cc 50  # Show first 50 packets for that MAC
```

This is useful for:
- Understanding the sequence of DHCP events
- Tracking a device's DHCP journey over time
- Seeing what IP was offered/assigned at each step
- Identifying patterns in retry behavior

#### `list_mac [mac]`
Lists all DORA sequences grouped by MAC address:
- Shows all complete and incomplete DHCP sequences
- Groups sequences by transaction ID (XID)
- Displays sequence pattern (e.g., DISCOVER → OFFER → REQUEST → ACK)
- Shows status: SUCCESS, FAILED (NAK), or INCOMPLETE with specific reason
- Each packet shows timestamp, packet number, message type, and IPs
- Sequences are ordered chronologically

Examples:
```
list_mac                    # Show all DORA sequences for all MACs
list_mac aa:bb:cc:dd:ee:ff  # Show sequences for specific MAC
list_mac aa:bb:cc           # Partial MAC match works too
```

Output format:
```
================================================================================
MAC: 54:2a:1b:1b:96:54
================================================================================
Total sequences: 7

  Sequence #1 - XID: 0x12345678 - SUCCESS
  Pattern: DISCOVER -> OFFER -> REQUEST -> ACK
  ────────────────────────────────────────────────────────────────────────────
    [2025-12-27 11:20:45.123] Pkt #   42 | DISCOVER   | 0.0.0.0         -> 255.255.255.255
    [2025-12-27 11:20:45.234] Pkt #   43 | OFFER      | 192.168.88.1    -> 255.255.255.255 (IP: 192.168.88.77)
    [2025-12-27 11:20:45.345] Pkt #   44 | REQUEST    | 0.0.0.0         -> 255.255.255.255
    [2025-12-27 11:20:45.456] Pkt #   45 | ACK        | 192.168.88.1    -> 192.168.88.77   (IP: 192.168.88.77)

  Sequence #2 - XID: 0x87654321 - FAILED (NAK)
  Pattern: DISCOVER -> OFFER -> REQUEST -> NAK
  ────────────────────────────────────────────────────────────────────────────
    [2025-12-27 11:21:10.123] Pkt #   52 | DISCOVER   | 0.0.0.0         -> 255.255.255.255
    [2025-12-27 11:21:10.234] Pkt #   53 | OFFER      | 192.168.88.1    -> 255.255.255.255 (IP: 192.168.88.77)
    [2025-12-27 11:21:10.345] Pkt #   54 | REQUEST    | 0.0.0.0         -> 255.255.255.255
    [2025-12-27 11:21:10.456] Pkt #   55 | NAK        | 192.168.88.1    -> 255.255.255.255
```

This is ideal for:
- Seeing the complete DORA flow for each device
- Quickly identifying where sequences break down
- Understanding retry patterns and timing
- Spotting incomplete sequences (no response from server)
- Debugging specific MAC address issues

#### `naks [mac]`
Displays all DHCP NAK (lease rejection) messages:
- Groups NAKs by MAC address
- Shows detailed packet info (IPs, transaction IDs)
- Optional filtering by MAC

#### `dor_nak [mac]`
Finds complete DHCP sequences that ended in NAK:
- DISCOVER → OFFER → REQUEST → NAK
- Shows full sequence with timestamps
- Identifies why leases are being rejected

#### `failed_dora [mac]`
Critical for debugging! Shows:
- How many DHCP attempts each MAC made
- How many failed (no ACK received)
- Success rate percentage
- Identifies devices stuck in retry loops

Example output shows **26:0a:bd:09:99:b5** made 17 attempts with 0% success!

#### `filter <mac>`
Deep dive into a specific MAC:
- All packets for that device
- Message type breakdown
- Detailed packet information

#### `storms [time] [count]`
Detects excessive DHCP traffic:
- Default: 10+ messages in 10 seconds
- Customizable thresholds
- Shows storm duration and message types

---

## Tool 2: Batch Analyzer

For automated reporting and integration with scripts.

### Basic Usage

```bash
./dhcp_analyzer.py DHCP_Storm_12_27.pcapng
```

### Filter by MAC Address

```bash
./dhcp_analyzer.py capture.pcap -m aa:bb:cc:dd:ee:ff

# Partial MAC matching supported
./dhcp_analyzer.py capture.pcap -m aa:bb:cc
```

### Verbose Output

```bash
./dhcp_analyzer.py capture.pcap -m aa:bb:cc:dd:ee:ff --verbose
```

### Custom Storm Detection

```bash
# Detect storms with 20+ messages within 5 seconds
./dhcp_analyzer.py capture.pcap --storm-threshold 20 --storm-window 5
```

### Command Line Options

```
usage: dhcp_analyzer.py [-h] [-m MAC] [-v] [--no-naks] [--no-storm-detection]
                        [--storm-window STORM_WINDOW]
                        [--storm-threshold STORM_THRESHOLD]
                        pcap_file

positional arguments:
  pcap_file             Path to pcap/pcapng file

optional arguments:
  -h, --help            show this help message and exit
  -m MAC, --mac MAC     Filter by MAC address (partial match supported)
  -v, --verbose         Show detailed packet information
  --no-naks             Disable NAK detection
  --no-storm-detection  Disable DHCP storm detection
  --storm-window STORM_WINDOW
                        Storm detection time window in seconds (default: 10)
  --storm-threshold STORM_THRESHOLD
                        Storm detection message threshold (default: 10)
```

---

## Tool 3: TPLink Log Analyzer

For analyzing TPLink router text log files (not pcap files).

### Quick Start

```bash
./tplink_log_analyzer.py log_tplink-12-31.txt
```

### Features

- **Mesh client analysis** - Detect clients with unstable connections (frequent add/delete)
- **DHCP statistics** - Track DISCOVER, OFFER, REQUEST, ACK, NAK messages
- **Success rate tracking** - Measure DHCP lease success percentage
- **MAC filtering** - View timeline of all events for specific device
- **Storm detection** - Identify clients making excessive DHCP requests
- **WAN DHCP tracking** - Monitor router's own internet connection
- **IP assignment tracking** - See which IPs were assigned to which clients

### Common Usage

```bash
# Full analysis of log file
./tplink_log_analyzer.py router.log

# Filter by specific MAC address
./tplink_log_analyzer.py router.log --mac 44:67:55:41:b5:7a

# Detect DHCP storms
./tplink_log_analyzer.py router.log --storms

# Custom storm detection (8+ requests in 5 seconds)
./tplink_log_analyzer.py router.log --storms --storm-window 5 --storm-threshold 8
```

### When to Use This vs Packet Analyzer

- **Use TPLink Log Analyzer** when:
  - You have TPLink router log files (text format)
  - You want to see mesh client behavior
  - You need to correlate mesh and DHCP issues
  - You don't have packet captures

- **Use DHCP Packet Analyzer** when:
  - You have Wireshark captures (.pcap/.pcapng)
  - You need detailed packet-level analysis
  - You want to see actual network traffic
  - You're debugging non-TPLink DHCP servers

For detailed guide, see **[TPLINK_LOG_ANALYZER_GUIDE.md](TPLINK_LOG_ANALYZER_GUIDE.md)**

---

## Tool 4: tshark Reference

Quick reference for using tshark directly:

```bash
./tshark_examples.sh
```

Common commands:

```bash
# All DHCP packets
tshark -r capture.pcap -Y "bootp"

# Filter by client MAC
tshark -r capture.pcap -Y "bootp.hw.mac_addr == aa:bb:cc:dd:ee:ff"

# Find DHCP NAKs
tshark -r capture.pcap -Y "bootp.option.dhcp == 6"

# Export filtered packets
tshark -r capture.pcap -Y "bootp.hw.mac_addr == aa:bb:cc:dd:ee:ff" -w filtered.pcap
```

---

## Common Troubleshooting Workflow

### 1. Capture Traffic

```bash
tcpdump -i eth0 -w capture.pcap port 67 or port 68
```

### 2. Start with Interactive Analysis

```bash
./dhcp_interactive.py capture.pcap
```

### 3. Investigation Steps

```
dhcp> summary              # Get overview
dhcp> list 20              # See first 20 packets chronologically
dhcp> failed_dora          # Find problematic MACs
dhcp> list_mac <mac>       # See all DORA sequences for problem device
dhcp> filter <problem_mac> # Deep dive into problem device
dhcp> dor_nak <mac>        # See why leases are rejected
dhcp> naks <mac>           # Review all rejections
dhcp> storms               # Check for retry loops
```

### 4. For Specific MAC Analysis

```bash
./dhcp_analyzer.py capture.pcap -m <mac> --verbose > report.txt
```

---

## Understanding DHCP Message Types

| Type | Name | Description |
|------|------|-------------|
| 1 | DISCOVER | Client looking for DHCP server |
| 2 | OFFER | Server offering IP address |
| 3 | REQUEST | Client requesting offered IP |
| 4 | DECLINE | Client rejecting offered IP |
| 5 | ACK | Server confirming lease (SUCCESS) |
| 6 | NAK | Server rejecting request (FAILURE) |
| 7 | RELEASE | Client releasing IP |
| 8 | INFORM | Client requesting config only |

**Normal DHCP Flow (DORA):**
DISCOVER → OFFER → REQUEST → ACK

**Failed DHCP Flow:**
DISCOVER → OFFER → REQUEST → NAK

---

## Real-World Example: Your Capture Analysis

From your `DHCP_Storm_12_27.pcapng`:

**Problem Identified:**
- 198 DHCP packets in 11 minutes
- 12 NAKs detected
- Only 5 successful leases (ACK) out of 35 attempts
- **85.7% failure rate!**

**Worst Offenders:**
1. `26:0a:bd:09:99:b5` - 17 attempts, 0 successful (0%)
2. `44:67:55:41:b5:7a` - 5 attempts, 0 successful, 1 NAK (0%)
3. `96:93:c1:08:9b:1f` - 3 attempts, 0 successful (0%)

**Root Cause:**
Multiple devices unable to obtain DHCP leases, causing continuous retry storms.

---

## Features

- **MAC Address Filtering** - Find all packets for specific devices
- **IP Assignment Tracking** - Track the last successful IP assigned to each MAC
- **NAK Detection** - Identify lease rejections with context (5 packets before, 3 after)
- **DORA Sequence Analysis** - Track complete DHCP negotiations
- **Storm Detection** - Identify excessive retry behavior
- **Success Rate Tracking** - Measure DHCP reliability per device
- **Transaction Tracking** - Follow DHCP conversations by XID
- **Time-based Analysis** - Understand temporal patterns
- **Interactive & Batch Modes** - Choose your workflow

---

## Tips

1. **Use interactive mode for exploration** - Faster iteration without reloading
2. **Use batch mode for reports** - Better for documentation and automation
3. **Start with `summary`** - Get the big picture first
4. **Focus on failed_dora** - This shows your real problems
5. **Investigate 0% success rates** - These devices need attention
6. **Look for same XID in multiple NAKs** - Indicates persistent issues

---

## Files

### Analyzers
- `dhcp_analyzer.py` - Batch DHCP packet analyzer (pcap files)
- `dhcp_interactive.py` - Interactive DHCP packet analyzer (pcap files) - **recommended for pcap analysis**
- `tplink_log_analyzer.py` - TPLink router log analyzer (text files)

### Documentation
- `README.md` - This file (main documentation)
- `TPLINK_LOG_ANALYZER_GUIDE.md` - Detailed guide for TPLink log analyzer

### Utilities
- `tshark_examples.sh` - tshark command reference

---

## Support

For TPLink WiFi7 DHCP debugging:
1. Capture traffic during the issue
2. Run `./dhcp_interactive.py <capture>`
3. Use `failed_dora` to identify problem MACs
4. Use `filter <mac>` to investigate each device
5. Check for IP conflicts, exhausted DHCP pools, or configuration issues
