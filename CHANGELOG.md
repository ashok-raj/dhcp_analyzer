# Changelog

All notable changes to the DHCP Debugging Toolkit.

## [2.0.0] - 2026-01-07

### Added - Six New Diagnostic Commands

#### `ratios` - Request/Reply Ratio Analysis
- Quick health check for DHCP server behavior
- Detects duplicate responses (ACK/REQUEST ratio anomalies)
- Identifies high renewal activity
- Shows OFFER/DISCOVER and ACK/REQUEST ratios with warnings

#### `duplicates [time_threshold_ms]` - Duplicate Response Detection
- Detects duplicate server responses with same transaction ID
- Shows detailed comparison of duplicate packets:
  - Different IP IDs
  - Different IP flags (DF vs none)
  - Different UDP checksums
  - Timing between duplicates (typically 50-100μs)
- Default threshold: 1000ms (configurable)
- Critical for identifying router firmware bugs

#### `checksums` - UDP Checksum Validation
- Recalculates and validates UDP checksums for all DHCP packets
- Identifies packets with checksum corruption
- Shows both original and calculated checksums
- Helps diagnose hardware checksum offloading issues
- Found: ~50% of duplicate ACKs have bad checksums

#### `vendor [mac]` - Vendor-Specific Options Analysis
- Parses Option 60 (Vendor Class ID)
- Parses Option 125 (Vendor-Specific Information)
- Shows device hostnames (Option 12)
- Displays both decoded and raw hex values
- Useful for identifying device manufacturers (TP-Link, etc.)
- Helps debug vendor-specific DHCP behaviors

#### `renewals [mac]` - Renewal Pattern Analysis
- Analyzes DHCP renewal intervals vs. lease times
- Calculates average, min, and max renewal intervals
- Compares with expected T1 (50% of lease) and T2 (87.5%)
- Detects abnormally aggressive renewal behavior
- **Found:** TP-Link devices renewing 8,640x more frequently than expected
  - Renewing every 10 seconds instead of 24 hours
  - Despite receiving 48-hour lease from server

#### `transaction <xid>` - Transaction Deep Dive
- Shows all packets in a specific transaction by XID
- Displays complete DHCP options for each packet
- Shows timing deltas between packets
- Displays IP IDs, flags, and checksums for comparison
- Detects duplicate message types within transaction
- Supports hex format with or without 0x prefix

### Enhanced

#### Parser Improvements
- Added IP ID extraction to packet parser
- Added IP flags extraction (DF, etc.)
- Added UDP checksum extraction and validation
- Enhanced packet structure for low-level analysis

#### Help System
- Updated help menu with new command categories
- Added detailed documentation for all new commands
- Organized commands into logical groups

### Documentation

#### New Files
- `EXAMPLE_ANALYSIS.md` - Complete real-world analysis walkthrough
  - Demonstrates all new diagnostic commands
  - Shows actual bugs found in test1.pcap
  - Provides root cause analysis and recommendations
- `setup.sh` - Automated installation script
  - Detects operating system (Ubuntu, Debian, Fedora, RHEL, Arch)
  - Installs Python dependencies (scapy)
  - Makes scripts executable
  - Optional installation of tcpdump and tshark
- `CHANGELOG.md` - This file

#### Updated Files
- `README.md` - Major update with:
  - "What's New in v2.0" section
  - Complete command reference with examples
  - Detailed documentation for all new commands
  - Updated installation instructions
  - Enhanced troubleshooting workflow
  - Updated file listing

### Bug Fixes Identified

Using the new diagnostic tools, we identified:

1. **Router Firmware Bug - Duplicate DHCP ACK Responses**
   - Server sends 2 ACK packets for every REQUEST
   - ACK/REQUEST ratio: 3.56:1 (expected: 1:1)
   - Affects all DHCP transactions
   - Estimated ~1,456 duplicate packets in 13-minute capture

2. **UDP Checksum Corruption**
   - First ACK has incorrect checksum (e.g., 0x33e0 instead of 0xee36)
   - Second ACK has correct checksum
   - Indicates hardware checksum offloading bug
   - Affects ~512 packets in sample capture

3. **Packet Generation Inconsistencies**
   - Duplicate ACKs have different IP IDs (e.g., 56183 vs 43556)
   - Different IP flags (first has DF set, second doesn't)
   - Suggests duplicate packets generated at different points in network stack

4. **TP-Link Client Firmware Bug - Aggressive Renewals**
   - TP-Link HB610V2 devices renew every ~10 seconds
   - Server offers 48-hour (172,800 second) lease
   - Expected renewal at T1: 24 hours (86,400 seconds)
   - Actual renewal: 10 seconds
   - Frequency: 8,640x higher than RFC specification
   - Causes unnecessary DHCP server load

### Performance

- All new commands designed for interactive use
- Efficient packet iteration (no reloading)
- Minimal memory overhead
- Fast duplicate detection with hash-based grouping

### Compatibility

- Python 3.6+
- Scapy 2.4+
- Tested on Ubuntu 22.04, Debian 11, Fedora 38
- Compatible with existing pcap analysis workflow

---

## [1.0.0] - 2025-12-31

### Initial Release

- Interactive DHCP packet analyzer (`dhcp_interactive.py`)
- Batch DHCP analyzer (`dhcp_analyzer.py`)
- TPLink log analyzer (`tplink_log_analyzer.py`)
- Basic DHCP analysis commands:
  - `summary`, `list`, `list_mac`, `filter`
  - `naks`, `dor_nak`, `failed_dora`
  - `storms`, `retries`, `conflicts`
  - `timings`, `servers`, `ips`, `options`
- Documentation and examples

---

## Version History Summary

- **v2.0.0** (2026-01-07) - Major diagnostic enhancement release
  - 6 new advanced diagnostic commands
  - Enhanced packet parsing
  - Automated setup script
  - Comprehensive real-world analysis example

- **v1.0.0** (2025-12-31) - Initial release
  - Core DHCP analysis functionality
  - Interactive and batch modes
  - TPLink log support
