# Multi-Satellite DHCP Capture Guide

## Overview

This enhanced capture system simultaneously captures DHCP traffic from the main HB810 router and all 6 HB610V2 satellite units. It supports extended capture durations (default 15 minutes) with the ability to stop early using Ctrl+C.

## Features

- **Parallel Capture**: Captures from 7 devices simultaneously (1 main + 6 satellites)
- **Extended Duration**: 15-minute capture window (configurable)
- **Early Termination**: Press Ctrl+C to stop all captures before timeout
- **Unique Filenames**: Each device gets a uniquely named capture file
- **Automatic TFTP**: TFTP receiver starts automatically and collects all captures
- **Organized Output**: All files saved in timestamped session directory

## Device List

| Device Type | IP Address | Device Name |
|------------|------------|-------------|
| HB810 (Main) | 192.168.88.1 | main_router |
| HB610V2 Sat | 192.168.88.27 | satellite_27 |
| HB610V2 Sat | 192.168.88.58 | satellite_58 |
| HB610V2 Sat | 192.168.88.59 | satellite_59 |
| HB610V2 Sat | 192.168.88.79 | satellite_79 |
| HB610V2 Sat | 192.168.88.80 | satellite_80 |
| HB610V2 Sat | 192.168.88.87 | satellite_87 |

## Requirements

- Root access (required for TFTP server on port 69)
- Python 3 with `tftpy` module
- `expect` package installed
- Network access to all devices
- TFTP server IP configured as 192.168.88.32

## Files

- `capture_all_satellites.sh` - Master orchestration script with auto-discovery
- `scan_satellites.sh` - Network scanner for finding TP-Link devices
- `tplink_multi_capture.exp` - Individual device capture script
- `tftp_receiver.py` - TFTP server for receiving captures
- `satellites.conf` - Configuration file (auto-generated or manual)
- `satellites.conf.example` - Example configuration file

## Usage

### First Time Setup (Auto-Discovery)

On first use, discover your satellites automatically:

```bash
# Discover satellites and save configuration
sudo ./capture_all_satellites.sh --scan
```

This will:
1. Scan your network (192.168.88.0/24) for TP-Link devices
2. Identify HB810 router and HB610V2 satellites
3. Display discovered devices for confirmation
4. Save to `satellites.conf` for future use

### Basic Usage (15 minutes, simultaneous TFTP)

```bash
sudo ./capture_all_satellites.sh
```

### Custom Duration

```bash
# Capture for 5 minutes (300 seconds)
sudo ./capture_all_satellites.sh 300

# Capture for 30 minutes (1800 seconds)
sudo ./capture_all_satellites.sh 1800
```

### Staggered TFTP Transfers (Recommended)

To avoid network congestion and ensure reliable transfers, use staggered mode:

```bash
# Stagger TFTP transfers by 10 seconds between each device
sudo ./capture_all_satellites.sh 900 --stagger 10

# Use predefined sequential mode (15 second delays)
sudo ./capture_all_satellites.sh 900 --sequential

# 5 minute capture with 5 second stagger
sudo ./capture_all_satellites.sh 300 --stagger 5
```

**Transfer Timing:**
- `--stagger 10`: Device 0→0s, Device 1→10s, Device 2→20s, Device 3→30s, etc.
- `--sequential`: Equivalent to `--stagger 15` (15 second delays)
- No flag: All devices transfer simultaneously (may cause congestion)

### Early Termination

While captures are running, press **Ctrl+C** to stop all captures immediately. The script will:
1. Send stop signals to all capture processes
2. Wait for devices to transfer their captures via TFTP
3. Stop the TFTP receiver
4. Display a summary of captured files

## Output Structure

```
capture_session_YYYYMMDD_HHMMSS/
├── dhcp_main_router_YYYYMMDD_HHMMSS.pcap
├── dhcp_satellite_27_YYYYMMDD_HHMMSS.pcap
├── dhcp_satellite_58_YYYYMMDD_HHMMSS.pcap
├── dhcp_satellite_59_YYYYMMDD_HHMMSS.pcap
├── dhcp_satellite_79_YYYYMMDD_HHMMSS.pcap
├── dhcp_satellite_80_YYYYMMDD_HHMMSS.pcap
├── dhcp_satellite_87_YYYYMMDD_HHMMSS.pcap
└── tftp_receiver.log

Root directory:
├── capture_main_router_YYYYMMDD_HHMMSS.log
├── capture_satellite_27_YYYYMMDD_HHMMSS.log
├── capture_satellite_58_YYYYMMDD_HHMMSS.log
├── capture_satellite_59_YYYYMMDD_HHMMSS.log
├── capture_satellite_79_YYYYMMDD_HHMMSS.log
├── capture_satellite_80_YYYYMMDD_HHMMSS.log
└── capture_satellite_87_YYYYMMDD_HHMMSS.log
```

## Example Output

### Simultaneous Mode (Default)

```
============================================
Multi-Satellite DHCP Capture
============================================
Session directory: capture_session_20260109_143000
Capture duration: 900s (15m)
Devices to capture: 7
TFTP server: 192.168.88.32
TFTP transfer mode: Simultaneous (all at once)

Press Ctrl+C at any time to stop all captures early
============================================

Starting TFTP receiver...
✓ TFTP receiver started (PID: 12345)

Launching captures on all devices...

Starting capture on main_router (192.168.88.1)
  Process ID: 12346
Starting capture on satellite_27 (192.168.88.27)
  Process ID: 12347
...

All captures launched successfully!
Monitoring progress... (Press Ctrl+C to stop early)
```

### Staggered Mode (--stagger 10)

```
============================================
Multi-Satellite DHCP Capture
============================================
Session directory: capture_session_20260109_143000
Capture duration: 900s (15m)
Devices to capture: 7
TFTP server: 192.168.88.32
TFTP transfer mode: Staggered (10s delay between devices)
Estimated transfer time: ~60s

Press Ctrl+C at any time to stop all captures early
============================================

Starting TFTP receiver...
✓ TFTP receiver started (PID: 12345)

Launching captures on all devices...

Starting capture on main_router (192.168.88.1)
  Process ID: 12346
Starting capture on satellite_27 (192.168.88.27)
  TFTP delay: 10s
  Process ID: 12347
Starting capture on satellite_58 (192.168.88.58)
  TFTP delay: 20s
  Process ID: 12348
...

All captures launched successfully!
Monitoring progress... (Press Ctrl+C to stop early)
```

## Summary Report

At the end of the capture session (or after Ctrl+C), you'll see a summary:

```
============================================
Capture Session Summary
============================================
Session directory: capture_session_20260109_143000

Captured files:
  ✓ main_router (192.168.88.1): 2.3M
  ✓ satellite_27 (192.168.88.27): 1.8M
  ✓ satellite_58 (192.168.88.58): 1.5M
  ✓ satellite_59 (192.168.88.59): 1.9M
  ✓ satellite_79 (192.168.88.79): 1.7M
  ✓ satellite_80 (192.168.88.80): 2.1M
  ✓ satellite_87 (192.168.88.87): 1.6M

Successfully captured: 7/7 devices

Log files:
  - capture_main_router_20260109_143000.log
  - capture_satellite_27_20260109_143000.log
  ...
============================================
```

## Device Discovery & Configuration

### Auto-Discovery Process

When you run `--scan`, the script:

1. **Network Scanning**
   - Scans 192.168.88.0/24 network
   - Uses arp-scan (preferred), nmap, or ping + ARP
   - Looks for TP-Link MAC prefixes: 78:20:51, 50:3d:d1, f0:f6:c1

2. **Device Identification**
   - Checks for open telnet port (23)
   - Identifies HB610V2 satellites vs HB810 router by MAC
   - Generates device names automatically

3. **Configuration**
   - Displays all discovered devices
   - Prompts for confirmation
   - Saves to `satellites.conf`
   - Creates backup of existing config

### Configuration File Format

`satellites.conf`:
```
# TP-Link Satellite Configuration
# Format: IP:DeviceName
192.168.88.1:main_router
192.168.88.27:satellite_27
192.168.88.58:satellite_58
```

You can manually edit this file to:
- Add/remove devices
- Change device names
- Comment out devices temporarily

### Device Validation

Before each capture session:
- Config file is loaded (if exists)
- Each device is validated with ping (1 second timeout)
- Unreachable devices are skipped with warning
- Capture proceeds with available devices only

### Fallback Behavior

If no `satellites.conf` exists:
1. Uses hard-coded default device list
2. Validates each device with ping
3. Shows tip to run `--scan`
4. Proceeds with reachable devices

## How It Works

1. **Initialization**
   - Validates root access and required files
   - Loads and validates device configuration
   - Creates timestamped session directory
   - Starts TFTP receiver in background

2. **Launch Phase**
   - Spawns expect script for each device in parallel
   - Each script logs into the device via telnet
   - Starts tcpdump filtering DHCP traffic (ports 67/68)
   - All devices begin capturing simultaneously

3. **Capture Phase**
   - All devices capture simultaneously
   - Monitors for Ctrl+C interrupt
   - Waits for specified duration or interrupt

4. **Transfer Phase**
   - **Simultaneous mode (default)**: All devices transfer at once
   - **Staggered mode**: Devices wait for their assigned delay before transferring
     - Device 0: Transfers immediately
     - Device 1: Waits N seconds, then transfers
     - Device 2: Waits 2N seconds, then transfers
     - etc.
   - TFTP receiver saves files with unique names
   - Devices clean up temporary files after successful transfer

5. **Cleanup**
   - Stops TFTP receiver
   - Displays summary of captured files
   - Exits gracefully

## TFTP Transfer Modes

### When to Use Each Mode

**Simultaneous Mode (default)**
- ✅ Fastest (all transfers at once)
- ⚠️ May cause network congestion with 7 devices
- ⚠️ Higher chance of TFTP failures
- Best for: Testing, small captures, reliable networks

**Staggered Mode (--stagger N)**
- ✅ More reliable (avoids congestion)
- ✅ Predictable transfer order
- ⚠️ Takes longer (N seconds × 6 devices)
- Best for: Production, large captures, unreliable networks
- **Recommended setting**: `--stagger 10` (60 seconds total)

**Sequential Mode (--sequential)**
- ✅ Most reliable (one at a time)
- ✅ Easy to debug
- ⚠️ Slowest (15 seconds × 6 = 90 seconds)
- Best for: Debugging transfer issues

### Transfer Time Comparison

| Mode | Transfer Pattern | Total Time | Reliability |
|------|------------------|------------|-------------|
| Simultaneous | All at once | ~10-30s | Low |
| --stagger 5 | 0s, 5s, 10s, 15s, 20s, 25s, 30s | ~40s | Medium |
| --stagger 10 | 0s, 10s, 20s, 30s, 40s, 50s, 60s | ~70s | High |
| --sequential | 0s, 15s, 30s, 45s, 60s, 75s, 90s | ~100s | Highest |

## Troubleshooting

### Permission Denied on Port 69

TFTP requires port 69 which needs root access:
```bash
sudo ./capture_all_satellites.sh
```

### Device Connection Timeout

If a device fails to connect:
- Check device IP is correct
- Verify device is powered on and accessible
- Check network connectivity
- Review device-specific log file

### Missing Capture Files

If a capture file is missing after completion:
- Check the device-specific log file for errors
- Verify TFTP transfer succeeded
- Check `tftp_receiver.log` in session directory
- Ensure sufficient disk space

### TFTP Transfer Failures

If TFTP transfers are failing or timing out:
```bash
# Try staggered mode to reduce congestion
sudo ./capture_all_satellites.sh 900 --stagger 10

# Or use fully sequential transfers
sudo ./capture_all_satellites.sh 900 --sequential
```

Symptoms of simultaneous transfer issues:
- Missing capture files after completion
- "TFTP transfer timeout" messages in logs
- Only some devices transfer successfully
- Network becomes unresponsive during transfers

**Solution**: Use `--stagger 10` or `--sequential` to avoid overwhelming the network.

### tftpy Module Not Found

Install the required Python module:
```bash
pip3 install tftpy
```

## Configuration

To modify the script for your environment:

### Change Password

Edit `capture_all_satellites.sh`:
```bash
PASSWORD="YourPasswordHere"
```

### Change TFTP Server IP

Edit both files:
- `capture_all_satellites.sh`: `TFTP_SERVER="192.168.88.32"`
- `tplink_multi_capture.exp`: `set tftp_server "192.168.88.32"`

### Add/Remove Devices

Edit the DEVICES array in `capture_all_satellites.sh`:
```bash
declare -a DEVICES=(
    "192.168.88.1:main_router"
    "192.168.88.27:satellite_27"
    # Add more devices here
)
```

### Change Capture Filter

Edit `tplink_multi_capture.exp` line with tcpdump command:
```tcl
send "tcpdump -i br0 -w $capture_file port 67 or port 68\r"
```

To capture all traffic:
```tcl
send "tcpdump -i br0 -w $capture_file\r"
```

## Advanced Usage

### Manual Device Capture

To capture from a single device manually:
```bash
./tplink_multi_capture.exp 192.168.88.27 Password1 satellite_27 900 test.pcap
```

Parameters:
1. Router IP address
2. Password
3. Device name (for logging)
4. Duration in seconds
5. Capture filename

## Notes

- Each capture session creates a new timestamped directory
- PCAP files are filtered to DHCP traffic only (ports 67/68)
- Devices capture on the `br0` bridge interface
- Files are removed from devices after successful TFTP transfer
- Signal handling ensures graceful shutdown on Ctrl+C
- All devices must use the same password

## Related Scripts

- `tplink_session.exp` - Original single-device session script
- `tplink_capture.exp` - Original single-device capture script
- `tftp_receiver.py` - TFTP server for receiving files
