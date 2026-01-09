# Complete Capture & Analysis Workflow

This guide shows the complete workflow from discovering satellites to analyzing captures.

## Step 1: First Time Setup (Auto-Discovery)

Discover all TP-Link devices on your network:

```bash
sudo ./capture_all_satellites.sh --scan
```

**Example Output:**
```
============================================
TP-Link Satellite Discovery
============================================

Scanning network: 192.168.88.0/24
Looking for TP-Link devices...

Using arp-scan for discovery...
  ✓ Found: 192.168.88.1 (MAC: 50:3d:d1:25:f5:39) - HB810
  ✓ Found: 192.168.88.27 (MAC: 78:20:51:71:1a:b9) - HB610V2
  ✓ Found: 192.168.88.58 (MAC: 78:20:51:71:48:79) - HB610V2
  ✓ Found: 192.168.88.59 (MAC: 78:20:51:70:f5:d1) - HB610V2
  ✓ Found: 192.168.88.79 (MAC: 78:20:51:70:f8:81) - HB610V2
  ✓ Found: 192.168.88.80 (MAC: 78:20:51:71:14:41) - HB610V2
  ✓ Found: 192.168.88.87 (MAC: 78:20:51:71:1a:21) - HB610V2

============================================
Discovery complete: Found 7 device(s)
============================================

Discovered devices:

  [1] 192.168.88.1 - main_router (HB810)
  [2] 192.168.88.27 - satellite_27 (HB610V2)
  [3] 192.168.88.58 - satellite_58 (HB610V2)
  [4] 192.168.88.59 - satellite_59 (HB610V2)
  [5] 192.168.88.79 - satellite_79 (HB610V2)
  [6] 192.168.88.80 - satellite_80 (HB610V2)
  [7] 192.168.88.87 - satellite_87 (HB610V2)

Save these devices to satellites.conf? (y/n) y
✓ Configuration saved to satellites.conf

You can now run:
  sudo ./capture_all_satellites.sh
```

**What just happened?**
- Network was scanned for TP-Link devices
- 7 devices discovered (1 router + 6 satellites)
- Configuration saved to `satellites.conf`
- Ready for capture!

---

## Step 2: Start Capture

Run a capture session with staggered TFTP transfers (recommended):

```bash
sudo ./capture_all_satellites.sh 900 --stagger 10
```

**Example Output:**
```
Loading devices from satellites.conf...
  ✓ main_router (192.168.88.1) - reachable
  ✓ satellite_27 (192.168.88.27) - reachable
  ✓ satellite_58 (192.168.88.58) - reachable
  ✓ satellite_59 (192.168.88.59) - reachable
  ✓ satellite_79 (192.168.88.79) - reachable
  ✓ satellite_80 (192.168.88.80) - reachable
  ✓ satellite_87 (192.168.88.87) - reachable

Loaded 7 device(s) from configuration

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
...

All captures launched successfully!
Monitoring progress... (Press Ctrl+C to stop early)

[15 minutes later or Ctrl+C pressed]

Stopping TFTP receiver...

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
============================================
```

**What just happened?**
- All 7 devices started capturing simultaneously
- Captured for 15 minutes (or until Ctrl+C)
- Devices transferred files via TFTP (staggered by 10s)
- All captures saved to timestamped directory

---

## Step 3: Analyze Captures

### Quick Overview

Check what you captured:

```bash
cd capture_session_20260109_143000
ls -lh *.pcap
```

### Analyze Main Router

```bash
../dhcp_interactive.py dhcp_main_router_20260109_143000.pcap
```

```
dhcp> summary
dhcp> ratios
dhcp> duplicates
dhcp> renewals
```

### Analyze Specific Satellite

```bash
../dhcp_interactive.py dhcp_satellite_80_20260109_143000.pcap
```

```
dhcp> summary
dhcp> list 20
dhcp> failed_dora
```

### Compare All Satellites

Create a quick comparison script:

```bash
#!/bin/bash
for pcap in dhcp_satellite_*.pcap; do
    echo "=== $pcap ==="
    echo "summary" | ../dhcp_interactive.py "$pcap" | grep "Total DHCP packets"
    echo ""
done
```

---

## Step 4: Common Scenarios

### Scenario 1: Device is Unreachable During Capture

If a satellite goes offline, it will be detected:

```
Loading devices from satellites.conf...
  ✓ main_router (192.168.88.1) - reachable
  ✓ satellite_27 (192.168.88.27) - reachable
  ✗ satellite_80 (192.168.88.80) - unreachable

Warning: 1 device(s) unreachable and will be skipped

Loaded 6 device(s) from configuration
```

The capture proceeds with the available 6 devices.

### Scenario 2: Re-scan After Network Changes

If you add/remove satellites:

```bash
# Re-discover devices
sudo ./capture_all_satellites.sh --scan

# Old config is backed up automatically
# New config is saved
```

### Scenario 3: Analyze Specific Time Window

If you stopped early with Ctrl+C, check actual capture duration:

```bash
tcpdump -r dhcp_main_router_20260109_143000.pcap -n | head -1
tcpdump -r dhcp_main_router_20260109_143000.pcap -n | tail -1
```

### Scenario 4: Manual Configuration Edit

Edit `satellites.conf` to temporarily disable a device:

```bash
nano satellites.conf
```

```
# Comment out device to skip
192.168.88.1:main_router
192.168.88.27:satellite_27
# 192.168.88.58:satellite_58  ← Commented out
192.168.88.59:satellite_59
...
```

Next capture will skip commented devices.

---

## Step 5: Troubleshooting

### TFTP Transfer Failures

If transfers fail, use sequential mode:

```bash
sudo ./capture_all_satellites.sh 900 --sequential
```

This transfers one device at a time with 15s delays.

### Network Congestion

Symptoms:
- Missing capture files
- Transfer timeout messages
- Some devices succeed, others fail

Solution:
```bash
# Increase stagger delay
sudo ./capture_all_satellites.sh 900 --stagger 20
```

### Can't Discover Satellites

Install better scanning tools:

```bash
# Install arp-scan (most reliable)
sudo apt-get install arp-scan

# Or install nmap
sudo apt-get install nmap

# Then re-scan
sudo ./capture_all_satellites.sh --scan
```

---

## Complete Example Session

```bash
# 1. First time setup
sudo ./capture_all_satellites.sh --scan
# [Select 'y' to save configuration]

# 2. Start 15-minute capture with staggered TFTP
sudo ./capture_all_satellites.sh 900 --stagger 10
# [Wait 15 minutes or press Ctrl+C when done]

# 3. Enter session directory
cd capture_session_20260109_143000

# 4. Analyze main router
../dhcp_interactive.py dhcp_main_router_20260109_143000.pcap

# 5. Check for issues
dhcp> summary
dhcp> ratios           # Check for duplicate responses
dhcp> duplicates       # Find duplicate ACKs
dhcp> failed_dora      # Find failed DHCP attempts
dhcp> renewals         # Check renewal patterns

# 6. Analyze problematic satellite
../dhcp_interactive.py dhcp_satellite_80_20260109_143000.pcap
dhcp> summary
dhcp> list_mac         # See all DORA sequences
dhcp> storms           # Check for retry storms

# 7. Compare packet counts
for pcap in *.pcap; do
    echo "$pcap: $(tcpdump -r $pcap -n 2>/dev/null | wc -l) packets"
done

# 8. If issue found, check specific MAC across all satellites
for pcap in *.pcap; do
    echo "=== $pcap ==="
    ../dhcp_interactive.py "$pcap" <<EOF
filter 78:20:51:71:14:41
exit
EOF
done
```

---

## Tips

1. **Always use --stagger or --sequential** for reliable transfers
2. **Start with --scan** to auto-discover devices
3. **Check satellites.conf** before each capture to ensure devices are correct
4. **Use Ctrl+C** if you have enough data (saves time)
5. **Keep session directories** for historical comparison
6. **Document changes** if you modify network topology

---

## Quick Reference

```bash
# Discovery
sudo ./capture_all_satellites.sh --scan

# Capture (recommended)
sudo ./capture_all_satellites.sh 900 --stagger 10

# Quick capture (5 min)
sudo ./capture_all_satellites.sh 300 --stagger 10

# Analysis
cd capture_session_*/
../dhcp_interactive.py dhcp_main_router_*.pcap
```
