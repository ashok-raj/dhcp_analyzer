#!/bin/bash
#
# Test Hypothesis: Missing T1/T2 Options Causing Fast Renewals
#
# This script helps test whether adding explicit T1/T2 options fixes the issue

cat << 'EOF'
================================================================================
  DHCP T1/T2 Testing Guide
================================================================================

HYPOTHESIS: TP-Link clients renew every 10 seconds because:
  1. DHCP server doesn't send Option 58 (T1) and Option 59 (T2)
  2. TP-Link firmware bug: Falls back to 10s instead of calculating from lease

TEST PLAN:
  1. Configure DHCP server to explicitly send T1/T2 options
  2. Capture new DHCP traffic
  3. Check if renewal interval changes

--------------------------------------------------------------------------------
STEP 1: Configure DHCP Server
--------------------------------------------------------------------------------

Option A - Router Web Interface:
  1. Login to router (192.168.88.1)
  2. Navigate to DHCP settings
  3. Look for "Advanced DHCP Options"
  4. Add custom options:
     Option 58 (T1): 86400 seconds (24 hours)
     Option 59 (T2): 151200 seconds (42 hours)

Option B - dnsmasq (if using):
  Add to /etc/dnsmasq.conf:
    dhcp-option=58,86400    # T1 renewal time
    dhcp-option=59,151200   # T2 rebinding time

  Restart: sudo systemctl restart dnsmasq

Option C - ISC DHCP Server (if using):
  Add to /etc/dhcp/dhcpd.conf:
    subnet 192.168.88.0 netmask 255.255.255.0 {
      option dhcp-renewal-time 86400;      # T1
      option dhcp-rebinding-time 151200;   # T2
      default-lease-time 172800;
      max-lease-time 172800;
    }

  Restart: sudo systemctl restart isc-dhcp-server

--------------------------------------------------------------------------------
STEP 2: Capture New Traffic
--------------------------------------------------------------------------------

# Capture for 5 minutes
sudo tcpdump -i eth0 -w test_with_t1t2.pcap port 67 or port 68 &
TCPDUMP_PID=$!

echo "Capturing for 5 minutes..."
echo "Watch for DHCP renewals from TP-Link clients"
sleep 300

sudo kill $TCPDUMP_PID

--------------------------------------------------------------------------------
STEP 3: Analyze Results
--------------------------------------------------------------------------------

./dhcp_interactive.py test_with_t1t2.pcap

# In the analyzer:
dhcp> renewals                    # Check renewal interval
dhcp> transaction <xid>           # Check if T1/T2 present in ACK
dhcp> vendor 78:20:51:71:14:41   # Check TP-Link behavior

EXPECTED RESULTS:
  If hypothesis is correct:
    • Renewal interval should change from 10s → ~24 hours
    • Transaction details should show Option 58 and 59

  If hypothesis is wrong:
    • Renewal interval stays at 10s
    • Need to investigate other causes

--------------------------------------------------------------------------------
STEP 4: Workarounds if T1/T2 Doesn't Help
--------------------------------------------------------------------------------

If adding T1/T2 doesn't fix it:

1. Reduce lease time to match client behavior:
   Set lease to 60 seconds (client renews at 30s = 50%)
   This reduces but doesn't fix the excessive renewals

2. Create DHCP reservation for TP-Link devices:
   Prevents IP changes, reduces impact of renewals

3. Update TP-Link firmware:
   Check for newer firmware addressing DHCP issues

4. Replace TP-Link devices:
   If firmware can't be fixed, consider alternative hardware

================================================================================

For detailed analysis of current behavior, see:
  EXAMPLE_ANALYSIS.md

EOF
