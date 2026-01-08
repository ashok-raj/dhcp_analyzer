#!/usr/bin/env python3
"""
Simple TFTP receiver - run this to accept incoming TFTP transfers
Files will be saved to the current directory
"""
import tftpy
import sys

# Directory where files will be saved
SAVE_DIR = "."
PORT = 69

print(f"Starting TFTP receiver on port {PORT}")
print(f"Files will be saved to: {SAVE_DIR}")
print("Waiting for incoming transfers... (Press Ctrl+C to stop)")

# Create TFTP server
server = tftpy.TftpServer(SAVE_DIR)

try:
    # Start listening
    server.listen('0.0.0.0', PORT)
except KeyboardInterrupt:
    print("\nStopping TFTP receiver...")
    sys.exit(0)
except PermissionError:
    print("\nError: Port 69 requires root privileges")
    print("Run with: sudo python3 tftp_receiver.py")
    sys.exit(1)
except Exception as e:
    print(f"\nError: {e}")
    sys.exit(1)
