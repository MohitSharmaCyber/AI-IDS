"""
Test live packet capture.
"""

import time

from detection.packet_capture.capture import PacketCapture

capture = PacketCapture()

capture.list_interfaces()

input("\nPress ENTER to start packet capture...")

capture.start()

try:

    while True:

        time.sleep(1)

except KeyboardInterrupt:

    print("\nStopping...\n")

    capture.stop()