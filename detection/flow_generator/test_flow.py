"""
test_flow.py

Tests the Enterprise Flow Manager and
Feature Extraction Engine.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from datetime import datetime
import time

from detection.flow_generator.flow_manager import FlowManager
from detection.flow_generator.feature_extractor import FeatureExtractor
from detection.packet_capture.packet import Packet


# --------------------------------------------------
# Initialize Flow Manager
# --------------------------------------------------

manager = FlowManager()


# --------------------------------------------------
# Simulated Network Traffic
# --------------------------------------------------

traffic = [
    ("192.168.1.100", 50000, "8.8.8.8", 443),
    ("192.168.1.100", 50000, "8.8.8.8", 443),
    ("8.8.8.8", 443, "192.168.1.100", 50000),
    ("192.168.1.100", 50000, "8.8.8.8", 443),
    ("8.8.8.8", 443, "192.168.1.100", 50000),
]


# --------------------------------------------------
# Packet Sizes
# --------------------------------------------------

sizes = [
    60,
    1500,
    350,
    1200,
    800,
]


# --------------------------------------------------
# TCP Flags
# --------------------------------------------------

flags = [
    "S",    # SYN
    "SA",   # SYN + ACK
    "A",    # ACK
    "PA",   # PSH + ACK
    "FA",   # FIN + ACK
]


# --------------------------------------------------
# Generate Packets
# --------------------------------------------------

for i, (src, sport, dst, dport) in enumerate(traffic):

    packet = Packet(
        timestamp=datetime.now(),
        interface="Wi-Fi",
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol="TCP",
        packet_size=sizes[i],
        payload_size=sizes[i] - 20,
        ttl=64,
        tcp_flags=flags[i],
    )

    manager.process_packet(packet)

    time.sleep(0.5)


# --------------------------------------------------
# Display Results
# --------------------------------------------------

print("\n" + "=" * 70)
print("FLOW SUMMARY")
print("=" * 70)

print(f"\nActive Flows : {manager.total_flows()}\n")

for flow in manager.get_active_flows().values():

    print(flow.summary())

    print("\nFlow Dictionary\n")
    print(flow.to_dict())

    print("\n" + "=" * 70)
    print("ML FEATURE VECTOR")
    print("=" * 70)

    features = FeatureExtractor.extract(flow)

    for key, value in features.items():
        print(f"{key:30}: {value}")