"""
FlowManager Integration Test

Tests:
    1. Flow creation
    2. Bidirectional packet processing
    3. Flow statistics
    4. Timeout detection
    5. Completed flow handling
    6. ML feature extraction
"""

from datetime import datetime, timedelta

from detection.flow_generator.flow_manager import FlowManager
from detection.flow_generator.feature_extractor import FeatureExtractor
from detection.packet_capture.packet import Packet


def create_packet(
    timestamp,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    packet_size=500,
    tcp_flags="A",
):
    return Packet(
        timestamp=timestamp,
        interface="Wi-Fi",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
        packet_size=packet_size,
        payload_size=max(packet_size - 20, 0),
        ttl=64,
        tcp_flags=tcp_flags,
    )


def main():

    print("=" * 70)
    print("FLOW MANAGER + TIMEOUT INTEGRATION TEST")
    print("=" * 70)

    # ------------------------------------------------------------
    # Create FlowManager
    # ------------------------------------------------------------

    manager = FlowManager(
        idle_timeout=5.0
    )

    base_time = datetime.now()

    # ------------------------------------------------------------
    # Create bidirectional traffic
    # ------------------------------------------------------------

    packets = [
        create_packet(
            base_time,
            "192.168.1.100",
            50000,
            "8.8.8.8",
            443,
            500,
            "S",
        ),

        create_packet(
            base_time + timedelta(seconds=1),
            "8.8.8.8",
            443,
            "192.168.1.100",
            50000,
            1500,
            "SA",
        ),

        create_packet(
            base_time + timedelta(seconds=2),
            "192.168.1.100",
            50000,
            "8.8.8.8",
            443,
            350,
            "A",
        ),

        create_packet(
            base_time + timedelta(seconds=3),
            "8.8.8.8",
            443,
            "192.168.1.100",
            50000,
            1200,
            "PA",
        ),
    ]

    # ------------------------------------------------------------
    # Process packets
    # ------------------------------------------------------------

    for packet in packets:
        manager.process_packet(packet)

    print()
    print("Active Flows:", manager.total_flows())

    # ------------------------------------------------------------
    # Display active flow
    # ------------------------------------------------------------

    active_flows = manager.get_active_flows()

    for flow in active_flows.values():

        print()
        print("Active Flow")
        print("-" * 70)

        print(flow.summary())

        print()
        print("Packets       :", flow.packet_count)
        print("Total Bytes   :", flow.total_bytes)
        print("Forward       :", flow.forward_packets)
        print("Backward      :", flow.backward_packets)

    # ------------------------------------------------------------
    # Test timeout
    # ------------------------------------------------------------

    expiration_time = base_time + timedelta(seconds=10)

    print()
    print("=" * 70)
    print("TIMEOUT TEST")
    print("=" * 70)

    print()
    print("Expiration Check Time :", expiration_time)

    expired_flows = manager.expire_flows(
        current_time=expiration_time
    )

    print()
    print("Expired Flows :", len(expired_flows))

    print("Active Flows  :", manager.total_flows())

    print(
        "Completed Flows:",
        manager.total_completed_flows()
    )

    # ------------------------------------------------------------
    # Display completed flow
    # ------------------------------------------------------------

    for flow in expired_flows:

        print()
        print("Completed Flow")
        print("-" * 70)

        print(flow.summary())

        print()
        print("Flow ID       :", flow.flow_id)
        print("Packets       :", flow.packet_count)
        print("Total Bytes   :", flow.total_bytes)
        print("Forward       :", flow.forward_packets)
        print("Backward      :", flow.backward_packets)

        # --------------------------------------------------------
        # Feature extraction
        # --------------------------------------------------------

        print()
        print("ML FEATURES")
        print("-" * 70)

        features = FeatureExtractor.extract(flow)

        for key, value in features.items():
            print(f"{key:28}: {value}")

    print()
    print("=" * 70)
    print("TEST COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    main()