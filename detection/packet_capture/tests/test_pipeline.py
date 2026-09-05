"""
test_pipeline.py

End-to-end offline test for the AI-IDS detection pipeline.

Pipeline tested:

Scapy Packet
    ↓
PacketParser
    ↓
FlowManager
    ↓
AnomalyDetector
    ↓
BehaviorTracker
    ↓
AttackClassifier

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from scapy.all import IP, TCP, Raw

from detection.packet_capture.parser import PacketParser
from detection.flow_generator.flow_manager import FlowManager
from detection.anomaly_detector.detector import AnomalyDetector


def create_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: str = "S",
    payload_size: int = 0,
):
    """
    Create a synthetic TCP/IP packet.
    """

    packet = (
        IP(
            src=src_ip,
            dst=dst_ip,
        )
        / TCP(
            sport=src_port,
            dport=dst_port,
            flags=flags,
        )
    )

    if payload_size > 0:
        packet = packet / Raw(
            load=b"A" * payload_size
        )

    return packet


def test_normal_pipeline():
    """
    Test normal traffic through the complete pipeline.
    """

    print("\n" + "=" * 70)
    print("TEST 1 - NORMAL TRAFFIC PIPELINE")
    print("=" * 70)

    flow_manager = FlowManager()
    detector = AnomalyDetector()

    packets = [
        create_tcp_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=443,
            flags="S",
            payload_size=100,
        ),
        create_tcp_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=443,
            flags="SA",
            payload_size=100,
        ),
        create_tcp_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=50000,
            dst_port=443,
            flags="A",
            payload_size=100,
        ),
    ]

    for packet in packets:

        parsed = PacketParser.parse(
            packet,
            interface="TEST_INTERFACE",
        )

        assert parsed is not None

        flow = flow_manager.process_packet(
            parsed
        )

        analyzed = detector.analyze(
            flow
        )

    print(
        f"Flow ID        : {analyzed.flow_id}"
    )

    print(
        f"Anomaly Score  : "
        f"{analyzed.anomaly_score:.2f}"
    )

    print(
        f"Severity       : "
        f"{analyzed.severity}"
    )

    print(
        f"Attack Type    : "
        f"{analyzed.attack_type}"
    )

    print(
        f"MITRE          : "
        f"{analyzed.mitre_technique}"
    )

    print(
        f"Label          : "
        f"{analyzed.label}"
    )

    assert analyzed.severity == "Normal"
    assert analyzed.attack_type is None
    assert analyzed.label == "Benign"

    print("Normal pipeline test passed.")


def test_port_scan_pipeline():
    """
    Test multi-flow port scan through the
    complete packet-processing pipeline.
    """

    print("\n" + "=" * 70)
    print("TEST 2 - PORT SCAN PIPELINE")
    print("=" * 70)

    flow_manager = FlowManager()
    detector = AnomalyDetector()

    destination_ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
    ]

    source_ip = "192.168.1.100"
    destination_ip = "192.168.1.10"

    last_analyzed_flow = None

    for index, destination_port in enumerate(
        destination_ports,
        start=1,
    ):

        packet = create_tcp_packet(
            src_ip=source_ip,
            dst_ip=destination_ip,
            src_port=40000 + index,
            dst_port=destination_port,
            flags="S",
        )

        parsed = PacketParser.parse(
            packet,
            interface="TEST_INTERFACE",
        )

        assert parsed is not None

        flow = flow_manager.process_packet(
            parsed
        )

        analyzed = detector.analyze(
            flow
        )

        last_analyzed_flow = analyzed

        behavior = detector.get_behavior_summary()

        if behavior:

            summary = behavior[0]

            print(
                f"Port {destination_port:>3} | "
                f"Flows={summary['total_flows']:>2} | "
                f"Ports={summary['unique_destination_ports']:>2} | "
                f"Scan Score="
                f"{summary['scan_score']:.2f} | "
                f"Final="
                f"{analyzed.anomaly_score:.2f}"
            )

    assert last_analyzed_flow is not None

    print("\nFinal Detection Result")
    print("-" * 70)

    print(
        f"Flow ID        : "
        f"{last_analyzed_flow.flow_id}"
    )

    print(
        f"Anomaly Score  : "
        f"{last_analyzed_flow.anomaly_score:.2f}"
    )

    print(
        f"Severity       : "
        f"{last_analyzed_flow.severity}"
    )

    print(
        f"Attack Type    : "
        f"{last_analyzed_flow.attack_type}"
    )

    print(
        f"MITRE          : "
        f"{last_analyzed_flow.mitre_technique}"
    )

    print(
        f"Label          : "
        f"{last_analyzed_flow.label}"
    )

    assert (
        last_analyzed_flow.attack_type
        == "Port Scan"
    )

    assert (
        last_analyzed_flow.mitre_technique
        == "T1046"
    )

    assert (
        last_analyzed_flow.label
        == "Malicious"
    )

    assert (
    last_analyzed_flow.anomaly_score
    >= 0.40
)

    print(
        "Port scan pipeline test passed."
    )


def test_parser_to_flow():
    """
    Verify that PacketParser output is correctly
    consumed by FlowManager.
    """

    print("\n" + "=" * 70)
    print("TEST 3 - PARSER → FLOW MANAGER")
    print("=" * 70)

    packet = create_tcp_packet(
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        src_port=50000,
        dst_port=22,
        flags="S",
        payload_size=50,
    )

    parsed = PacketParser.parse(
        packet,
        interface="TEST_INTERFACE",
    )

    assert parsed is not None

    assert parsed.src_ip == "10.0.0.5"
    assert parsed.dst_ip == "10.0.0.10"
    assert parsed.src_port == 50000
    assert parsed.dst_port == 22
    assert parsed.protocol == "TCP"

    flow_manager = FlowManager()

    flow = flow_manager.process_packet(
        parsed
    )

    assert flow.src_ip == "10.0.0.5"
    assert flow.dst_ip == "10.0.0.10"
    assert flow.src_port == 50000
    assert flow.dst_port == 22
    assert flow.protocol == "TCP"

    assert flow.packet_count == 1

    print(
        f"Flow Created    : {flow.flow_id}"
    )

    print(
        f"Source          : "
        f"{flow.src_ip}:{flow.src_port}"
    )

    print(
        f"Destination     : "
        f"{flow.dst_ip}:{flow.dst_port}"
    )

    print(
        f"Protocol        : "
        f"{flow.protocol}"
    )

    print(
        f"Packet Count    : "
        f"{flow.packet_count}"
    )

    print("Parser → Flow Manager test passed.")


def main():

    print("\n" + "#" * 70)
    print("AI-IDS END-TO-END PIPELINE TEST")
    print("#" * 70)

    test_parser_to_flow()
    test_normal_pipeline()
    test_port_scan_pipeline()

    print("\n" + "#" * 70)
    print("ALL PIPELINE TESTS PASSED")
    print("#" * 70)


if __name__ == "__main__":
    main()