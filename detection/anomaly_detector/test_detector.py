"""
Anomaly Detector Integration Tests

Tests:
    - Normal traffic
    - Suspicious packet behavior
    - Multi-flow port scanning
    - Behavioral aggregation
    - Detector breakdown

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from datetime import datetime, timedelta

from detection.anomaly_detector.detector import AnomalyDetector
from detection.flow_generator.flow import Flow


def create_flow(
    flow_id: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    flags: list[str],
    packet_sizes: list[int] | None = None,
) -> Flow:
    """
    Create a synthetic Flow for testing.
    """

    now = datetime.now()

    if packet_sizes is None:
        packet_sizes = [60, 60]

    return Flow(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        start_time=now,
        end_time=now + timedelta(milliseconds=100),
        packet_count=len(packet_sizes),
        total_bytes=sum(packet_sizes),
        forward_packets=len(packet_sizes),
        backward_packets=0,
        average_packet_size=(
            sum(packet_sizes) / len(packet_sizes)
            if packet_sizes
            else 0.0
        ),
        duration=0.1,
        packets_per_second=len(packet_sizes) / 0.1,
        bytes_per_second=sum(packet_sizes) / 0.1,
        packet_sizes=packet_sizes,
        packet_times=[
            now + timedelta(milliseconds=index * 10)
            for index in range(len(packet_sizes))
        ],
        tcp_flags_history=flags,
    )


def test_normal_traffic() -> None:
    """
    Test a basic normal TCP flow.
    """

    detector = AnomalyDetector()

    flow = create_flow(
        flow_id="NORMAL-001",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        dst_port=443,
        flags=["S", "SA", "A"],
        packet_sizes=[500, 600, 700],
    )

    result = detector.analyze_with_breakdown(flow)

    print("\n" + "=" * 70)
    print("TEST 1 - NORMAL TRAFFIC")
    print("=" * 70)

    for key, value in result.items():
        print(f"{key:<40}: {value}")

    assert result["attack_type"] is None
    assert result["behavior_total_flows"] == 1


def test_multi_flow_port_scan() -> None:
    """
    Test detection of a port scan spread across
    multiple independent flows.
    """

    detector = AnomalyDetector()

    source_ip = "192.168.1.100"
    target_ip = "192.168.1.10"

    scan_ports = [
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

    print("\n" + "=" * 70)
    print("TEST 2 - MULTI-FLOW PORT SCAN")
    print("=" * 70)

    last_result = None

    for index, port in enumerate(scan_ports, start=1):

        flow = create_flow(
            flow_id=f"SCAN-{index:03d}",
            src_ip=source_ip,
            dst_ip=target_ip,
            dst_port=port,
            flags=["S", "R"],
        )

        last_result = detector.analyze_with_breakdown(flow)

        print(
            f"Flow {index:02d} | "
            f"Destination Port: {port:>3} | "
            f"Behavior Ports: "
            f"{last_result['behavior_unique_destination_ports']:>2} | "
            f"Behavior Score: "
            f"{last_result['behavior_scan_score']:.2f} | "
            f"Final Score: "
            f"{last_result['final_score']:.2f}"
        )

    assert last_result is not None

    print("\nFinal behavioral result:")

    for key, value in last_result.items():
        if key.startswith("behavior_") or key in {
            "final_score",
            "severity",
            "attack_type",
            "mitre_technique",
            "label",
        }:
            print(f"{key:<40}: {value}")

    assert last_result["behavior_total_flows"] == 12
    assert last_result["behavior_unique_destination_ports"] == 12
    assert last_result["behavior_scan_score"] >= 0.40


def test_behavioral_summary() -> None:
    """
    Test access to the detector's behavioral summary.
    """

    detector = AnomalyDetector()

    flow = create_flow(
        flow_id="SUMMARY-001",
        src_ip="10.0.0.5",
        dst_ip="10.0.0.10",
        dst_port=22,
        flags=["S", "R"],
    )

    detector.analyze(flow)

    summaries = detector.get_behavior_summary()

    print("\n" + "=" * 70)
    print("TEST 3 - BEHAVIORAL SUMMARY")
    print("=" * 70)

    for summary in summaries:
        print(summary)

    assert len(summaries) == 1
    assert summaries[0]["src_ip"] == "10.0.0.5"


def test_behavior_reset() -> None:
    """
    Test clearing behavioral tracking state.
    """

    detector = AnomalyDetector()

    flow = create_flow(
        flow_id="RESET-001",
        src_ip="10.0.0.20",
        dst_ip="10.0.0.30",
        dst_port=80,
        flags=["S", "SA", "A"],
    )

    detector.analyze(flow)

    assert len(detector.get_behavior_summary()) == 1

    detector.reset_behavior()

    print("\n" + "=" * 70)
    print("TEST 4 - BEHAVIOR RESET")
    print("=" * 70)

    print("Behavior tracker reset successfully.")

    assert len(detector.get_behavior_summary()) == 0


def main() -> None:
    """
    Run all detector tests.
    """

    print("\n")
    print("#" * 70)
    print("AI-IDS ANOMALY DETECTOR TEST SUITE")
    print("#" * 70)

    test_normal_traffic()
    test_multi_flow_port_scan()
    test_behavioral_summary()
    test_behavior_reset()

    print("\n" + "#" * 70)
    print("ALL DETECTOR TESTS PASSED")
    print("#" * 70)


if __name__ == "__main__":
    main()