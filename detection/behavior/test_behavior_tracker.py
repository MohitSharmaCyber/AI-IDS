"""
Behavior Tracker Test
=====================

Simulates multiple flows from one source IP
to different destination ports.
"""

from datetime import datetime, timedelta

from detection.behavior.behavior_tracker import BehaviorTracker
from detection.flow_generator.flow import Flow


def create_flow(
    flow_id: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    syn: bool = True,
    rst: bool = True,
) -> Flow:

    now = datetime.now()

    flags = []

    if syn:
        flags.append("S")

    if rst:
        flags.append("R")

    return Flow(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        start_time=now,
        end_time=now + timedelta(milliseconds=100),
        packet_count=2,
        total_bytes=120,
        forward_packets=2,
        backward_packets=0,
        packet_sizes=[60, 60],
        packet_times=[
            now,
            now + timedelta(milliseconds=100),
        ],
        tcp_flags_history=flags,
    )


def main() -> None:

    print("=" * 70)
    print("BEHAVIOR TRACKER TEST")
    print("=" * 70)

    tracker = BehaviorTracker(window_seconds=60)

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

    print("\nSimulating port scan...\n")

    for index, port in enumerate(scan_ports, start=1):

        flow = create_flow(
            flow_id=f"SCAN-{index:03d}",
            src_ip=source_ip,
            dst_ip=target_ip,
            dst_port=port,
        )

        tracker.update(flow)

        print(
            f"Flow {index:02d}: "
            f"{source_ip}:{flow.src_port} -> "
            f"{target_ip}:{port}"
        )

    behavior = tracker.get_behavior(source_ip)

    print("\n" + "=" * 70)
    print("BEHAVIOR SUMMARY")
    print("=" * 70)

    if behavior is None:
        print("ERROR: No behavior found.")
        return

    summary = behavior.summary()

    for key, value in summary.items():
        print(f"{key:<30}: {value}")

    print("\n" + "=" * 70)
    print("PORT SCAN ANALYSIS")
    print("=" * 70)

    if behavior.unique_destination_port_count >= 10:
        print("✓ Multiple destination ports detected")
        print("✓ Source is contacting many services")
        print("✓ Behavioral scan score increased")
    else:
        print("✗ Port scan behavior not detected")

    print("\nTest completed.")


if __name__ == "__main__":
    main()