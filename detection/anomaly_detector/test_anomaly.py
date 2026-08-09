from datetime import datetime, timedelta

from detection.anomaly_detector.detector import AnomalyDetector
from detection.flow_generator.flow import Flow
from detection.ml_detector.ml_engine import MLEngine


def create_flow(
    flow_id,
    packet_sizes,
    flags,
):
    start = datetime.now()

    flow = Flow(
        flow_id=flow_id,
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        start_time=start,
        end_time=start,
    )

    for i, size in enumerate(packet_sizes):

        timestamp = (
            start
            + timedelta(seconds=i + 1)
        )

        flow.end_time = timestamp

        flow.forward_packets += 1

        flow.update(
            packet_size=size,
            timestamp=timestamp,
            tcp_flags=flags[i],
        )

    return flow


def main():

    print()
    print("=" * 70)
    print("AI-IDS END-TO-END ANOMALY DETECTION TEST")
    print("=" * 70)

    # ============================================================
    # TRAINING DATA
    # ============================================================

    training_flows = []

    normal_sizes = [
        [500, 510, 495, 505, 500],
        [510, 500, 505, 495, 515],
        [490, 500, 510, 505, 495],
        [500, 505, 500, 510, 495],
        [505, 495, 500, 500, 510],
        [495, 510, 505, 500, 500],
        [500, 500, 505, 495, 510],
        [510, 505, 495, 500, 505],
    ]

    normal_flags = [
        ["A", "A", "A", "A", "A"],
        ["A", "A", "A", "A", "A"],
        ["A", "A", "A", "A", "A"],
        ["A", "A", "A", "A", "A"],
        ["A", "A", "A", "A", "A"],
        ["A", "A", "A", "A", "A"],
        ["A", "A", "A", "A", "A"],
        ["A", "A", "A", "A", "A"],
    ]

    for i in range(len(normal_sizes)):

        training_flows.append(
            create_flow(
                f"TRAIN-{i+1:03}",
                normal_sizes[i],
                normal_flags[i],
            )
        )

    # ============================================================
    # TRAIN ML ENGINE
    # ============================================================

    ml_engine = MLEngine(
        contamination=0.1,
        random_state=42,
    )

    ml_engine.train(
        training_flows
    )

    # ============================================================
    # CREATE ANOMALY DETECTOR
    # ============================================================

    detector = AnomalyDetector(
        ml_engine=ml_engine
    )

    # ============================================================
    # TEST NORMAL FLOW
    # ============================================================

    normal_flow = create_flow(
        "TEST-NORMAL",
        [500, 510, 495, 505, 500],
        ["A", "A", "A", "A", "A"],
    )

    normal_result = detector.analyze_with_breakdown(
        normal_flow
    )

    print()
    print("NORMAL FLOW")
    print("-" * 70)

    for key, value in normal_result.items():
        print(f"{key:22}: {value}")

    # ============================================================
    # TEST ANOMALOUS FLOW
    # ============================================================

    anomalous_flow = create_flow(
        "TEST-ANOMALOUS",
        [40, 1500, 64, 1500, 32],
        ["S", "S", "S", "S", "R"],
    )

    anomalous_result = detector.analyze_with_breakdown(
        anomalous_flow
    )

    print()
    print("ANOMALOUS FLOW")
    print("-" * 70)

    for key, value in anomalous_result.items():
        print(f"{key:22}: {value}")


if __name__ == "__main__":
    main()