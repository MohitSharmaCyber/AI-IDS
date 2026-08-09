"""
ML Engine Integration Test

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from datetime import datetime, timedelta

from detection.ml_detector.ml_engine import MLEngine
from detection.flow_generator.flow import Flow


def create_flow(
    flow_id: str,
    packet_sizes: list[int],
    start_time: datetime,
) -> Flow:

    flow = Flow(
        flow_id=flow_id,
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        start_time=start_time,
        end_time=start_time,
    )

    for index, size in enumerate(packet_sizes):

        timestamp = (
            start_time
            + timedelta(seconds=index + 1)
        )

        flow.end_time = timestamp

        flow.forward_packets += 1

        flow.update(
            packet_size=size,
            timestamp=timestamp,
            tcp_flags="A",
        )

    return flow


def main():

    print()
    print("=" * 70)
    print("AI-IDS MACHINE LEARNING ENGINE TEST")
    print("=" * 70)

    # ------------------------------------------------------------
    # Create training flows
    # ------------------------------------------------------------

    training_flows = [

        create_flow(
            "TRAIN-001",
            [500, 520, 480, 510, 490],
            datetime.now(),
        ),

        create_flow(
            "TRAIN-002",
            [510, 500, 495, 505, 515],
            datetime.now(),
        ),

        create_flow(
            "TRAIN-003",
            [480, 490, 500, 510, 495],
            datetime.now(),
        ),

        create_flow(
            "TRAIN-004",
            [520, 510, 500, 530, 515],
            datetime.now(),
        ),

        create_flow(
            "TRAIN-005",
            [490, 505, 500, 495, 510],
            datetime.now(),
        ),

        create_flow(
            "TRAIN-006",
            [500, 500, 510, 505, 495],
            datetime.now(),
        ),

        create_flow(
            "TRAIN-007",
            [505, 515, 495, 500, 510],
            datetime.now(),
        ),

        create_flow(
            "TRAIN-008",
            [495, 500, 505, 510, 500],
            datetime.now(),
        ),
    ]

    # ------------------------------------------------------------
    # Train ML engine
    # ------------------------------------------------------------

    engine = MLEngine(
        contamination=0.1,
        random_state=42,
    )

    engine.train(training_flows)

    print()
    print("Model Status")
    print("-" * 70)

    print(engine.status())

    # ------------------------------------------------------------
    # Test normal flow
    # ------------------------------------------------------------

    normal_flow = create_flow(
        "TEST-NORMAL",
        [500, 510, 495, 505, 500],
        datetime.now(),
    )

    normal_result = engine.predict(normal_flow)

    print()
    print("NORMAL FLOW")
    print("-" * 70)

    print(f"Label          : {normal_result['label']}")
    print(
        f"Anomaly Score  : "
        f"{normal_result['anomaly_score']:.4f}"
    )
    print(
        f"Decision Score : "
        f"{normal_result['decision_score']:.4f}"
    )

    # ------------------------------------------------------------
    # Test unusual flow
    # ------------------------------------------------------------

    anomalous_flow = create_flow(
        "TEST-ANOMALOUS",
        [40, 1500, 64, 1500, 32],
        datetime.now(),
    )

    anomalous_result = engine.predict(
        anomalous_flow
    )

    print()
    print("ANOMALOUS FLOW")
    print("-" * 70)

    print(f"Label          : {anomalous_result['label']}")
    print(
        f"Anomaly Score  : "
        f"{anomalous_result['anomaly_score']:.4f}"
    )
    print(
        f"Decision Score : "
        f"{anomalous_result['decision_score']:.4f}"
    )


if __name__ == "__main__":
    main()