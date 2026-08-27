from datetime import datetime, timedelta

from detection.anomaly_detector.detector import AnomalyDetector
from detection.flow_generator.flow import Flow
from detection.flow_generator.feature_extractor import FeatureExtractor
from detection.ml_detector.ml_engine import MLEngine


def create_flow(flow_id, packet_sizes, flags, backward_packets=0):
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
        timestamp = start + timedelta(seconds=i + 1)

        flow.end_time = timestamp
        flow.forward_packets += 1

        flow.update(
            packet_size=size,
            timestamp=timestamp,
            tcp_flags=flags[i],
        )

    flow.backward_packets = backward_packets

    return flow


def train_ml_engine():
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
                f"TRAIN-{i + 1:03}",
                normal_sizes[i],
                normal_flags[i],
            )
        )

    ml_engine = MLEngine(
        contamination=0.1,
        random_state=42,
    )

    ml_engine.train(training_flows)

    return ml_engine


def print_result(name, result):
    print()
    print("=" * 70)
    print(name)
    print("=" * 70)

    for key, value in result.items():
        print(f"{key:22}: {value}")


def main():

    print()
    print("=" * 70)
    print("AI-IDS MULTI-ATTACK DETECTION TEST")
    print("=" * 70)

    # ------------------------------------------------------------
    # TRAIN ML ENGINE
    # ------------------------------------------------------------

    ml_engine = train_ml_engine()

    detector = AnomalyDetector(
        ml_engine=ml_engine
    )

    # ------------------------------------------------------------
    # 1. NORMAL TRAFFIC
    # ------------------------------------------------------------

    normal_flow = create_flow(
        "NORMAL-001",
        [500, 510, 495, 505, 500],
        ["A", "A", "A", "A", "A"],
    )

    normal_result = detector.analyze_with_breakdown(
        normal_flow
    )

    print_result(
        "1. NORMAL TRAFFIC",
        normal_result
    )

    # ------------------------------------------------------------
    # 2. PORT SCAN / SYN FLOOD
    # ------------------------------------------------------------

    port_scan = create_flow(
        "PORT-SCAN-001",
        [40, 1500, 64, 1500, 32],
        ["S", "S", "S", "S", "R"],
    )

    port_scan_result = detector.analyze_with_breakdown(
        port_scan
    )

    print_result(
        "2. PORT SCAN / SYN ATTACK",
        port_scan_result
    )

    # ------------------------------------------------------------
    # 3. PACKET SIZE ANOMALY
    # ------------------------------------------------------------

    packet_anomaly = create_flow(
        "PACKET-ANOMALY-001",
        [20, 1500, 30, 1500, 40],
        ["A", "A", "A", "A", "A"],
    )

    packet_result = detector.analyze_with_breakdown(
        packet_anomaly
    )

    print_result(
        "3. PACKET SIZE ANOMALY",
        packet_result
    )

    # ------------------------------------------------------------
    # 4. SYN HEAVY TRAFFIC
    # ------------------------------------------------------------

    syn_attack = create_flow(
        "SYN-ATTACK-001",
        [60, 60, 60, 60, 60],
        ["S", "S", "S", "S", "S"],
    )

    syn_result = detector.analyze_with_breakdown(
        syn_attack
    )

    print_result(
        "4. SYN HEAVY ATTACK",
        syn_result
    )

    # ------------------------------------------------------------
    # 5. RST HEAVY TRAFFIC
    # ------------------------------------------------------------

    rst_attack = create_flow(
        "RST-ATTACK-001",
        [500, 500, 500, 500, 500],
        ["R", "R", "R", "R", "A"],
    )

    rst_result = detector.analyze_with_breakdown(
        rst_attack
    )

    print_result(
        "5. RST HEAVY TRAFFIC",
        rst_result
    )

    # ------------------------------------------------------------
    # 6. DISPLAY FEATURES FOR PORT SCAN
    # ------------------------------------------------------------

    print()
    print("=" * 70)
    print("PORT SCAN FEATURE ANALYSIS")
    print("=" * 70)

    features = FeatureExtractor.extract(port_scan)

    for key, value in features.items():
        print(f"{key:30}: {value}")


if __name__ == "__main__":
    main()