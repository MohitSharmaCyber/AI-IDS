from datetime import datetime
import time

from detection.anomaly_detector.detector import AnomalyDetector
from detection.flow_generator.flow_manager import FlowManager
from detection.packet_capture.packet import Packet


def main():

    manager = FlowManager()

    detector = AnomalyDetector()

    traffic = [
        ("192.168.1.100", 50000, "8.8.8.8", 443, 60, "S"),
        ("192.168.1.100", 50000, "8.8.8.8", 443, 1500, "SA"),
        ("8.8.8.8", 443, "192.168.1.100", 50000, 350, "A"),
        ("192.168.1.100", 50000, "8.8.8.8", 443, 1200, "PA"),
        ("8.8.8.8", 443, "192.168.1.100", 50000, 800, "FA"),
    ]

    for src, sport, dst, dport, size, flags in traffic:

        packet = Packet(
            timestamp=datetime.now(),
            interface="Wi-Fi",
            src_ip=src,
            dst_ip=dst,
            src_port=sport,
            dst_port=dport,
            protocol="TCP",
            packet_size=size,
            payload_size=max(size - 20, 0),
            ttl=64,
            tcp_flags=flags,
        )

        manager.process_packet(packet)

        time.sleep(0.5)

    print()
    print("=" * 70)
    print("ANOMALY DETECTION TEST")
    print("=" * 70)

    for flow in manager.get_active_flows().values():

        detector.analyze(flow)

        print()
        print("Flow")
        print("-" * 70)

        print(flow.summary())

        print()
        print("Detection Results")
        print("-" * 70)

        print(f"Anomaly Score : {flow.anomaly_score:.4f}")
        print(f"Severity      : {flow.severity}")
        print(f"Attack Type   : {flow.attack_type}")
        print(f"Label         : {flow.label}")


if __name__ == "__main__":
    main()