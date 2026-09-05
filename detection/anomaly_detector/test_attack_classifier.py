"""
Attack Classifier Test Suite

Tests:
    - Normal traffic
    - Suspicious TCP activity
    - Port scan
    - SYN Flood / DoS
    - Brute force
    - Generic anomalous traffic

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from detection.anomaly_detector.attack_classifier import AttackClassifier


classifier = AttackClassifier()


def print_result(
    name: str,
    features: dict,
    anomaly_score: float,
    severity: str,
) -> dict:
    """Run classification and print the result."""

    result = classifier.classify_with_details(
        features=features,
        anomaly_score=anomaly_score,
        severity=severity,
    )

    print("=" * 70)
    print(name)
    print("=" * 70)

    print(f"Attack Type       : {result.get('attack_type')}")
    print(f"MITRE Technique    : {result.get('mitre_technique')}")
    print(f"Label              : {result.get('label')}")
    print(f"Confidence         : {result.get('confidence')}")
    print(f"Evidence           : {result.get('evidence')}")
    print()

    return result


# ============================================================
# TEST 1 - NORMAL TRAFFIC
# ============================================================

result = print_result(
    "NORMAL TRAFFIC",
    {
        "behavior_scan_score": 0.0,
        "behavior_total_flows": 1,
        "behavior_unique_destination_ips": 1,
        "behavior_unique_destination_ports": 1,
        "behavior_syn_flows": 1,
        "behavior_rst_flows": 0,
        "behavior_failed_connection_flows": 0,
        "behavior_connection_failure_ratio": 0.0,
        "packet_count": 3,
        "packets_per_second": 3.0,
        "syn_count": 1,
        "ack_count": 1,
        "rst_count": 0,
        "fin_count": 1,
        "forward_packets": 2,
        "backward_packets": 1,
    },
    anomaly_score=0.0,
    severity="Normal",
)

assert result["attack_type"] is None
assert result["label"] == "Benign"


# ============================================================
# TEST 2 - SUSPICIOUS TCP ACTIVITY
# ============================================================

result = print_result(
    "SUSPICIOUS TCP ACTIVITY",
    {
        "behavior_scan_score": 0.0,
        "behavior_total_flows": 1,
        "behavior_unique_destination_ips": 1,
        "behavior_unique_destination_ports": 1,
        "behavior_syn_flows": 1,
        "behavior_rst_flows": 1,
        "behavior_failed_connection_flows": 1,
        "behavior_connection_failure_ratio": 1.0,
        "packet_count": 4,
        "packets_per_second": 4.0,
        "syn_count": 3,
        "ack_count": 0,
        "rst_count": 1,
        "fin_count": 0,
        "forward_packets": 3,
        "backward_packets": 1,
    },
    anomaly_score=0.30,
    severity="Suspicious",
)

assert result["attack_type"] is None
assert result["label"] == "Suspicious"


# ============================================================
# TEST 3 - PORT SCAN
# ============================================================

result = print_result(
    "PORT SCAN",
    {
        "behavior_scan_score": 0.75,
        "behavior_total_flows": 12,
        "behavior_unique_destination_ips": 1,
        "behavior_unique_destination_ports": 12,
        "behavior_syn_flows": 12,
        "behavior_rst_flows": 12,
        "behavior_failed_connection_flows": 12,
        "behavior_connection_failure_ratio": 1.0,
        "packet_count": 2,
        "packets_per_second": 20.0,
        "syn_count": 1,
        "ack_count": 0,
        "rst_count": 1,
        "fin_count": 0,
        "forward_packets": 1,
        "backward_packets": 1,
    },
    anomaly_score=0.75,
    severity="High",
)

assert result["attack_type"] == "Port Scan"
assert result["mitre_technique"] == "T1046"
assert result["label"] == "Malicious"


# ============================================================
# TEST 4 - SYN FLOOD / DOS
# ============================================================

result = print_result(
    "SYN FLOOD / DOS",
    {
        # Same destination service is important here.
        "behavior_scan_score": 0.0,
        "behavior_total_flows": 100,
        "behavior_unique_destination_ips": 1,
        "behavior_unique_destination_ports": 1,
        "behavior_syn_flows": 100,
        "behavior_rst_flows": 0,
        "behavior_failed_connection_flows": 100,
        "behavior_connection_failure_ratio": 1.0,
        "behavior_flow_rate": 100.0,
        "behavior_syn_flow_ratio": 1.0,

        # High-volume SYN flood indicators.
        "packet_count": 100,
        "packets_per_second": 1000.0,
        "syn_count": 100,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0,
        "forward_packets": 100,
        "backward_packets": 0,
        "syn_ack_ratio": 100.0,
    },
    anomaly_score=0.90,
    severity="Critical",
)

assert result["attack_type"] == "SYN Flood / DoS"
assert result["mitre_technique"] == "T1498"
assert result["label"] == "Malicious"


# ============================================================
# TEST 5 - BRUTE FORCE
# ============================================================

result = print_result(
    "BRUTE FORCE",
    {
        # Repeated attempts against ONE service.
        "behavior_scan_score": 0.0,
        "behavior_total_flows": 20,
        "behavior_unique_destination_ips": 1,
        "behavior_unique_destination_ports": 1,
        "behavior_syn_flows": 20,
        "behavior_rst_flows": 20,
        "behavior_failed_connection_flows": 20,
        "behavior_connection_failure_ratio": 1.0,

        # Moderate repeated connection activity,
        # intentionally below SYN-flood volume.
        "packet_count": 30,
        "packets_per_second": 10.0,
        "syn_count": 8,
        "ack_count": 2,
        "rst_count": 5,
        "fin_count": 0,
        "forward_packets": 20,
        "backward_packets": 10,
        "syn_ack_ratio": 4.0,
    },
    anomaly_score=0.80,
    severity="High",
)

assert result["attack_type"] == "Brute Force"
assert result["mitre_technique"] == "T1110"
assert result["label"] == "Malicious"


# ============================================================
# TEST 6 - GENERIC ANOMALOUS TRAFFIC
# ============================================================

result = print_result(
    "GENERIC ANOMALOUS TRAFFIC",
    {
        "behavior_scan_score": 0.0,
        "behavior_total_flows": 2,
        "behavior_unique_destination_ips": 1,
        "behavior_unique_destination_ports": 1,
        "behavior_syn_flows": 0,
        "behavior_rst_flows": 0,
        "behavior_failed_connection_flows": 0,
        "behavior_connection_failure_ratio": 0.0,
        "packet_count": 8,
        "packets_per_second": 8.0,
        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0,
        "forward_packets": 4,
        "backward_packets": 4,
    },
    anomaly_score=0.75,
    severity="High",
)

assert result["attack_type"] == "Generic Anomalous Traffic"
assert result["label"] == "Malicious"


# ============================================================
# COMPLETION
# ============================================================

print("=" * 70)
print("ALL ATTACK CLASSIFIER TESTS PASSED")
print("=" * 70)