"""
Attack Classification Engine Test

Tests:
    - Normal traffic
    - Port scan
    - SYN flood / DoS
    - Brute force
    - Suspicious TCP activity

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from detection.anomaly_detector.attack_classifier import (
    AttackClassifier,
)


def print_result(name, features, anomaly_score, severity):
    result = AttackClassifier.classify_with_details(
        features=features,
        anomaly_score=anomaly_score,
        severity=severity,
    )

    print()
    print("=" * 70)
    print(name)
    print("=" * 70)

    print(f"Anomaly Score : {anomaly_score}")
    print(f"Severity      : {severity}")
    print(f"Attack Type   : {result['attack_type']}")
    print(f"MITRE         : {result['mitre_technique']}")
    print(f"Label         : {result['label']}")


# ============================================================
# NORMAL TRAFFIC
# ============================================================

normal_flow = {
    "packet_count": 5,
    "packets_per_second": 2.5,
    "syn_count": 1,
    "ack_count": 4,
    "rst_count": 0,
    "fin_count": 1,
    "forward_packets": 3,
    "backward_packets": 2,
    "rst_ratio": 0.0,
}

print_result(
    "NORMAL TRAFFIC",
    normal_flow,
    anomaly_score=0.10,
    severity="Normal",
)


# ============================================================
# PORT SCAN
# ============================================================

port_scan = {
    "packet_count": 10,
    "packets_per_second": 8.0,
    "syn_count": 6,
    "ack_count": 1,
    "rst_count": 2,
    "fin_count": 0,
    "forward_packets": 8,
    "backward_packets": 1,
    "rst_ratio": 0.20,
}

print_result(
    "PORT SCAN",
    port_scan,
    anomaly_score=0.75,
    severity="High",
)


# ============================================================
# SYN FLOOD / DOS
# ============================================================

syn_flood = {
    "packet_count": 100,
    "packets_per_second": 50.0,
    "syn_count": 80,
    "ack_count": 10,
    "rst_count": 0,
    "fin_count": 0,
    "forward_packets": 95,
    "backward_packets": 5,
    "rst_ratio": 0.0,
}

print_result(
    "SYN FLOOD / DOS",
    syn_flood,
    anomaly_score=0.95,
    severity="Critical",
)


# ============================================================
# BRUTE FORCE
# ============================================================

brute_force = {
    "packet_count": 30,
    "packets_per_second": 6.0,
    "syn_count": 10,
    "ack_count": 5,
    "rst_count": 6,
    "fin_count": 0,
    "forward_packets": 25,
    "backward_packets": 5,
    "rst_ratio": 0.20,
}

print_result(
    "BRUTE FORCE",
    brute_force,
    anomaly_score=0.65,
    severity="High",
)


# ============================================================
# SUSPICIOUS TCP
# ============================================================

suspicious_tcp = {
    "packet_count": 12,
    "packets_per_second": 5.0,
    "syn_count": 6,
    "ack_count": 2,
    "rst_count": 4,
    "fin_count": 0,
    "forward_packets": 9,
    "backward_packets": 3,
    "rst_ratio": 0.60,
}

print_result(
    "SUSPICIOUS TCP ACTIVITY",
    suspicious_tcp,
    anomaly_score=0.55,
    severity="Medium",
)


print()
print("=" * 70)
print("ATTACK CLASSIFICATION TEST COMPLETED")
print("=" * 70)