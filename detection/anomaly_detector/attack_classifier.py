"""
Attack Classification Engine

Classifies anomalous network flows into attack categories
using flow-level TCP/traffic indicators and host-level behavioral evidence.

Supported attack categories:
    - Port Scan
    - SYN Flood / DoS
    - Brute Force
    - Suspicious TCP Activity
    - Generic Anomalous Traffic

MITRE ATT&CK mappings:
    - Port Scan        -> T1046
    - SYN Flood / DoS  -> T1498
    - Brute Force      -> T1110

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from typing import Any, Optional


class AttackClassifier:
    """
    Rule-based attack classification engine.

    Classification priority:
        1. SYN Flood / DoS
        2. Brute Force
        3. Behavioral Port Scan
        4. Single-flow Port Scan
        5. Suspicious TCP Activity
        6. Generic Anomalous Traffic
    """

    MITRE_MAPPING = {
        "Port Scan": "T1046",
        "SYN Flood / DoS": "T1498",
        "Brute Force": "T1110",
        "Suspicious TCP Activity": None,
        "Generic Anomalous Traffic": None,
    }

    def __init__(self) -> None:
        """Initialize the attack classifier."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(
        self,
        features: dict[str, Any],
        anomaly_score: float,
        severity: str,
    ) -> Optional[str]:
        """Return the detected attack type or None."""

        result = self.classify_with_details(
            features=features,
            anomaly_score=anomaly_score,
            severity=severity,
        )

        return result["attack_type"]

    def classify_with_details(
        self,
        features: dict[str, Any],
        anomaly_score: float,
        severity: str,
    ) -> dict[str, Any]:
        """
        Classify traffic and return complete classification details.
        """

        anomaly_score = self._clamp_score(anomaly_score)

        # --------------------------------------------------------------
        # Flow-level features
        # --------------------------------------------------------------

        packet_count = self._get_float(features, "packet_count")
        packets_per_second = self._get_float(
            features,
            "packets_per_second",
        )

        syn_count = self._get_float(features, "syn_count")
        ack_count = self._get_float(features, "ack_count")
        rst_count = self._get_float(features, "rst_count")
        fin_count = self._get_float(features, "fin_count")

        forward_packets = self._get_float(
            features,
            "forward_packets",
        )

        backward_packets = self._get_float(
            features,
            "backward_packets",
        )

        syn_ack_ratio = self._get_float(
            features,
            "syn_ack_ratio",
        )

        rst_ratio = self._get_float(
            features,
            "rst_ratio",
        )

        # --------------------------------------------------------------
        # Behavioral features
        # --------------------------------------------------------------

        behavior_scan_score = self._get_float(
            features,
            "behavior_scan_score",
        )

        behavior_total_flows = self._get_float(
            features,
            "behavior_total_flows",
        )

        behavior_unique_destination_ips = self._get_float(
            features,
            "behavior_unique_destination_ips",
        )

        behavior_unique_destination_ports = self._get_float(
            features,
            "behavior_unique_destination_ports",
        )

        behavior_syn_flows = self._get_float(
            features,
            "behavior_syn_flows",
        )

        behavior_rst_flows = self._get_float(
            features,
            "behavior_rst_flows",
        )

        behavior_failed_connection_flows = self._get_float(
            features,
            "behavior_failed_connection_flows",
        )

        behavior_connection_failure_ratio = self._get_float(
            features,
            "behavior_connection_failure_ratio",
        )

        # --------------------------------------------------------------
        # Evidence
        # --------------------------------------------------------------

        evidence: list[str] = []

        # --------------------------------------------------------------
        # 1. BENIGN
        # --------------------------------------------------------------

        if (
            anomaly_score < 0.40
            and severity == "Normal"
            and behavior_scan_score < 0.40
        ):
            return self._result(
                attack_type=None,
                label="Benign",
                confidence=0.0,
                evidence=[],
            )

        # --------------------------------------------------------------
        # 2. SYN FLOOD / DOS
        # --------------------------------------------------------------
        #
        # IMPORTANT:
        # This is evaluated BEFORE port scanning.
        #
        # SYN flood is characterized by:
        # - High packet volume
        # - High packet rate
        # - Many SYN packets
        # - Few ACK responses
        #
        # A SYN-heavy flow must not automatically become a port scan.
        # --------------------------------------------------------------

        if self._is_syn_flood(
            packet_count=packet_count,
            packets_per_second=packets_per_second,
            syn_count=syn_count,
            ack_count=ack_count,
            syn_ack_ratio=syn_ack_ratio,
            anomaly_score=anomaly_score,
        ):
            evidence.extend(
                [
                    "High packet rate",
                    "Large number of SYN packets",
                ]
            )

            if syn_ack_ratio > 3:
                evidence.append(
                    "High SYN-to-ACK ratio"
                )

            if ack_count < syn_count:
                evidence.append(
                    "SYN packets significantly exceed ACK packets"
                )

            confidence = self._calculate_confidence(
                anomaly_score,
                base=0.70,
            )

            return self._result(
                attack_type="SYN Flood / DoS",
                label="Malicious",
                confidence=confidence,
                evidence=evidence,
            )

        # --------------------------------------------------------------
        # 3. BRUTE FORCE
        # --------------------------------------------------------------
        #
        # Brute force is evaluated before port scan because repeated
        # connection attempts against the same service can look like
        # SYN-heavy reconnaissance.
        # --------------------------------------------------------------

        if self._is_brute_force(
            anomaly_score=anomaly_score,
            packet_count=packet_count,
            packets_per_second=packets_per_second,
            syn_count=syn_count,
            rst_count=rst_count,
            behavior_total_flows=behavior_total_flows,
            behavior_unique_destination_ports=(
                behavior_unique_destination_ports
            ),
            behavior_failed_connection_flows=(
                behavior_failed_connection_flows
            ),
            behavior_connection_failure_ratio=(
                behavior_connection_failure_ratio
            ),
        ):
            evidence.extend(
                [
                    "Repeated connection attempts",
                    "Abnormally high failed connection activity",
                ]
            )

            if syn_count >= 5:
                evidence.append(
                    "Repeated SYN connection attempts"
                )

            if rst_count >= 3:
                evidence.append(
                    "Multiple failed TCP connection responses"
                )

            confidence = self._calculate_confidence(
                anomaly_score,
                base=0.60,
            )

            return self._result(
                attack_type="Brute Force",
                label="Malicious",
                confidence=confidence,
                evidence=evidence,
            )

        # --------------------------------------------------------------
        # 4. BEHAVIORAL PORT SCAN
        # --------------------------------------------------------------

        behavioral_port_scan = self._is_behavioral_port_scan(
            behavior_scan_score=behavior_scan_score,
            behavior_total_flows=behavior_total_flows,
            behavior_unique_destination_ips=(
                behavior_unique_destination_ips
            ),
            behavior_unique_destination_ports=(
                behavior_unique_destination_ports
            ),
            behavior_syn_flows=behavior_syn_flows,
            behavior_rst_flows=behavior_rst_flows,
            behavior_failed_connection_flows=(
                behavior_failed_connection_flows
            ),
            behavior_connection_failure_ratio=(
                behavior_connection_failure_ratio
            ),
        )

        if behavioral_port_scan:
            evidence.extend(
                self._get_port_scan_behavior_evidence(
                    behavior_scan_score=behavior_scan_score,
                    behavior_total_flows=behavior_total_flows,
                    behavior_unique_destination_ips=(
                        behavior_unique_destination_ips
                    ),
                    behavior_unique_destination_ports=(
                        behavior_unique_destination_ports
                    ),
                    behavior_syn_flows=behavior_syn_flows,
                    behavior_rst_flows=behavior_rst_flows,
                    behavior_connection_failure_ratio=(
                        behavior_connection_failure_ratio
                    ),
                )
            )

            confidence = self._calculate_port_scan_confidence(
                anomaly_score=anomaly_score,
                behavior_scan_score=behavior_scan_score,
                unique_ports=behavior_unique_destination_ports,
                unique_ips=behavior_unique_destination_ips,
                failure_ratio=behavior_connection_failure_ratio,
            )

            return self._result(
                attack_type="Port Scan",
                label="Malicious",
                confidence=confidence,
                evidence=evidence,
            )

        # --------------------------------------------------------------
        # 5. SINGLE-FLOW PORT SCAN
        # --------------------------------------------------------------

        if self._is_port_scan(
            syn_count=syn_count,
            ack_count=ack_count,
            forward_packets=forward_packets,
            backward_packets=backward_packets,
            rst_count=rst_count,
            anomaly_score=anomaly_score,
        ):
            evidence.extend(
                [
                    "Abnormal SYN activity",
                    "Limited response traffic",
                ]
            )

            if rst_count >= 2:
                evidence.append(
                    "Multiple TCP reset responses"
                )

            confidence = self._calculate_confidence(
                anomaly_score,
                base=0.65,
            )

            return self._result(
                attack_type="Port Scan",
                label="Malicious",
                confidence=confidence,
                evidence=evidence,
            )

        # --------------------------------------------------------------
        # 6. SUSPICIOUS TCP ACTIVITY
        # --------------------------------------------------------------

        if self._is_suspicious_tcp(
            anomaly_score=anomaly_score,
            rst_ratio=rst_ratio,
            syn_count=syn_count,
            fin_count=fin_count,
            rst_count=rst_count,
        ):
            evidence.append(
                "Abnormal TCP flag behavior"
            )

            if rst_ratio >= 0.50:
                evidence.append(
                    "High TCP reset ratio"
                )

            if syn_count >= 5 and fin_count == 0:
                evidence.append(
                    "Repeated SYN activity without FIN termination"
                )

            if rst_count >= 3:
                evidence.append(
                    "Multiple TCP reset packets"
                )

            confidence = self._calculate_confidence(
                anomaly_score,
                base=0.45,
            )

            return self._result(
                attack_type="Suspicious TCP Activity",
                label="Malicious",
                confidence=confidence,
                evidence=evidence,
            )

        # --------------------------------------------------------------
        # 7. GENERIC ANOMALOUS TRAFFIC
        # --------------------------------------------------------------

        if anomaly_score >= 0.40:
            evidence.append(
                "Traffic behavior is anomalous"
            )

            confidence = self._calculate_confidence(
                anomaly_score,
                base=0.40,
            )

            return self._result(
                attack_type="Generic Anomalous Traffic",
                label="Malicious",
                confidence=confidence,
                evidence=evidence,
            )

        # --------------------------------------------------------------
        # 8. SUSPICIOUS / LOW-CONFIDENCE
        # --------------------------------------------------------------

        if severity == "Suspicious":
            evidence.append(
                "Traffic exceeded the anomaly suspicion threshold"
            )

            confidence = self._calculate_confidence(
                anomaly_score,
                base=0.20,
            )

            return self._result(
                attack_type=None,
                label="Suspicious",
                confidence=confidence,
                evidence=evidence,
            )

        # --------------------------------------------------------------
        # 9. DEFAULT
        # --------------------------------------------------------------

        return self._result(
            attack_type=None,
            label="Benign",
            confidence=0.0,
            evidence=[],
        )

    # ------------------------------------------------------------------
    # Behavioral Port Scan Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_behavioral_port_scan(
        behavior_scan_score: float,
        behavior_total_flows: float,
        behavior_unique_destination_ips: float,
        behavior_unique_destination_ports: float,
        behavior_syn_flows: float,
        behavior_rst_flows: float,
        behavior_failed_connection_flows: float,
        behavior_connection_failure_ratio: float,
    ) -> bool:

        if (
            behavior_scan_score >= 0.40
            and behavior_unique_destination_ports >= 8
        ):
            return True

        if (
            behavior_unique_destination_ports >= 10
            and behavior_syn_flows >= 5
            and behavior_connection_failure_ratio >= 0.50
        ):
            return True

        if (
            behavior_unique_destination_ports >= 6
            and behavior_total_flows >= 6
            and behavior_syn_flows >= 4
            and behavior_failed_connection_flows >= 4
            and behavior_connection_failure_ratio >= 0.60
        ):
            return True

        if (
            behavior_unique_destination_ips >= 5
            and behavior_total_flows >= 10
            and behavior_syn_flows >= 5
            and behavior_scan_score >= 0.35
        ):
            return True

        if (
            behavior_unique_destination_ports >= 5
            and behavior_syn_flows >= 5
            and behavior_rst_flows >= 3
            and behavior_connection_failure_ratio >= 0.60
            and behavior_scan_score >= 0.25
        ):
            return True

        return False

    @staticmethod
    def _get_port_scan_behavior_evidence(
        behavior_scan_score: float,
        behavior_total_flows: float,
        behavior_unique_destination_ips: float,
        behavior_unique_destination_ports: float,
        behavior_syn_flows: float,
        behavior_rst_flows: float,
        behavior_connection_failure_ratio: float,
    ) -> list[str]:

        evidence: list[str] = []

        if behavior_unique_destination_ports >= 5:
            evidence.append(
                f"Contacted {int(behavior_unique_destination_ports)} "
                "unique destination ports"
            )

        if behavior_unique_destination_ips >= 3:
            evidence.append(
                f"Contacted {int(behavior_unique_destination_ips)} "
                "unique destination IPs"
            )

        if behavior_total_flows >= 5:
            evidence.append(
                f"Generated {int(behavior_total_flows)} "
                "flows within the behavior window"
            )

        if behavior_syn_flows >= 3:
            evidence.append(
                f"Observed {int(behavior_syn_flows)} "
                "SYN-based flows"
            )

        if behavior_rst_flows >= 2:
            evidence.append(
                f"Observed {int(behavior_rst_flows)} "
                "RST responses"
            )

        if behavior_connection_failure_ratio >= 0.50:
            evidence.append(
                "High connection failure ratio"
            )

        if behavior_scan_score >= 0.40:
            evidence.append(
                f"Elevated behavioral scan score "
                f"({behavior_scan_score:.2f})"
            )

        return evidence

    @staticmethod
    def _calculate_port_scan_confidence(
        anomaly_score: float,
        behavior_scan_score: float,
        unique_ports: float,
        unique_ips: float,
        failure_ratio: float,
    ) -> float:

        confidence = (
            0.30 * anomaly_score
            + 0.35 * behavior_scan_score
            + 0.20 * min(unique_ports / 10.0, 1.0)
            + 0.10 * min(unique_ips / 5.0, 1.0)
            + 0.05 * failure_ratio
        )

        confidence = max(confidence, 0.50)

        return min(round(confidence, 4), 1.0)

    # ------------------------------------------------------------------
    # SYN Flood / DoS
    # ------------------------------------------------------------------

    @staticmethod
    def _is_syn_flood(
        packet_count: float,
        packets_per_second: float,
        syn_count: float,
        ack_count: float,
        syn_ack_ratio: float,
        anomaly_score: float,
    ) -> bool:

        if packet_count < 20:
            return False

        if packets_per_second < 10:
            return False

        if syn_count < 10:
            return False

        if anomaly_score < 0.40:
            return False

        if syn_ack_ratio > 3:
            return True

        if syn_count >= 20 and ack_count < syn_count:
            return True

        return False

    # ------------------------------------------------------------------
    # Brute Force
    # ------------------------------------------------------------------

    @staticmethod
    def _is_brute_force(
        anomaly_score: float,
        packet_count: float,
        packets_per_second: float,
        syn_count: float,
        rst_count: float,
        behavior_total_flows: float,
        behavior_unique_destination_ports: float,
        behavior_failed_connection_flows: float,
        behavior_connection_failure_ratio: float,
    ) -> bool:

        if anomaly_score < 0.50:
            return False

        if packet_count < 15:
            return False

        if packets_per_second < 3:
            return False

        # Strong behavioral evidence of repeated attempts.
        if (
            behavior_total_flows >= 5
            and behavior_unique_destination_ports <= 2
            and behavior_failed_connection_flows >= 3
            and behavior_connection_failure_ratio >= 0.50
        ):
            return True

        # Strong repeated SYN attempts.
        if syn_count >= 8 and rst_count >= 3:
            return True

        # Repeated connection attempts.
        if syn_count >= 5 and rst_count >= 5:
            return True

        return False

    # ------------------------------------------------------------------
    # Single Flow Port Scan
    # ------------------------------------------------------------------

    @staticmethod
    def _is_port_scan(
        syn_count: float,
        ack_count: float,
        forward_packets: float,
        backward_packets: float,
        rst_count: float,
        anomaly_score: float,
    ) -> bool:

        if anomaly_score < 0.40:
            return False

        if syn_count < 3:
            return False

        if syn_count > ack_count * 2:
            return True

        if (
            forward_packets >= 5
            and backward_packets <= 2
        ):
            return True

        if (
            rst_count >= 2
            and syn_count >= 3
        ):
            return True

        return False

    # ------------------------------------------------------------------
    # Suspicious TCP
    # ------------------------------------------------------------------

    @staticmethod
    def _is_suspicious_tcp(
        anomaly_score: float,
        rst_ratio: float,
        syn_count: float,
        fin_count: float,
        rst_count: float,
    ) -> bool:

        if anomaly_score < 0.40:
            return False

        if rst_ratio >= 0.50:
            return True

        if syn_count >= 5 and fin_count == 0:
            return True

        if rst_count >= 3:
            return True

        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_float(
        features: dict[str, Any],
        key: str,
    ) -> float:

        value = features.get(key, 0.0)

        if value is None:
            return 0.0

        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _clamp_score(score: float) -> float:
        """Clamp anomaly score between 0 and 1."""

        return max(0.0, min(float(score), 1.0))

    @staticmethod
    def _calculate_confidence(
        anomaly_score: float,
        base: float,
    ) -> float:

        confidence = max(
            base,
            anomaly_score,
        )

        return round(
            min(confidence, 1.0),
            4,
        )

    @staticmethod
    def _result(
        attack_type: Optional[str],
        label: str,
        confidence: float,
        evidence: list[str],
    ) -> dict[str, Any]:
        """Build a standardized classification result."""

        return {
            "attack_type": attack_type,
            "mitre_technique": (
                AttackClassifier.MITRE_MAPPING.get(attack_type)
                if attack_type
                else None
            ),
            "label": label,
            "confidence": confidence,
            "evidence": evidence,
        }

    # ------------------------------------------------------------------
    # Compatibility / Metadata
    # ------------------------------------------------------------------

    @classmethod
    def get_mitre_technique(
        cls,
        attack_type: Optional[str],
    ) -> Optional[str]:

        if attack_type is None:
            return None

        return cls.MITRE_MAPPING.get(attack_type)

    @classmethod
    def get_supported_attacks(cls) -> list[str]:

        return list(cls.MITRE_MAPPING.keys())

    @classmethod
    def get_mitre_mapping(cls) -> dict[str, Optional[str]]:

        return cls.MITRE_MAPPING.copy()