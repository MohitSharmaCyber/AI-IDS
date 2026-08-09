"""
Enterprise Anomaly Detection Engine

Combines statistical, TCP, traffic, and ML signals
to detect suspicious network flows.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from detection.anomaly_detector.scorer import AnomalyScorer
from detection.anomaly_detector.severity import SeverityClassifier
from detection.flow_generator.flow import Flow
from detection.flow_generator.feature_extractor import FeatureExtractor


class AnomalyDetector:
    """
    Enterprise anomaly detection engine.

    Converts flow statistics into anomaly scores
    and severity classifications.
    """

    def __init__(self):
        pass

    # ============================================================
    # STATISTICAL ANALYSIS
    # ============================================================

    @staticmethod
    def statistical_score(features: dict) -> float:
        """
        Calculate anomaly score based on packet-size statistics.
        """

        score = 0.0

        # Very small packets can indicate scanning/probing
        if features.get("min_packet_size", 0) < 64:
            score += 0.25

        # Large variation in packet sizes
        if features.get("std_packet_size", 0) > 500:
            score += 0.20

        # High packet size
        if features.get("max_packet_size", 0) > 1400:
            score += 0.15

        return min(score, 1.0)

    # ============================================================
    # TCP ANALYSIS
    # ============================================================

    @staticmethod
    def tcp_score(features: dict) -> float:
        """
        Calculate anomaly score from TCP behavior.
        """

        score = 0.0

        # SYN without proportional ACK response
        syn_ack_ratio = features.get("syn_ack_ratio", 0.0)

        if syn_ack_ratio > 1.0:
            score += 0.40

        # RST activity
        rst_ratio = features.get("rst_ratio", 0.0)

        if rst_ratio > 0.2:
            score += 0.30

        # Excessive SYN packets
        syn_count = features.get("syn_count", 0)

        if syn_count >= 5:
            score += 0.30

        return min(score, 1.0)

    # ============================================================
    # TRAFFIC ANALYSIS
    # ============================================================

    @staticmethod
    def traffic_score(features: dict) -> float:
        """
        Calculate anomaly score from traffic volume.
        """

        score = 0.0

        packets_per_second = features.get(
            "packets_per_second",
            0.0
        )

        bytes_per_second = features.get(
            "bytes_per_second",
            0.0
        )

        # High packet rate
        if packets_per_second > 100:
            score += 0.50
        elif packets_per_second > 50:
            score += 0.30

        # High bandwidth
        if bytes_per_second > 1_000_000:
            score += 0.50
        elif bytes_per_second > 500_000:
            score += 0.30

        return min(score, 1.0)

    # ============================================================
    # ML SCORE
    # ============================================================

    @staticmethod
    def ml_score(flow: Flow) -> float:
        """
        Return ML anomaly score already attached to the flow.
        """

        return max(
            0.0,
            min(
                float(flow.anomaly_score),
                1.0
            )
        )

    # ============================================================
    # ATTACK CLASSIFICATION
    # ============================================================

    @staticmethod
    def classify_attack(
        features: dict,
        final_score: float
    ) -> str:
        """
        Identify a high-level attack category.
        """

        syn_count = features.get("syn_count", 0)
        rst_ratio = features.get("rst_ratio", 0.0)

        packets_per_second = features.get(
            "packets_per_second",
            0.0
        )

        # Possible port/network scanning
        if syn_count >= 5:
            return "TCP SYN Scan"

        # Possible reset-based probing
        if rst_ratio > 0.2:
            return "TCP Reset Activity"

        # Possible high-volume attack
        if packets_per_second > 100:
            return "High Traffic Anomaly"

        if final_score >= 0.9:
            return "Unknown Anomaly"

        if final_score >= 0.7:
            return "Suspicious Activity"

        return "Normal Traffic"

    # ============================================================
    # FLOW ANALYSIS
    # ============================================================

    def analyze(self, flow: Flow) -> Flow:
        """
        Analyze a Flow and update its detection fields.

        Returns:
            Flow: Updated flow object.
        """

        # Extract ML-ready features
        features = FeatureExtractor.extract(flow)

        # Individual detection signals
        statistical = self.statistical_score(features)

        tcp = self.tcp_score(features)

        traffic = self.traffic_score(features)

        ml = self.ml_score(flow)

        # Combined anomaly score
        final_score = AnomalyScorer.calculate(
            statistical_score=statistical,
            tcp_score=tcp,
            traffic_score=traffic,
            ml_score=ml,
        )

        # Severity
        severity = SeverityClassifier.classify(
            final_score
        )

        # Attack classification
        attack_type = self.classify_attack(
            features,
            final_score
        )

        # Update Flow
        flow.anomaly_score = final_score
        flow.severity = severity

        if attack_type != "Normal Traffic":
            flow.attack_type = attack_type
        else:
            flow.attack_type = None

        flow.label = (
            "Attack"
            if final_score >= 0.7
            else "Benign"
        )

        return flow