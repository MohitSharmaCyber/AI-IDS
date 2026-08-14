"""
Enterprise Anomaly Detection Engine

Combines statistical, TCP, traffic, and ML signals
to detect suspicious network flows.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from detection.anomaly_detector.scorer import AnomalyScorer
from detection.anomaly_detector.severity import SeverityClassifier
from detection.anomaly_detector.attack_classifier import AttackClassifier

from detection.flow_generator.flow import Flow
from detection.flow_generator.feature_extractor import FeatureExtractor
from detection.ml_detector.ml_engine import MLEngine


class AnomalyDetector:
    """
    Enterprise anomaly detection engine.

    Combines:
        - Statistical analysis
        - TCP behavior analysis
        - Traffic analysis
        - Machine-learning anomaly detection
        - Attack classification
    """

    def __init__(
        self,
        ml_engine: MLEngine | None = None,
    ):
        self.ml_engine = ml_engine

    # ============================================================
    # STATISTICAL ANALYSIS
    # ============================================================

    @staticmethod
    def statistical_score(features: dict) -> float:
        """
        Calculate anomaly score based on packet statistics.
        """

        score = 0.0

        if features.get("min_packet_size", 0) < 64:
            score += 0.25

        if features.get("std_packet_size", 0) > 500:
            score += 0.20

        if features.get("max_packet_size", 0) > 1400:
            score += 0.15

        return min(score, 1.0)

    # ============================================================
    # TCP ANALYSIS
    # ============================================================

    @staticmethod
    def tcp_score(features: dict) -> float:
        """
        Detect suspicious TCP flag behavior.

        Signals:
            - SYN-heavy traffic
            - SYN packets without ACK responses
            - Elevated RST ratio
            - Repeated SYN attempts
            - One-way TCP probing
        """

        score = 0.0

        syn_ack_ratio = features.get(
            "syn_ack_ratio",
            0.0,
        )

        rst_ratio = features.get(
            "rst_ratio",
            0.0,
        )

        syn_count = features.get(
            "syn_count",
            0,
        )

        ack_count = features.get(
            "ack_count",
            0,
        )

        backward_packets = features.get(
            "backward_packets",
            0,
        )

        # --------------------------------------------------------
        # SYN-heavy traffic
        # --------------------------------------------------------

        if syn_count >= 3:
            score += 0.30

        # --------------------------------------------------------
        # Multiple SYNs with no ACK response
        # --------------------------------------------------------

        if syn_count >= 3 and ack_count == 0:
            score += 0.30

        # --------------------------------------------------------
        # SYN / ACK imbalance
        # --------------------------------------------------------

        if syn_ack_ratio > 1.0:
            score += 0.20

        # --------------------------------------------------------
        # RST activity
        # --------------------------------------------------------

        if rst_ratio >= 0.20:
            score += 0.20

        # --------------------------------------------------------
        # One-way TCP probing
        # --------------------------------------------------------

        if syn_count >= 3 and backward_packets == 0:
            score += 0.20

        return min(score, 1.0)

    # ============================================================
    # TRAFFIC ANALYSIS
    # ============================================================

    @staticmethod
    def traffic_score(features: dict) -> float:
        """
        Calculate anomaly score based on traffic volume.
        """

        score = 0.0

        packets_per_second = features.get(
            "packets_per_second",
            0.0,
        )

        bytes_per_second = features.get(
            "bytes_per_second",
            0.0,
        )

        # --------------------------------------------------------
        # Packet rate
        # --------------------------------------------------------

        if packets_per_second > 100:
            score += 0.50

        elif packets_per_second > 50:
            score += 0.30

        # --------------------------------------------------------
        # Byte rate
        # --------------------------------------------------------

        if bytes_per_second > 1_000_000:
            score += 0.50

        elif bytes_per_second > 500_000:
            score += 0.30

        return min(score, 1.0)

    # ============================================================
    # MACHINE LEARNING
    # ============================================================

    def ml_score(self, flow: Flow) -> float:
        """
        Get anomaly score from the trained ML engine.
        """

        if self.ml_engine is None:
            return 0.0

        if not self.ml_engine.is_trained:
            return 0.0

        return self.ml_engine.anomaly_score(flow)

    # ============================================================
    # ATTACK CLASSIFICATION
    # ============================================================

    @staticmethod
    def classify_attack(
        features: dict,
        final_score: float,
        severity: str = "Normal",
    ) -> dict:
        """
        Classify the network flow.

        Returns:
            attack_type
            mitre_technique
            label
        """

        classification = AttackClassifier.classify_with_details(
            features=features,
            anomaly_score=final_score,
            severity=severity,
        )

        # Safety fallback
        if classification is None:
            return {
                "attack_type": None,
                "mitre_technique": None,
                "label": (
                    "Malicious"
                    if final_score >= 0.7
                    else "Benign"
                ),
            }

        return classification

    # ============================================================
    # FULL FLOW ANALYSIS
    # ============================================================

    def analyze(self, flow: Flow) -> Flow:
        """
        Perform complete anomaly analysis.
        """

        features = FeatureExtractor.extract(flow)

        # --------------------------------------------------------
        # Individual detection signals
        # --------------------------------------------------------

        statistical = self.statistical_score(
            features
        )

        tcp = self.tcp_score(
            features
        )

        traffic = self.traffic_score(
            features
        )

        ml = self.ml_score(
            flow
        )

        # --------------------------------------------------------
        # Combined anomaly score
        # --------------------------------------------------------

        final_score = AnomalyScorer.calculate(
            statistical_score=statistical,
            tcp_score=tcp,
            traffic_score=traffic,
            ml_score=ml,
        )

        # --------------------------------------------------------
        # Severity classification
        # --------------------------------------------------------

        severity = SeverityClassifier.classify(
            final_score
        )

        # --------------------------------------------------------
        # Attack classification
        # --------------------------------------------------------

        classification = self.classify_attack(
            features,
            final_score,
            severity,
        )

        # --------------------------------------------------------
        # Update Flow object
        # --------------------------------------------------------

        flow.anomaly_score = final_score

        flow.severity = severity

        flow.attack_type = classification.get(
            "attack_type"
        )

        flow.mitre_technique = classification.get(
            "mitre_technique"
        )

        flow.label = classification.get(
            "label",
            (
                "Malicious"
                if final_score >= 0.7
                else "Benign"
            ),
        )

        return flow

    # ============================================================
    # ANALYSIS BREAKDOWN
    # ============================================================

    def analyze_with_breakdown(
        self,
        flow: Flow,
    ) -> dict:
        """
        Return complete detection information.

        Includes:
            - Statistical score
            - TCP score
            - Traffic score
            - ML score
            - Final anomaly score
            - Severity
            - Attack type
            - MITRE technique
            - Label
        """

        features = FeatureExtractor.extract(
            flow
        )

        # --------------------------------------------------------
        # Individual detection signals
        # --------------------------------------------------------

        statistical = self.statistical_score(
            features
        )

        tcp = self.tcp_score(
            features
        )

        traffic = self.traffic_score(
            features
        )

        ml = self.ml_score(
            flow
        )

        # --------------------------------------------------------
        # Combined anomaly score
        # --------------------------------------------------------

        final_score = AnomalyScorer.calculate(
            statistical_score=statistical,
            tcp_score=tcp,
            traffic_score=traffic,
            ml_score=ml,
        )

        # --------------------------------------------------------
        # Severity classification
        # --------------------------------------------------------

        severity = SeverityClassifier.classify(
            final_score
        )

        # --------------------------------------------------------
        # Attack classification
        # --------------------------------------------------------

        classification = self.classify_attack(
            features,
            final_score,
            severity,
        )

        # --------------------------------------------------------
        # Return complete breakdown
        # --------------------------------------------------------

        return {
            "statistical_score": statistical,

            "tcp_score": tcp,

            "traffic_score": traffic,

            "ml_score": ml,

            "final_score": final_score,

            "severity": severity,

            "attack_type": classification.get(
                "attack_type"
            ),

            "mitre_technique": classification.get(
                "mitre_technique"
            ),

            "label": classification.get(
                "label",
                (
                    "Malicious"
                    if final_score >= 0.7
                    else "Benign"
                ),
            ),
        }