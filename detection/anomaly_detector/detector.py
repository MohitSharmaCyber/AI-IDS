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
from detection.ml_detector.ml_engine import MLEngine


class AnomalyDetector:
    """
    Enterprise anomaly detection engine.

    Combines:
        - Statistical analysis
        - TCP behavior analysis
        - Traffic analysis
        - Machine-learning anomaly detection

    The final score is converted into a severity level
    and attack classification.
    """

    def __init__(
        self,
        ml_engine: MLEngine | None = None,
    ):
        """
        Args:
            ml_engine:
                Optional trained MLEngine instance.
        """

        self.ml_engine = ml_engine

    # ============================================================
    # STATISTICAL ANALYSIS
    # ============================================================

    @staticmethod
    def statistical_score(features: dict) -> float:

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

        if syn_ack_ratio > 1.0:
            score += 0.40

        if rst_ratio > 0.2:
            score += 0.30

        if syn_count >= 5:
            score += 0.30

        return min(score, 1.0)

    # ============================================================
    # TRAFFIC ANALYSIS
    # ============================================================

    @staticmethod
    def traffic_score(features: dict) -> float:

        score = 0.0

        packets_per_second = features.get(
            "packets_per_second",
            0.0,
        )

        bytes_per_second = features.get(
            "bytes_per_second",
            0.0,
        )

        if packets_per_second > 100:
            score += 0.50

        elif packets_per_second > 50:
            score += 0.30

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

        If no ML engine is configured, returns 0.0.
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
    ) -> str:

        syn_count = features.get(
            "syn_count",
            0,
        )

        rst_ratio = features.get(
            "rst_ratio",
            0.0,
        )

        packets_per_second = features.get(
            "packets_per_second",
            0.0,
        )

        if syn_count >= 5:
            return "TCP SYN Scan"

        if rst_ratio > 0.2:
            return "TCP Reset Activity"

        if packets_per_second > 100:
            return "High Traffic Anomaly"

        if final_score >= 0.9:
            return "Unknown Anomaly"

        if final_score >= 0.7:
            return "Suspicious Activity"

        return "Normal Traffic"

    # ============================================================
    # FULL FLOW ANALYSIS
    # ============================================================

    def analyze(self, flow: Flow) -> Flow:
        """
        Perform complete anomaly analysis.

        Pipeline:

            Flow
              ↓
            Features
              ↓
            Statistical
            TCP
            Traffic
            ML
              ↓
            Final Score
              ↓
            Severity
              ↓
            Attack Classification
        """

        # --------------------------------------------------------
        # Feature extraction
        # --------------------------------------------------------

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
        # Severity
        # --------------------------------------------------------

        severity = SeverityClassifier.classify(
            final_score
        )

        # --------------------------------------------------------
        # Attack classification
        # --------------------------------------------------------

        attack_type = self.classify_attack(
            features,
            final_score,
        )

        # --------------------------------------------------------
        # Update Flow
        # --------------------------------------------------------

        flow.anomaly_score = final_score

        flow.severity = severity

        if attack_type == "Normal Traffic":
            flow.attack_type = None
        else:
            flow.attack_type = attack_type

        flow.label = (
            "Attack"
            if final_score >= 0.7
            else "Benign"
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
        Return complete detection information,
        including individual scoring components.
        """

        features = FeatureExtractor.extract(flow)

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

        final_score = AnomalyScorer.calculate(
            statistical_score=statistical,
            tcp_score=tcp,
            traffic_score=traffic,
            ml_score=ml,
        )

        severity = SeverityClassifier.classify(
            final_score
        )

        attack_type = self.classify_attack(
            features,
            final_score,
        )

        return {
            "statistical_score": statistical,
            "tcp_score": tcp,
            "traffic_score": traffic,
            "ml_score": ml,
            "final_score": final_score,
            "severity": severity,
            "attack_type": (
                None
                if attack_type == "Normal Traffic"
                else attack_type
            ),
            "label": (
                "Attack"
                if final_score >= 0.7
                else "Benign"
            ),
        }