"""
Enterprise Anomaly Detection Engine

Combines:
    - Statistical analysis
    - TCP analysis
    - Traffic analysis
    - Machine-learning anomaly detection
    - Host-level behavioral analysis
    - Attack classification

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from detection.anomaly_detector.scorer import AnomalyScorer
from detection.anomaly_detector.severity import SeverityClassifier
from detection.anomaly_detector.attack_classifier import AttackClassifier

from detection.behavior.behavior_tracker import BehaviorTracker

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
        - Host-level behavioral analysis
        - Attack classification
    """

    def __init__(
        self,
        ml_engine: MLEngine | None = None,
        behavior_tracker: BehaviorTracker | None = None,
    ):
        """
        Initialize the anomaly detection engine.

        Args:
            ml_engine:
                Optional trained machine-learning engine.

            behavior_tracker:
                Optional host-level behavior tracker.
                If not provided, a 60-second tracker is created.
        """

        self.ml_engine = ml_engine

        self.behavior_tracker = (
            behavior_tracker
            if behavior_tracker is not None
            else BehaviorTracker(window_seconds=60)
        )

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

        # SYN-heavy traffic
        if syn_count >= 3:
            score += 0.30

        # Multiple SYNs with no ACK response
        if syn_count >= 3 and ack_count == 0:
            score += 0.30

        # SYN / ACK imbalance
        if syn_ack_ratio > 1.0:
            score += 0.20

        # RST activity
        if rst_ratio >= 0.20:
            score += 0.20

        # One-way TCP probing
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

        # Packet rate
        if packets_per_second > 100:
            score += 0.50

        elif packets_per_second > 50:
            score += 0.30

        # Byte rate
        if bytes_per_second > 1_000_000:
            score += 0.50

        elif bytes_per_second > 500_000:
            score += 0.30

        return min(score, 1.0)

    # ============================================================
    # BEHAVIORAL ANALYSIS
    # ============================================================

    def behavioral_analysis(
        self,
        flow: Flow,
    ) -> dict:
        """
        Analyze host-level behavior across multiple flows.

        Tracks:
            - Unique destination IPs
            - Unique destination ports
            - Destination IP fan-out
            - Destination port fan-out
            - Total flows
            - Observation duration
            - Flow rate
            - Packet rate
            - Byte rate
            - SYN activity
            - RST activity
            - Connection failures
            - SYN ratio
            - RST ratio
            - Behavioral scan score
        """

        behavior = self.behavior_tracker.update(flow)

        return {
            # ----------------------------------------------------
            # Primary behavioral score
            # ----------------------------------------------------

            "behavior_scan_score": (
                behavior.scan_score
            ),

            # ----------------------------------------------------
            # Basic behavior statistics
            # ----------------------------------------------------

            "behavior_total_flows": (
                behavior.total_flows
            ),

            "behavior_total_packets": (
                behavior.total_packets
            ),

            "behavior_total_bytes": (
                behavior.total_bytes
            ),

            "behavior_unique_destination_ips": (
                behavior.unique_destination_ip_count
            ),

            "behavior_unique_destination_ports": (
                behavior.unique_destination_port_count
            ),

            # ----------------------------------------------------
            # Fan-out metrics
            # ----------------------------------------------------

            "behavior_destination_ip_fanout": (
                behavior.destination_ip_fanout
            ),

            "behavior_destination_port_fanout": (
                behavior.destination_port_fanout
            ),

            # ----------------------------------------------------
            # Temporal / rate metrics
            # ----------------------------------------------------

            "behavior_observation_duration": (
                behavior.observation_duration
            ),

            "behavior_flow_rate": (
                behavior.flow_rate
            ),

            "behavior_packet_rate": (
                behavior.packet_rate
            ),

            "behavior_byte_rate": (
                behavior.byte_rate
            ),

            # ----------------------------------------------------
            # TCP behavior
            # ----------------------------------------------------

            "behavior_tcp_flows": (
                behavior.tcp_flows
            ),

            "behavior_syn_flows": (
                behavior.syn_flows
            ),

            "behavior_rst_flows": (
                behavior.rst_flows
            ),

            "behavior_failed_connection_flows": (
                behavior.failed_connection_flows
            ),

            # ----------------------------------------------------
            # TCP ratios
            # ----------------------------------------------------

            "behavior_syn_flow_ratio": (
                behavior.syn_flow_ratio
            ),

            "behavior_rst_flow_ratio": (
                behavior.rst_flow_ratio
            ),

            "behavior_connection_failure_ratio": (
                behavior.connection_failure_ratio
            ),
        }

    # ============================================================
    # MACHINE LEARNING
    # ============================================================

    def ml_score(
        self,
        flow: Flow,
    ) -> float:
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
        """

        classifier = AttackClassifier()

        classification = classifier.classify_with_details(
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
                    if final_score >= 0.70
                    else "Benign"
                ),
                "confidence": 0.0,
                "evidence": [],
            }

        return classification

    # ============================================================
    # FINAL SCORE COMBINATION
    # ============================================================

    @staticmethod
    def combine_behavior_score(
        base_score: float,
        behavior_score: float,
    ) -> float:
        """
        Combine the existing anomaly score with the
        host-level behavioral score.
        """

        return min(
            max(
                base_score,
                behavior_score,
            ),
            1.0,
        )

    # ============================================================
    # FULL FLOW ANALYSIS
    # ============================================================

    def analyze(
        self,
        flow: Flow,
    ) -> Flow:
        """
        Perform complete anomaly analysis.
        """

        # --------------------------------------------------------
        # Feature extraction
        # --------------------------------------------------------

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
        # Host-level behavioral analysis
        # --------------------------------------------------------

        behavioral = self.behavioral_analysis(
            flow
        )

        # Add behavioral intelligence to
        # classification features.
        features.update(
            behavioral
        )

        behavior_score = behavioral.get(
            "behavior_scan_score",
            0.0,
        )

        # --------------------------------------------------------
        # Existing combined anomaly score
        # --------------------------------------------------------

        base_score = AnomalyScorer.calculate(
            statistical_score=statistical,
            tcp_score=tcp,
            traffic_score=traffic,
            ml_score=ml,
        )

        # --------------------------------------------------------
        # Add behavioral intelligence
        # --------------------------------------------------------

        final_score = self.combine_behavior_score(
            base_score=base_score,
            behavior_score=behavior_score,
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
            features=features,
            final_score=final_score,
            severity=severity,
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
                if final_score >= 0.70
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
        """

        # --------------------------------------------------------
        # Feature extraction
        # --------------------------------------------------------

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
        # Host-level behavioral analysis
        # --------------------------------------------------------

        behavioral = self.behavioral_analysis(
            flow
        )

        features.update(
            behavioral
        )

        behavior_score = behavioral.get(
            "behavior_scan_score",
            0.0,
        )

        # --------------------------------------------------------
        # Existing anomaly score
        # --------------------------------------------------------

        base_score = AnomalyScorer.calculate(
            statistical_score=statistical,
            tcp_score=tcp,
            traffic_score=traffic,
            ml_score=ml,
        )

        # --------------------------------------------------------
        # Combined score
        # --------------------------------------------------------

        final_score = self.combine_behavior_score(
            base_score=base_score,
            behavior_score=behavior_score,
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

        classification = self.classify_attack(
            features=features,
            final_score=final_score,
            severity=severity,
        )

        # --------------------------------------------------------
        # Complete breakdown
        # --------------------------------------------------------

        return {
            # ====================================================
            # Detection scores
            # ====================================================

            "statistical_score": statistical,

            "tcp_score": tcp,

            "traffic_score": traffic,

            "ml_score": ml,

            "behavior_scan_score": (
                behavior_score
            ),

            # ====================================================
            # Behavioral statistics
            # ====================================================

            "behavior_total_flows": behavioral.get(
                "behavior_total_flows",
                0,
            ),

            "behavior_total_packets": behavioral.get(
                "behavior_total_packets",
                0,
            ),

            "behavior_total_bytes": behavioral.get(
                "behavior_total_bytes",
                0,
            ),

            "behavior_unique_destination_ips": behavioral.get(
                "behavior_unique_destination_ips",
                0,
            ),

            "behavior_unique_destination_ports": behavioral.get(
                "behavior_unique_destination_ports",
                0,
            ),

            "behavior_destination_ip_fanout": behavioral.get(
                "behavior_destination_ip_fanout",
                0.0,
            ),

            "behavior_destination_port_fanout": behavioral.get(
                "behavior_destination_port_fanout",
                0.0,
            ),

            # ====================================================
            # Behavioral temporal metrics
            # ====================================================

            "behavior_observation_duration": behavioral.get(
                "behavior_observation_duration",
                0.0,
            ),

            "behavior_flow_rate": behavioral.get(
                "behavior_flow_rate",
                0.0,
            ),

            "behavior_packet_rate": behavioral.get(
                "behavior_packet_rate",
                0.0,
            ),

            "behavior_byte_rate": behavioral.get(
                "behavior_byte_rate",
                0.0,
            ),

            # ====================================================
            # TCP behavioral metrics
            # ====================================================

            "behavior_tcp_flows": behavioral.get(
                "behavior_tcp_flows",
                0,
            ),

            "behavior_syn_flows": behavioral.get(
                "behavior_syn_flows",
                0,
            ),

            "behavior_rst_flows": behavioral.get(
                "behavior_rst_flows",
                0,
            ),

            "behavior_failed_connection_flows": behavioral.get(
                "behavior_failed_connection_flows",
                0,
            ),

            "behavior_syn_flow_ratio": behavioral.get(
                "behavior_syn_flow_ratio",
                0.0,
            ),

            "behavior_rst_flow_ratio": behavioral.get(
                "behavior_rst_flow_ratio",
                0.0,
            ),

            "behavior_connection_failure_ratio": behavioral.get(
                "behavior_connection_failure_ratio",
                0.0,
            ),

            # ====================================================
            # Final detection result
            # ====================================================

            "base_score": base_score,

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
                    if final_score >= 0.70
                    else "Benign"
                ),
            ),

            "confidence": classification.get(
                "confidence",
                0.0,
            ),

            "evidence": classification.get(
                "evidence",
                [],
            ),
        }

    # ============================================================
    # BEHAVIOR TRACKER MANAGEMENT
    # ============================================================

    def reset_behavior(self) -> None:
        """
        Clear all tracked host behavior.
        """

        self.behavior_tracker.clear()

    def get_behavior_summary(self) -> list[dict]:
        """
        Return behavioral summaries for all
        currently tracked source IPs.
        """

        return self.behavior_tracker.summary()