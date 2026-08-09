"""
Enterprise ML Detection Engine

Uses Isolation Forest to detect anomalous network flows.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from typing import Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from detection.flow_generator.flow import Flow
from detection.flow_generator.feature_extractor import FeatureExtractor


class MLEngine:
    """
    Machine-learning engine for network-flow anomaly detection.

    The engine:
        1. Extracts ML features from a Flow.
        2. Trains an Isolation Forest model.
        3. Calculates an anomaly score.
        4. Classifies the flow as Normal or Anomalous.
    """

    # Feature order must remain consistent between
    # training and prediction.
    FEATURE_NAMES = [
        "duration",
        "packet_count",
        "total_bytes",
        "forward_packets",
        "backward_packets",
        "packets_per_second",
        "bytes_per_second",
        "min_packet_size",
        "max_packet_size",
        "mean_packet_size",
        "median_packet_size",
        "variance_packet_size",
        "std_packet_size",
        "average_packet_size",
        "syn_count",
        "ack_count",
        "fin_count",
        "rst_count",
        "psh_count",
        "urg_count",
        "ece_count",
        "cwr_count",
        "total_flags",
        "syn_ack_ratio",
        "rst_ratio",
    ]

    def __init__(
        self,
        contamination: float = 0.1,
        random_state: int = 42,
    ):
        """
        Initialize the Isolation Forest model.

        Args:
            contamination:
                Expected proportion of anomalous samples.

            random_state:
                Ensures reproducible model behavior.
        """

        if not 0 < contamination < 0.5:
            raise ValueError(
                "contamination must be between 0 and 0.5"
            )

        self.contamination = contamination

        self.random_state = random_state

        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
        )

        self.is_trained = False

    # ============================================================
    # FEATURE VECTOR
    # ============================================================

    @classmethod
    def flow_to_vector(cls, flow: Flow) -> np.ndarray:
        """
        Convert a Flow into a numerical ML feature vector.
        """

        features = FeatureExtractor.extract(flow)

        vector = [
            float(features.get(name, 0.0))
            for name in cls.FEATURE_NAMES
        ]

        return np.asarray(vector, dtype=float)

    # ============================================================
    # TRAINING
    # ============================================================

    def train(self, flows: List[Flow]) -> None:
        """
        Train the Isolation Forest model using network flows.

        Args:
            flows:
                List of Flow objects.
        """

        if not flows:
            raise ValueError(
                "Training requires at least one flow."
            )

        vectors = [
            self.flow_to_vector(flow)
            for flow in flows
        ]

        X = np.asarray(vectors, dtype=float)

        self.model.fit(X)

        self.is_trained = True

    # ============================================================
    # RAW MODEL SCORE
    # ============================================================

    def decision_score(self, flow: Flow) -> float:
        """
        Return the raw Isolation Forest decision score.

        Higher values generally indicate more normal samples.
        """

        if not self.is_trained:
            raise RuntimeError(
                "ML engine must be trained before prediction."
            )

        vector = self.flow_to_vector(flow).reshape(1, -1)

        return float(
            self.model.decision_function(vector)[0]
        )

    # ============================================================
    # ANOMALY SCORE
    # ============================================================

    def anomaly_score(self, flow: Flow) -> float:
        """
        Convert the Isolation Forest decision score
        into a normalized anomaly score between 0 and 1.

        Higher value = more anomalous.
        """

        raw_score = self.decision_score(flow)

        # Isolation Forest normally produces values
        # around the range [-0.5, 0.5].
        #
        # Convert the score so that:
        #
        # normal     -> lower anomaly score
        # anomalous  -> higher anomaly score

        score = 0.5 - raw_score

        # Normalize to [0, 1]
        score = max(0.0, min(1.0, score))

        return float(score)

    # ============================================================
    # PREDICTION
    # ============================================================

    def predict(self, flow: Flow) -> Dict:
        """
        Analyze a flow using the trained ML model.

        Returns:
            Dictionary containing prediction information.
        """

        if not self.is_trained:
            raise RuntimeError(
                "ML engine must be trained before prediction."
            )

        vector = self.flow_to_vector(flow).reshape(1, -1)

        prediction = int(
            self.model.predict(vector)[0]
        )

        raw_score = self.decision_score(flow)

        score = self.anomaly_score(flow)

        label = (
            "Anomalous"
            if prediction == -1
            else "Normal"
        )

        return {
            "prediction": prediction,
            "label": label,
            "anomaly_score": score,
            "decision_score": raw_score,
        }

    # ============================================================
    # APPLY RESULT TO FLOW
    # ============================================================

    def analyze(self, flow: Flow) -> Flow:
        """
        Run ML detection and update the Flow object.
        """

        result = self.predict(flow)

        flow.anomaly_score = result["anomaly_score"]

        flow.label = result["label"]

        return flow

    # ============================================================
    # MODEL STATUS
    # ============================================================

    def status(self) -> Dict:
        """
        Return current ML engine status.
        """

        return {
            "model": "IsolationForest",
            "trained": self.is_trained,
            "contamination": self.contamination,
            "feature_count": len(self.FEATURE_NAMES),
            "features": self.FEATURE_NAMES.copy(),
        }