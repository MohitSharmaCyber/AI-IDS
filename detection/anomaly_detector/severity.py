"""
Enterprise Severity Classification Engine

Converts anomaly scores into meaningful security severity levels.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""


class SeverityClassifier:
    """
    Classifies anomaly scores into security severity levels.
    """

    # Severity thresholds
    CRITICAL_THRESHOLD = 0.90
    HIGH_THRESHOLD = 0.70
    MEDIUM_THRESHOLD = 0.40

    @classmethod
    def classify(cls, anomaly_score: float) -> str:
        """
        Convert anomaly score into severity.

        Score range:
            0.0 - 0.39  -> Normal
            0.40 - 0.69 -> Medium
            0.70 - 0.89 -> High
            0.90 - 1.00 -> Critical
        """

        # Keep score within valid range
        score = max(0.0, min(1.0, float(anomaly_score)))

        if score >= cls.CRITICAL_THRESHOLD:
            return "Critical"

        if score >= cls.HIGH_THRESHOLD:
            return "High"

        if score >= cls.MEDIUM_THRESHOLD:
            return "Medium"

        return "Normal"

    @classmethod
    def is_threat(cls, anomaly_score: float) -> bool:
        """
        Return True when the anomaly score
        reaches the Medium severity threshold.
        """

        return float(anomaly_score) >= cls.MEDIUM_THRESHOLD

    @classmethod
    def get_thresholds(cls) -> dict:
        """
        Return configured severity thresholds.
        """

        return {
            "critical": cls.CRITICAL_THRESHOLD,
            "high": cls.HIGH_THRESHOLD,
            "medium": cls.MEDIUM_THRESHOLD,
        }