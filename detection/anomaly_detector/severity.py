"""
Enterprise Severity Classification Engine

Converts anomaly scores into meaningful security severity levels.

Severity levels:

    Normal
    Suspicious
    Medium
    High
    Critical

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""


class SeverityClassifier:
    """
    Classifies anomaly scores into security severity levels.
    """

    # ============================================================
    # SEVERITY THRESHOLDS
    # ============================================================

    CRITICAL_THRESHOLD = 0.90
    HIGH_THRESHOLD = 0.70
    MEDIUM_THRESHOLD = 0.40
    SUSPICIOUS_THRESHOLD = 0.20

    # ============================================================
    # SEVERITY CLASSIFICATION
    # ============================================================

    @classmethod
    def classify(cls, anomaly_score: float) -> str:
        """
        Convert anomaly score into a security severity level.

        Score ranges:

            0.00 - 0.19 -> Normal
            0.20 - 0.39 -> Suspicious
            0.40 - 0.69 -> Medium
            0.70 - 0.89 -> High
            0.90 - 1.00 -> Critical
        """

        score = max(
            0.0,
            min(1.0, float(anomaly_score))
        )

        if score >= cls.CRITICAL_THRESHOLD:
            return "Critical"

        if score >= cls.HIGH_THRESHOLD:
            return "High"

        if score >= cls.MEDIUM_THRESHOLD:
            return "Medium"

        if score >= cls.SUSPICIOUS_THRESHOLD:
            return "Suspicious"

        return "Normal"

    # ============================================================
    # THREAT CHECK
    # ============================================================

    @classmethod
    def is_threat(
        cls,
        anomaly_score: float,
    ) -> bool:
        """
        Return True when the anomaly score reaches
        the Suspicious threshold.
        """

        return (
            float(anomaly_score)
            >= cls.SUSPICIOUS_THRESHOLD
        )

    # ============================================================
    # CONFIRMED THREAT CHECK
    # ============================================================

    @classmethod
    def is_confirmed_threat(
        cls,
        anomaly_score: float,
    ) -> bool:
        """
        Return True when the anomaly score reaches
        Medium severity.

        Medium, High, and Critical events are treated
        as confirmed security threats.
        """

        return (
            float(anomaly_score)
            >= cls.MEDIUM_THRESHOLD
        )

    # ============================================================
    # GET THRESHOLDS
    # ============================================================

    @classmethod
    def get_thresholds(cls) -> dict:
        """
        Return configured severity thresholds.
        """

        return {
            "critical": cls.CRITICAL_THRESHOLD,
            "high": cls.HIGH_THRESHOLD,
            "medium": cls.MEDIUM_THRESHOLD,
            "suspicious": cls.SUSPICIOUS_THRESHOLD,
        }