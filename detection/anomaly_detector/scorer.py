"""
Enterprise Anomaly Scoring Engine

Combines multiple detection signals into a normalized
anomaly score between 0.0 and 1.0.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""


class AnomalyScorer:
    """
    Calculates a normalized anomaly score from
    individual detection signals.
    """

    # Default weights
    WEIGHTS = {
    "statistical": 0.25,
    "tcp": 0.35,
    "traffic": 0.15,
    "ml": 0.25,
}

    @classmethod
    def calculate(
        cls,
        statistical_score: float = 0.0,
        tcp_score: float = 0.0,
        traffic_score: float = 0.0,
        ml_score: float = 0.0,
    ) -> float:
        """
        Calculate the final anomaly score.

        All input scores must be between 0.0 and 1.0.

        Returns:
            float: Final normalized anomaly score.
        """

        scores = {
            "statistical": statistical_score,
            "tcp": tcp_score,
            "traffic": traffic_score,
            "ml": ml_score,
        }

        normalized_scores = {}

        for name, score in scores.items():
            normalized_scores[name] = max(
                0.0,
                min(1.0, float(score))
            )

        final_score = sum(
            normalized_scores[name] * weight
            for name, weight in cls.WEIGHTS.items()
        )

        return round(
            max(0.0, min(1.0, final_score)),
            6
        )

    @classmethod
    def weighted_breakdown(
        cls,
        statistical_score: float = 0.0,
        tcp_score: float = 0.0,
        traffic_score: float = 0.0,
        ml_score: float = 0.0,
    ) -> dict:
        """
        Return the contribution of each detection signal.
        """

        scores = {
            "statistical": statistical_score,
            "tcp": tcp_score,
            "traffic": traffic_score,
            "ml": ml_score,
        }

        breakdown = {}

        for name, score in scores.items():
            normalized = max(
                0.0,
                min(1.0, float(score))
            )

            breakdown[name] = round(
                normalized * cls.WEIGHTS[name],
                6
            )

        breakdown["final_score"] = round(
            sum(breakdown.values()),
            6
        )

        return breakdown

    @classmethod
    def get_weights(cls) -> dict:
        """
        Return the configured scoring weights.
        """

        return dict(cls.WEIGHTS)