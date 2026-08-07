"""
tcp_analyzer.py

Enterprise TCP Flag Analysis Engine

Extracts TCP flag statistics for machine-learning.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""


class TCPAnalyzer:
    """
    Analyze TCP flags from a completed flow.
    """

    FLAG_MAP = {
        "S": "syn_count",
        "A": "ack_count",
        "F": "fin_count",
        "R": "rst_count",
        "P": "psh_count",
        "U": "urg_count",
        "E": "ece_count",
        "C": "cwr_count",
    }

    @staticmethod
    def analyze(flags_history: list[str]) -> dict:
        """
        Count every TCP flag, including combined flags
        such as SA, PA, FA, RA, etc.
        """

        features = {
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "psh_count": 0,
            "urg_count": 0,
            "ece_count": 0,
            "cwr_count": 0,
        }

        for flag_string in flags_history:

            if not flag_string:
                continue

            # Example:
            # "SA"
            # -> S
            # -> A

            for flag in flag_string:

                if flag in TCPAnalyzer.FLAG_MAP:

                    feature = TCPAnalyzer.FLAG_MAP[flag]

                    features[feature] += 1

        total = sum(features.values())

        features["total_flags"] = total

        # -----------------------------
        # Useful ML Ratios
        # -----------------------------

        features["syn_ack_ratio"] = (
            features["syn_count"] /
            features["ack_count"]
            if features["ack_count"] > 0
            else 0
        )

        features["rst_ratio"] = (
            features["rst_count"] /
            total
            if total > 0
            else 0
        )

        return features