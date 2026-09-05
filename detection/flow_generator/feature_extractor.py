"""
feature_extractor.py

Enterprise Feature Extraction Engine

Extracts machine-learning ready features
from a completed network flow.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from statistics import (
    mean,
    median,
    variance,
    stdev,
)

from detection.flow_generator.flow import Flow
from detection.flow_generator.tcp_analyzer import TCPAnalyzer


class FeatureExtractor:
    """
    Converts a Flow object into a machine-learning
    feature vector.
    """

    @staticmethod
    def extract(flow: Flow) -> dict:
        """
        Extract statistical, TCP, and behavioral
        features from a flow.
        """

        sizes = flow.packet_sizes
        dst_ports = flow.dst_ports_history

        # =====================================================
        # Destination Port Behavioral Features
        # =====================================================

        unique_dst_ports = len(set(dst_ports))

        port_diversity = (
            unique_dst_ports / len(dst_ports)
            if dst_ports
            else 0.0
        )

        # =====================================================
        # Flow Features
        # =====================================================

        features = {

            # -------------------------------------------------
            # Flow Statistics
            # -------------------------------------------------

            "duration": flow.duration,
            "packet_count": flow.packet_count,
            "total_bytes": flow.total_bytes,

            "forward_packets": flow.forward_packets,
            "backward_packets": flow.backward_packets,

            # -------------------------------------------------
            # Throughput
            # -------------------------------------------------

            "packets_per_second": flow.packets_per_second,
            "bytes_per_second": flow.bytes_per_second,

            # -------------------------------------------------
            # Packet Size Statistics
            # -------------------------------------------------

            "min_packet_size":
                min(sizes) if sizes else 0,

            "max_packet_size":
                max(sizes) if sizes else 0,

            "mean_packet_size":
                mean(sizes) if sizes else 0,

            "median_packet_size":
                median(sizes) if sizes else 0,

            "variance_packet_size":
                variance(sizes) if len(sizes) > 1 else 0,

            "std_packet_size":
                stdev(sizes) if len(sizes) > 1 else 0,

            "average_packet_size":
                flow.average_packet_size,

            # -------------------------------------------------
            # Destination Port Behavior
            # -------------------------------------------------

            "unique_dst_ports": unique_dst_ports,
            "port_diversity": port_diversity,
        }

        # =====================================================
        # TCP Flag Features
        # =====================================================

        tcp_features = TCPAnalyzer.analyze(
            flow.tcp_flags_history
        )

        features.update(tcp_features)

        return features