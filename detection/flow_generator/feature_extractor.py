"""
Feature Extraction Engine

Converts a Flow object into ML-ready features.
"""

from statistics import mean

from detection.flow_generator.flow import Flow


class FeatureExtractor:

    @staticmethod
    def extract(flow: Flow):

        features = {

            "duration": flow.duration,

            "packet_count": flow.packet_count,

            "total_bytes": flow.total_bytes,

            "forward_packets": flow.forward_packets,

            "backward_packets": flow.backward_packets,

            "average_packet_size": flow.average_packet_size,

            "packets_per_second": flow.packets_per_second,

            "bytes_per_second": flow.bytes_per_second,

            "min_packet_size":
                min(flow.packet_sizes) if flow.packet_sizes else 0,

            "max_packet_size":
                max(flow.packet_sizes) if flow.packet_sizes else 0,

            "mean_packet_size":
                mean(flow.packet_sizes) if flow.packet_sizes else 0,
        }

        return features