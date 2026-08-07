"""
Enterprise Feature Extraction Engine

Extracts ML-ready statistical features from a Flow.
"""

from statistics import (
    mean,
    median,
    variance,
    stdev,
)

from detection.flow_generator.flow import Flow


class FeatureExtractor:

    @staticmethod
    def extract(flow: Flow):

        sizes = flow.packet_sizes

        features = {

            # ------------------------
            # Flow Statistics
            # ------------------------

            "duration": flow.duration,

            "packet_count": flow.packet_count,

            "total_bytes": flow.total_bytes,

            "forward_packets": flow.forward_packets,

            "backward_packets": flow.backward_packets,

            # ------------------------
            # Throughput
            # ------------------------

            "packets_per_second": flow.packets_per_second,

            "bytes_per_second": flow.bytes_per_second,

            # ------------------------
            # Packet Statistics
            # ------------------------

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
        }

        return features