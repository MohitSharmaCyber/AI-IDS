"""
flow_manager.py

Manages active network flows.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from datetime import datetime
from threading import Lock

from detection.flow_generator.flow import Flow
from detection.packet_capture.packet import Packet


class FlowManager:
    """
    Creates and updates active flows.
    """

    def __init__(self):

        self.flows = {}

        self.lock = Lock()

    @staticmethod
    def generate_flow_key(packet: Packet):
        """
        Generates a unique flow key.
        """

        return (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
        )

    def process_packet(self, packet: Packet) -> Flow:
        """
        Create or update a flow.
        """

        key = self.generate_flow_key(packet)

        with self.lock:

            if key not in self.flows:

                flow = Flow(
                    flow_id=f"FLOW-{len(self.flows)+1:06}",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    start_time=packet.timestamp,
                    end_time=packet.timestamp,
                )

                self.flows[key] = flow

            flow = self.flows[key]

            flow.end_time = packet.timestamp

            flow.update(packet.packet_size)

            return flow

    def get_active_flows(self):

        return self.flows

    def total_flows(self):

        return len(self.flows)

    def clear(self):

        self.flows.clear()