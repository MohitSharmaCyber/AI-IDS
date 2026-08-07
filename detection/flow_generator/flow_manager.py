"""
Enterprise Flow Manager
"""

from threading import Lock

from detection.flow_generator.flow import Flow
from detection.packet_capture.packet import Packet


class FlowManager:

    def __init__(self):

        self.lock = Lock()

        self.flows = {}

        self.flow_counter = 1

    @staticmethod
    def generate_key(packet: Packet):

        forward = (
            packet.src_ip,
            packet.src_port,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
        )

        backward = (
            packet.dst_ip,
            packet.dst_port,
            packet.src_ip,
            packet.src_port,
            packet.protocol,
        )

        return min(forward, backward)

    def process_packet(self, packet: Packet):

        key = self.generate_key(packet)

        with self.lock:

            if key not in self.flows:

                self.flows[key] = Flow(
                    flow_id=f"FLOW-{self.flow_counter:06}",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    start_time=packet.timestamp,
                    end_time=packet.timestamp,
                )

                self.flow_counter += 1

            flow = self.flows[key]

            flow.end_time = packet.timestamp

            if (
                packet.src_ip == flow.src_ip
                and packet.src_port == flow.src_port
            ):

                flow.forward_packets += 1

            else:

                flow.backward_packets += 1

            flow.update(
    packet_size=packet.packet_size,
    timestamp=packet.timestamp,
    tcp_flags=packet.tcp_flags,
)

            return flow

    def get_active_flows(self):

        return self.flows

    def total_flows(self):

        return len(self.flows)

    def clear(self):

        self.flows.clear()