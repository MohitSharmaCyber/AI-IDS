"""
Enterprise Flow Manager

Manages bidirectional network flows and integrates
flow timeout handling for the AI-IDS pipeline.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from threading import Lock

from detection.flow_generator.flow import Flow
from detection.flow_generator.timeout import FlowTimeoutManager
from detection.packet_capture.packet import Packet


class FlowManager:
    """
    Enterprise network flow manager.

    Responsibilities:
        - Create network flows
        - Maintain bidirectional flows
        - Update flow statistics
        - Track forward/backward traffic
        - Track destination ports
        - Detect expired flows
        - Return completed flows
    """

    def __init__(self, idle_timeout: float = 5.0):
        self.lock = Lock()

        # Active flows
        self.flows: dict = {}

        # Completed/expired flows
        self.completed_flows: list[Flow] = []

        # Flow ID counter
        self.flow_counter = 1

        # Timeout manager
        self.timeout_manager = FlowTimeoutManager(
            idle_timeout=idle_timeout
        )

    # ============================================================
    # FLOW KEY GENERATION
    # ============================================================

    @staticmethod
    def generate_key(packet: Packet):
        """
        Generate a bidirectional flow key.

        Forward and reverse packets belonging to the same
        connection receive the same key.
        """

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

    # ============================================================
    # PACKET PROCESSING
    # ============================================================

    def process_packet(self, packet: Packet) -> Flow:
        """
        Process a packet and update/create its flow.

        Returns:
            Flow: Active flow associated with the packet.
        """

        key = self.generate_key(packet)

        with self.lock:

            # ----------------------------------------------------
            # Create new flow
            # ----------------------------------------------------

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

            # ----------------------------------------------------
            # Get existing flow
            # ----------------------------------------------------

            flow = self.flows[key]

            # Update end timestamp
            flow.end_time = packet.timestamp

            # ----------------------------------------------------
            # Direction tracking
            # ----------------------------------------------------

            if (
                packet.src_ip == flow.src_ip
                and packet.src_port == flow.src_port
            ):
                flow.forward_packets += 1
            else:
                flow.backward_packets += 1

            # ----------------------------------------------------
            # Update statistics
            # ----------------------------------------------------

            flow.update(
                packet_size=packet.packet_size,
                timestamp=packet.timestamp,
                tcp_flags=packet.tcp_flags,
                dst_port=packet.dst_port,
            )

            return flow

    # ============================================================
    # TIMEOUT PROCESSING
    # ============================================================

    def expire_flows(self, current_time=None) -> list[Flow]:
        """
        Detect and remove expired flows.

        Expired flows are moved from active flows
        to completed_flows.

        Returns:
            list[Flow]: Expired/completed flows.
        """

        with self.lock:

            expired_flows, expired_count = (
                self.timeout_manager.expire_flows(
                    self.flows,
                    current_time=current_time,
                )
            )

            self.completed_flows.extend(expired_flows)

            return expired_flows

    # ============================================================
    # ACTIVE FLOWS
    # ============================================================

    def get_active_flows(self):
        """
        Return currently active flows.
        """

        with self.lock:
            return dict(self.flows)

    # ============================================================
    # COMPLETED FLOWS
    # ============================================================

    def get_completed_flows(self):
        """
        Return completed/expired flows.
        """

        with self.lock:
            return list(self.completed_flows)

    # ============================================================
    # FLOW COUNTERS
    # ============================================================

    def total_flows(self):
        """
        Return number of currently active flows.
        """

        with self.lock:
            return len(self.flows)

    def total_completed_flows(self):
        """
        Return number of completed flows.
        """

        with self.lock:
            return len(self.completed_flows)

    # ============================================================
    # CLEAR METHODS
    # ============================================================

    def clear(self):
        """
        Clear active flows.
        """

        with self.lock:
            self.flows.clear()

    def clear_completed(self):
        """
        Clear completed flows.
        """

        with self.lock:
            self.completed_flows.clear()

    def clear_all(self):
        """
        Clear both active and completed flows.
        """

        with self.lock:
            self.flows.clear()
            self.completed_flows.clear()