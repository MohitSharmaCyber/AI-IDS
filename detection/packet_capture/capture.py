"""
capture.py

Live packet capture engine for AI-IDS.

Pipeline:

Scapy Packet
    ↓
PacketParser
    ↓
Packet
    ↓
FlowManager
    ↓
AnomalyDetector
    ↓
Detection Result

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from typing import Optional

from scapy.all import AsyncSniffer
from scapy.interfaces import get_working_ifaces

from detection.packet_capture.parser import PacketParser
from detection.packet_capture.config import config
from detection.packet_capture.logger import logger

from detection.flow_generator.flow_manager import FlowManager
from detection.anomaly_detector.detector import AnomalyDetector


class PacketCapture:
    """
    Live packet capture and detection engine.

    Responsibilities:
        - Capture packets
        - Parse packets
        - Convert packets into flows
        - Analyze flows for anomalies
        - Track packet statistics
        - Track detection statistics
    """

    def __init__(
        self,
        flow_manager: Optional[FlowManager] = None,
        anomaly_detector: Optional[AnomalyDetector] = None,
    ):
        """
        Initialize packet capture.

        Args:
            flow_manager:
                Optional FlowManager instance.

            anomaly_detector:
                Optional AnomalyDetector instance.
        """

        self.sniffer: Optional[AsyncSniffer] = None

        self.running = False

        # Packet counters
        self.packet_count = 0
        self.accepted_packets = 0

        # Detection counters
        self.analyzed_flows = 0
        self.threat_count = 0

        # Core pipeline components
        self.flow_manager = (
            flow_manager
            if flow_manager is not None
            else FlowManager()
        )

        self.anomaly_detector = (
            anomaly_detector
            if anomaly_detector is not None
            else AnomalyDetector()
        )

    def list_interfaces(self):
        """
        Display available network interfaces.
        """

        logger.info("Available Network Interfaces")

        for iface in get_working_ifaces():
            print(f"- {iface.name}")

    def process_packet(self, packet):
        """
        Process one captured Scapy packet.

        Pipeline:

            Scapy Packet
                ↓
            PacketParser
                ↓
            FlowManager
                ↓
            AnomalyDetector
        """

        self.packet_count += 1

        try:

            # -------------------------------------------------
            # STEP 1: Parse packet
            # -------------------------------------------------

            parsed = PacketParser.parse(
                packet,
                interface=config.NETWORK_INTERFACE,
            )

            if parsed is None:
                return

            self.accepted_packets += 1

            # -------------------------------------------------
            # STEP 2: Convert packet into flow
            # -------------------------------------------------

            flow = self.flow_manager.process_packet(parsed)

            # -------------------------------------------------
            # STEP 3: Analyze flow
            # -------------------------------------------------

            analyzed_flow = self.anomaly_detector.analyze(flow)

            self.analyzed_flows += 1

            # -------------------------------------------------
            # STEP 4: Log detection result
            # -------------------------------------------------

            logger.info(
                "Detection | "
                f"Flow={analyzed_flow.flow_id} | "
                f"Score={analyzed_flow.anomaly_score:.3f} | "
                f"Severity={analyzed_flow.severity} | "
                f"Attack={analyzed_flow.attack_type} | "
                f"Label={analyzed_flow.label}"
            )

            # -------------------------------------------------
            # STEP 5: Track threats
            # -------------------------------------------------

            if analyzed_flow.label in ("Suspicious", "Malicious"):

                self.threat_count += 1

                logger.warning(
                    "THREAT DETECTED | "
                    f"Flow={analyzed_flow.flow_id} | "
                    f"Source={analyzed_flow.src_ip} | "
                    f"Destination={analyzed_flow.dst_ip} | "
                    f"Score={analyzed_flow.anomaly_score:.3f} | "
                    f"Severity={analyzed_flow.severity} | "
                    f"Attack={analyzed_flow.attack_type} | "
                    f"MITRE={analyzed_flow.mitre_technique}"
                )

        except Exception as e:

            logger.error(
                f"Packet Processing Error: {e}"
            )

    def start(self):
        """
        Start live packet capture.
        """

        if self.running:

            logger.warning(
                "Packet Capture is already running."
            )

            return

        logger.info(
            "Starting Packet Capture..."
        )

        self.running = True

        self.sniffer = AsyncSniffer(
            iface=config.NETWORK_INTERFACE,
            prn=self.process_packet,
            store=False,
        )

        try:

            self.sniffer.start()

            logger.info(
                "Packet Capture Started"
            )

            logger.info(
                f"Interface : {config.NETWORK_INTERFACE}"
            )

        except Exception as e:

            self.running = False

            logger.error(
                f"Failed to start packet capture: {e}"
            )

            raise

    def stop(self):
        """
        Stop packet capture.
        """

        if self.sniffer:

            try:

                self.sniffer.stop()

            except Exception as e:

                logger.error(
                    f"Error stopping sniffer: {e}"
                )

        self.running = False

        # Expire remaining flows
        try:

            expired_flows = (
                self.flow_manager.expire_flows()
            )

            for flow in expired_flows:

                logger.info(
                    "Flow Expired | "
                    f"Flow={flow.flow_id} | "
                    f"Score={flow.anomaly_score:.3f} | "
                    f"Severity={flow.severity} | "
                    f"Attack={flow.attack_type}"
                )

        except Exception as e:

            logger.error(
                f"Flow expiration error: {e}"
            )

        logger.info(
            "Packet Capture Stopped"
        )

        logger.info(
            f"Packets Captured : {self.packet_count}"
        )

        logger.info(
            f"Packets Accepted : {self.accepted_packets}"
        )

        logger.info(
            f"Flows Analyzed   : {self.analyzed_flows}"
        )

        logger.info(
            f"Threats Detected : {self.threat_count}"
        )

    def get_statistics(self) -> dict:
        """
        Return packet capture and detection statistics.
        """

        return {
            "running": self.running,
            "packets_captured": self.packet_count,
            "packets_accepted": self.accepted_packets,
            "flows_analyzed": self.analyzed_flows,
            "threats_detected": self.threat_count,
            "active_flows": self.flow_manager.total_flows(),
            "completed_flows": (
                self.flow_manager.total_completed_flows()
            ),
        }

    def reset_statistics(self):
        """
        Reset packet and detection counters.
        """

        self.packet_count = 0
        self.accepted_packets = 0
        self.analyzed_flows = 0
        self.threat_count = 0

        logger.info(
            "Capture statistics reset."
        )