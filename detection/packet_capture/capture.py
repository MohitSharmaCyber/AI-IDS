"""
capture.py

Live packet capture engine for AI-IDS.

Author: Mohit Sharma
"""

from scapy.all import AsyncSniffer
from scapy.interfaces import get_working_ifaces
from typing import Optional

from detection.packet_capture.parser import PacketParser
from detection.packet_capture.config import config
from detection.packet_capture.logger import logger


class PacketCapture:

    def __init__(self):

        self.sniffer: Optional[AsyncSniffer] = None

        self.running = False

        self.packet_count = 0

        self.accepted_packets = 0

    def list_interfaces(self):

        """
        Display available network interfaces.
        """

        logger.info("Available Network Interfaces")

        for iface in get_working_ifaces():

            print(f"- {iface.name}")

    def process_packet(self, packet):

        """
        Callback executed for every captured packet.
        """

        self.packet_count += 1

        parsed = PacketParser.parse(
            packet,
            interface=config.NETWORK_INTERFACE,
        )

        if parsed:

            self.accepted_packets += 1

    def start(self):

        """
        Start packet capture.
        """

        logger.info("Starting Packet Capture...")

        self.running = True

        self.sniffer = AsyncSniffer(
            iface=config.NETWORK_INTERFACE,
            prn=self.process_packet,
            store=False,
        )

        self.sniffer.start()

        logger.info("Packet Capture Started")

    def stop(self):

        """
        Stop packet capture.
        """

        if self.sniffer:

            self.sniffer.stop()

        self.running = False

        logger.info("Packet Capture Stopped")

        logger.info(f"Packets Captured : {self.packet_count}")

        logger.info(f"Packets Accepted : {self.accepted_packets}")