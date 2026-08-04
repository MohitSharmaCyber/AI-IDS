"""
parser.py

Converts Scapy packets into standardized Packet objects.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from datetime import datetime
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet as ScapyPacket

from detection.packet_capture.packet import Packet
from detection.packet_capture.filters import PacketFilter
from detection.packet_capture.logger import logger


class PacketParser:
    """
    Converts Scapy packets into Packet dataclass objects.
    """

    @staticmethod
    def parse(packet: ScapyPacket, interface: str = "Unknown") -> Optional[Packet]:
        """
        Parse a Scapy packet.

        Returns:
            Packet object if valid.
            None if ignored.
        """

        try:

            # Ignore non-IP packets
            if not packet.haslayer(IP):
                return None

            ip = packet[IP]

            src_ip = ip.src
            dst_ip = ip.dst

            protocol = "UNKNOWN"
            src_port = None
            dst_port = None
            tcp_flags = None

            # ---------------- TCP ----------------

            if packet.haslayer(TCP):

                protocol = "TCP"

                tcp = packet[TCP]

                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = str(tcp.flags)

            # ---------------- UDP ----------------

            elif packet.haslayer(UDP):

                protocol = "UDP"

                udp = packet[UDP]

                src_port = udp.sport
                dst_port = udp.dport

            # ---------------- ICMP ----------------

            elif packet.haslayer(ICMP):

                protocol = "ICMP"

            # Filter unwanted traffic

            if not PacketFilter.should_process(
                src_ip,
                dst_ip,
                protocol,
            ):
                return None

            parsed_packet = Packet(

                timestamp=datetime.now(),

                interface=interface,

                src_ip=src_ip,

                dst_ip=dst_ip,

                src_port=src_port,

                dst_port=dst_port,

                protocol=protocol,

                packet_size=len(packet),

                payload_size=len(bytes(packet.payload)),

                ttl=ip.ttl,

                tcp_flags=tcp_flags,

            )

            logger.info(parsed_packet.summary())

            return parsed_packet

        except Exception as e:

            logger.error(f"Parser Error: {e}")

            return None