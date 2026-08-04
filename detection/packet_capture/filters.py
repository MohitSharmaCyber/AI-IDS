"""
filters.py

Packet filtering logic for AI-IDS.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from ipaddress import ip_address
from typing import Optional


class PacketFilter:
    """
    Performs packet validation before parsing.
    """

    @staticmethod
    def is_loopback(ip: Optional[str]) -> bool:
        if not ip:
            return False
        return ip.startswith("127.")

    @staticmethod
    def is_multicast(ip: Optional[str]) -> bool:
        if not ip:
            return False

        try:
            return ip_address(ip).is_multicast
        except ValueError:
            return False

    @staticmethod
    def is_broadcast(ip: Optional[str]) -> bool:
        return ip == "255.255.255.255"

    @staticmethod
    def allow_protocol(protocol: str) -> bool:
        allowed = {
            "TCP",
            "UDP",
            "ICMP"
        }

        return protocol.upper() in allowed

    @classmethod
    def should_process(
        cls,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        protocol: str
    ) -> bool:
        """
        Returns True if the packet should be processed.
        """

        if cls.is_loopback(src_ip):
            return False

        if cls.is_loopback(dst_ip):
            return False

        if cls.is_broadcast(src_ip):
            return False

        if cls.is_broadcast(dst_ip):
            return False

        if cls.is_multicast(src_ip):
            return False

        if cls.is_multicast(dst_ip):
            return False

        if not cls.allow_protocol(protocol):
            return False

        return True