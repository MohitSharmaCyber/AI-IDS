"""
packet.py

Defines the standardized packet model used throughout the AI-IDS project.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class Packet:
    """
    Standardized packet representation.

    Every captured packet is converted into this object before being
    processed by the detection engine, ML engine, alert engine,
    or stored in the database.
    """

    # -------------------------
    # Capture Information
    # -------------------------

    timestamp: datetime

    interface: str

    # -------------------------
    # Network Information
    # -------------------------

    src_ip: str
    dst_ip: str

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    protocol: str = "UNKNOWN"

    # -------------------------
    # Packet Statistics
    # -------------------------

    packet_size: int = 0

    payload_size: int = 0

    ttl: Optional[int] = None

    tcp_flags: Optional[str] = None

    # -------------------------
    # Future ML Fields
    # -------------------------

    flow_id: Optional[str] = None

    direction: Optional[str] = None

    anomaly_score: float = 0.0

    severity: str = "Normal"

    attack_type: Optional[str] = None

    mitre_technique: Optional[str] = None

    country: Optional[str] = None

    reputation_score: Optional[int] = None

    # -------------------------
    # Utility Functions
    # -------------------------

    def to_dict(self) -> dict:
        """
        Convert Packet object into dictionary.
        """
        return asdict(self)

    def summary(self) -> str:
        """
        Human-readable packet summary.
        """
        return (
            f"[{self.timestamp}] "
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} "
            f"{self.protocol} "
            f"({self.packet_size} Bytes)"
        )