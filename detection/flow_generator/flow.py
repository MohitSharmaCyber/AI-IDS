"""
flow.py

Defines the network flow model for AI-IDS.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class Flow:
    """
    Represents a bidirectional network flow.
    """

    # --------------------------
    # Flow Identification
    # --------------------------

    flow_id: str

    src_ip: str
    dst_ip: str

    src_port: Optional[int]
    dst_port: Optional[int]

    protocol: str

    # --------------------------
    # Timing
    # --------------------------

    start_time: datetime
    end_time: datetime

    # --------------------------
    # Statistics
    # --------------------------

    packet_count: int = 0
    total_bytes: int = 0

    forward_packets: int = 0
    backward_packets: int = 0

    average_packet_size: float = 0.0

    duration: float = 0.0

    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # --------------------------
    # Raw Packet Data
    # --------------------------

    packet_sizes: list[int] = field(default_factory=list)
    packet_times: list[datetime] = field(default_factory=list)
    tcp_flags_history: list[str] = field(default_factory=list)

    # --------------------------
    # ML Fields
    # --------------------------

    anomaly_score: float = 0.0

    severity: str = "Normal"

    attack_type: Optional[str] = None

    mitre_technique: Optional[str] = None

    label: str = "Unknown"

    # --------------------------
    # Utility Methods
    # --------------------------

    def update(
        self,
        packet_size: int,
        timestamp: Optional[datetime] = None,
        tcp_flags: Optional[str] = None,
    ) -> None:
        """
        Update statistics when a new packet
        is added to the flow.
        """

        self.packet_sizes.append(packet_size)

        if timestamp is not None:
            self.packet_times.append(timestamp)

        if tcp_flags is not None:
            self.tcp_flags_history.append(tcp_flags)

        self.packet_count += 1
        self.total_bytes += packet_size

        self.average_packet_size = (
            self.total_bytes / self.packet_count
        )

        self.duration = (
            self.end_time - self.start_time
        ).total_seconds()

        if self.duration > 0:

            self.packets_per_second = (
                self.packet_count / self.duration
            )

            self.bytes_per_second = (
                self.total_bytes / self.duration
            )

    def to_dict(self) -> dict:
        """
        Convert Flow object to dictionary.
        """
        return asdict(self)

    def summary(self) -> str:
        """
        Return a short summary of the flow.
        """
        return (
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} | "
            f"{self.protocol} | "
            f"Packets={self.packet_count} | "
            f"Bytes={self.total_bytes}"
        )