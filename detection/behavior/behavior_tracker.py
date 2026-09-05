"""
Host-Level Behavioral Tracking Engine

Tracks network behavior across multiple flows from the same
source IP and extracts behavioral indicators useful for IDS
detection.

Current behavioral indicators:
    - Unique destination IPs
    - Unique destination ports
    - Total flows
    - Total packets
    - Total bytes
    - TCP flows
    - SYN flows
    - RST flows
    - Failed connections
    - Connection failure ratio
    - Port scan score
    - Destination IP fan-out
    - Destination port fan-out
    - Flow rate
    - Packet rate
    - Byte rate

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class HostBehavior:
    """
    Behavioral profile for a single source IP.
    """

    src_ip: str

    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0

    unique_destination_ips: set[str] = field(
        default_factory=set
    )

    unique_destination_ports: set[int] = field(
        default_factory=set
    )

    tcp_flows: int = 0
    syn_flows: int = 0
    rst_flows: int = 0
    failed_connection_flows: int = 0

    # ------------------------------------------------------------
    # Update behavior
    # ------------------------------------------------------------

    def update(
        self,
        flow,
    ) -> None:
        """
        Update the behavioral profile using a Flow object.
        """

        now = (
            flow.end_time
            or flow.start_time
            or datetime.now()
        )

        if self.first_seen is None:
            self.first_seen = (
                flow.start_time
                or now
            )

        self.last_seen = now

        # --------------------------------------------------------
        # Basic traffic statistics
        # --------------------------------------------------------

        self.total_flows += 1

        self.total_packets += int(
            getattr(
                flow,
                "packet_count",
                0,
            )
            or 0
        )

        self.total_bytes += int(
            getattr(
                flow,
                "total_bytes",
                0,
            )
            or 0
        )

        # --------------------------------------------------------
        # Destination information
        # --------------------------------------------------------

        dst_ip = getattr(
            flow,
            "dst_ip",
            None,
        )

        if dst_ip:
            self.unique_destination_ips.add(
                dst_ip
            )

        dst_port = getattr(
            flow,
            "dst_port",
            None,
        )

        if dst_port is not None:
            self.unique_destination_ports.add(
                int(dst_port)
            )

        # --------------------------------------------------------
        # TCP behavior
        # --------------------------------------------------------

        protocol = str(
            getattr(
                flow,
                "protocol",
                "",
            )
            or ""
        ).upper()

        tcp_flags = getattr(
            flow,
            "tcp_flags_history",
            [],
        ) or []

        if protocol == "TCP":
            self.tcp_flows += 1

            has_syn = any(
                "S" in str(flag).upper()
                for flag in tcp_flags
            )

            has_syn_ack = any(
                (
                    "S" in str(flag).upper()
                    and "A" in str(flag).upper()
                )
                for flag in tcp_flags
            )

            has_rst = any(
                "R" in str(flag).upper()
                for flag in tcp_flags
            )

            # SYN flow means a flow containing SYN without
            # a completed SYN/ACK handshake.
            if has_syn and not has_syn_ack:
                self.syn_flows += 1

            if has_rst:
                self.rst_flows += 1

            # A simple failed-connection indicator:
            # SYN activity followed by RST is treated as
            # a failed connection attempt.
            if has_syn and has_rst:
                self.failed_connection_flows += 1

    # ------------------------------------------------------------
    # Destination metrics
    # ------------------------------------------------------------

    @property
    def unique_destination_ip_count(self) -> int:
        """Number of unique destination IP addresses."""

        return len(
            self.unique_destination_ips
        )

    @property
    def unique_destination_port_count(self) -> int:
        """Number of unique destination ports."""

        return len(
            self.unique_destination_ports
        )

    @property
    def destination_ip_fanout(self) -> float:
        """
        Average number of flows per unique destination IP.
        """

        if self.unique_destination_ip_count == 0:
            return 0.0

        return (
            self.total_flows
            / self.unique_destination_ip_count
        )

    @property
    def destination_port_fanout(self) -> float:
        """
        Average number of flows per unique destination port.
        """

        if self.unique_destination_port_count == 0:
            return 0.0

        return (
            self.total_flows
            / self.unique_destination_port_count
        )

    # ------------------------------------------------------------
    # Rate metrics
    # ------------------------------------------------------------

    @property
    def observation_duration(self) -> float:
        """
        Duration of the observed behavior in seconds.
        """

        if (
            self.first_seen is None
            or self.last_seen is None
        ):
            return 0.0

        duration = (
            self.last_seen
            - self.first_seen
        ).total_seconds()

        return max(duration, 0.0)

    @property
    def flow_rate(self) -> float:
        """
        Number of flows per second.
        """

        duration = self.observation_duration

        if duration <= 0:
            return float(
                self.total_flows
            )

        return (
            self.total_flows
            / duration
        )

    @property
    def packet_rate(self) -> float:
        """
        Number of packets per second.
        """

        duration = self.observation_duration

        if duration <= 0:
            return float(
                self.total_packets
            )

        return (
            self.total_packets
            / duration
        )

    @property
    def byte_rate(self) -> float:
        """
        Number of bytes per second.
        """

        duration = self.observation_duration

        if duration <= 0:
            return float(
                self.total_bytes
            )

        return (
            self.total_bytes
            / duration
        )

    # ------------------------------------------------------------
    # Failure metrics
    # ------------------------------------------------------------

    @property
    def connection_failure_ratio(self) -> float:
        """
        Ratio of failed connections to total TCP flows.
        """

        if self.tcp_flows == 0:
            return 0.0

        return min(
            self.failed_connection_flows
            / self.tcp_flows,
            1.0,
        )

    @property
    def syn_flow_ratio(self) -> float:
        """
        Ratio of SYN flows to TCP flows.
        """

        if self.tcp_flows == 0:
            return 0.0

        return min(
            self.syn_flows
            / self.tcp_flows,
            1.0,
        )

    @property
    def rst_flow_ratio(self) -> float:
        """
        Ratio of RST flows to TCP flows.
        """

        if self.tcp_flows == 0:
            return 0.0

        return min(
            self.rst_flows
            / self.tcp_flows,
            1.0,
        )

    # ------------------------------------------------------------
    # Port scan score
    # ------------------------------------------------------------

    @property
    def scan_score(self) -> float:
        """
        Calculate a behavioral port-scan score.

        Indicators:
            - Destination port diversity
            - Destination IP diversity
            - Flow volume
            - SYN activity
            - Connection failures

        Score range:
            0.0 - 1.0
        """

        score = 0.0

        # --------------------------------------------------------
        # Destination port diversity
        # --------------------------------------------------------

        if self.unique_destination_port_count >= 10:
            score += 0.40

        elif self.unique_destination_port_count >= 5:
            score += 0.25

        elif self.unique_destination_port_count >= 3:
            score += 0.10

        # --------------------------------------------------------
        # Destination IP diversity
        # --------------------------------------------------------

        if self.unique_destination_ip_count >= 10:
            score += 0.35

        elif self.unique_destination_ip_count >= 5:
            score += 0.20

        elif self.unique_destination_ip_count >= 3:
            score += 0.10

        # --------------------------------------------------------
        # Flow volume
        # --------------------------------------------------------

        if self.total_flows >= 50:
            score += 0.25

        elif self.total_flows >= 20:
            score += 0.15

        elif self.total_flows >= 10:
            score += 0.05

        # --------------------------------------------------------
        # SYN-heavy behavior
        # --------------------------------------------------------

        if (
            self.syn_flow_ratio >= 0.80
            and self.syn_flows >= 5
        ):
            score += 0.15

        elif (
            self.syn_flow_ratio >= 0.50
            and self.syn_flows >= 3
        ):
            score += 0.08

        # --------------------------------------------------------
        # Failed connection behavior
        # --------------------------------------------------------

        if (
            self.connection_failure_ratio >= 0.80
            and self.failed_connection_flows >= 5
        ):
            score += 0.15

        elif (
            self.connection_failure_ratio >= 0.50
            and self.failed_connection_flows >= 3
        ):
            score += 0.08

        return min(
            score,
            1.0,
        )

    # ------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------

    def summary(self) -> dict:
        """
        Return a serializable behavioral summary.
        """

        return {
            "src_ip": self.src_ip,

            "first_seen": (
                self.first_seen.isoformat()
                if self.first_seen
                else None
            ),

            "last_seen": (
                self.last_seen.isoformat()
                if self.last_seen
                else None
            ),

            "observation_duration": (
                round(
                    self.observation_duration,
                    4,
                )
            ),

            "total_flows": self.total_flows,

            "total_packets": self.total_packets,

            "total_bytes": self.total_bytes,

            "unique_destination_ips": (
                self.unique_destination_ip_count
            ),

            "unique_destination_ports": (
                self.unique_destination_port_count
            ),

            "destination_ip_fanout": round(
                self.destination_ip_fanout,
                4,
            ),

            "destination_port_fanout": round(
                self.destination_port_fanout,
                4,
            ),

            "flow_rate": round(
                self.flow_rate,
                4,
            ),

            "packet_rate": round(
                self.packet_rate,
                4,
            ),

            "byte_rate": round(
                self.byte_rate,
                4,
            ),

            "tcp_flows": self.tcp_flows,

            "syn_flows": self.syn_flows,

            "rst_flows": self.rst_flows,

            "failed_connection_flows": (
                self.failed_connection_flows
            ),

            "syn_flow_ratio": round(
                self.syn_flow_ratio,
                4,
            ),

            "rst_flow_ratio": round(
                self.rst_flow_ratio,
                4,
            ),

            "connection_failure_ratio": round(
                self.connection_failure_ratio,
                4,
            ),

            "scan_score": round(
                self.scan_score,
                4,
            ),
        }


class BehaviorTracker:
    """
    Tracks HostBehavior objects using source IP addresses.

    A sliding time window is used to prevent old activity from
    permanently influencing current behavioral decisions.
    """

    def __init__(
        self,
        window_seconds: int = 60,
    ):
        """
        Initialize the behavior tracker.

        Args:
            window_seconds:
                Time window used for stale-host cleanup.
        """

        self.window_seconds = max(
            int(window_seconds),
            1,
        )

        self.hosts: dict[
            str,
            HostBehavior,
        ] = {}

    # ------------------------------------------------------------
    # Update
    # ------------------------------------------------------------

    def update(
        self,
        flow: Flow,
    ) -> HostBehavior:
        """
        Add a flow to the appropriate source-IP profile.
        """

        self._cleanup()

        src_ip = getattr(
            flow,
            "src_ip",
            None,
        )

        if not src_ip:
            raise ValueError(
                "Flow must contain a valid src_ip"
            )

        if src_ip not in self.hosts:
            self.hosts[src_ip] = HostBehavior(
                src_ip=src_ip
            )

        self.hosts[src_ip].update(
            flow
        )

        return self.hosts[src_ip]

    # ------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------

    def get_behavior(
        self,
        src_ip: str,
    ) -> Optional[HostBehavior]:
        """
        Get the behavioral profile for a source IP.
        """

        self._cleanup()

        return self.hosts.get(
            src_ip
        )

    def get_all_behaviors(
        self,
    ) -> list[HostBehavior]:
        """
        Return all currently active host profiles.
        """

        self._cleanup()

        return list(
            self.hosts.values()
        )

    # ------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------

    def _cleanup(self) -> None:
        """
        Remove hosts whose activity is outside the
        configured behavioral window.
        """

        now = datetime.now()

        stale_hosts: list[str] = []

        for src_ip, behavior in self.hosts.items():

            if behavior.last_seen is None:
                continue

            age = (
                now
                - behavior.last_seen
            ).total_seconds()

            if age > self.window_seconds:
                stale_hosts.append(
                    src_ip
                )

        for src_ip in stale_hosts:
            del self.hosts[src_ip]

    # ------------------------------------------------------------
    # Management
    # ------------------------------------------------------------

    def remove_host(
        self,
        src_ip: str,
    ) -> None:
        """
        Remove one source-IP profile.
        """

        self.hosts.pop(
            src_ip,
            None,
        )

    def clear(self) -> None:
        """
        Remove all behavioral profiles.
        """

        self.hosts.clear()

    # ------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------

    def summary(self) -> list[dict]:
        """
        Return summaries for all tracked hosts.
        """

        self._cleanup()

        return [
            behavior.summary()
            for behavior in self.hosts.values()
        ]

    def get_window_seconds(self) -> int:
        """
        Return the configured behavioral window.
        """

        return self.window_seconds