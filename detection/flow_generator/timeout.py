"""
timeout.py

Enterprise Flow Timeout Manager.

Responsible for detecting inactive network flows,
expiring them, and returning completed flows for
downstream feature extraction and ML processing.

Author: Mohit Sharma
Project: AI-Powered Intrusion Detection System
"""

from datetime import datetime
from typing import Dict, List, Tuple

from detection.flow_generator.flow import Flow


class FlowTimeoutManager:
    """
    Manages idle timeouts for active network flows.

    A flow is considered expired when no packet has been
    received for longer than the configured timeout.
    """

    def __init__(self, idle_timeout: float = 30.0):
        """
        Args:
            idle_timeout: Maximum number of seconds a flow
                          can remain inactive.
        """

        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be greater than 0")

        self.idle_timeout = float(idle_timeout)

    # --------------------------------------------------
    # Check whether a flow has expired
    # --------------------------------------------------

    def is_expired(
        self,
        flow: Flow,
        current_time: datetime | None = None,
    ) -> bool:
        """
        Return True if the flow has been inactive longer
        than the configured idle timeout.
        """

        if current_time is None:
            current_time = datetime.now()

        elapsed = (
            current_time - flow.end_time
        ).total_seconds()

        return elapsed >= self.idle_timeout

    # --------------------------------------------------
    # Find expired flows
    # --------------------------------------------------

    def get_expired_flows(
        self,
        flows: Dict[str, Flow],
        current_time: datetime | None = None,
    ) -> List[Flow]:
        """
        Return all flows that have exceeded the idle timeout.
        """

        if current_time is None:
            current_time = datetime.now()

        expired = []

        for flow in flows.values():

            if self.is_expired(flow, current_time):
                expired.append(flow)

        return expired

    # --------------------------------------------------
    # Expire and remove flows
    # --------------------------------------------------

    def expire_flows(
        self,
        flows: Dict[str, Flow],
        current_time: datetime | None = None,
    ) -> Tuple[List[Flow], int]:
        """
        Find expired flows and remove them from the
        active-flow dictionary.

        Returns:
            Tuple containing:

            expired_flows
            number_of_expired_flows
        """

        if current_time is None:
            current_time = datetime.now()

        expired_flows = []

        expired_ids = []

        for flow_id, flow in flows.items():

            if self.is_expired(flow, current_time):

                expired_flows.append(flow)
                expired_ids.append(flow_id)

        for flow_id in expired_ids:
            del flows[flow_id]

        return expired_flows, len(expired_flows)

    # --------------------------------------------------
    # Configuration
    # --------------------------------------------------

    def set_timeout(self, idle_timeout: float) -> None:
        """
        Dynamically change the idle timeout.
        """

        if idle_timeout <= 0:
            raise ValueError(
                "idle_timeout must be greater than 0"
            )

        self.idle_timeout = float(idle_timeout)

    # --------------------------------------------------
    # Status
    # --------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"FlowTimeoutManager("
            f"idle_timeout={self.idle_timeout}s)"
        )