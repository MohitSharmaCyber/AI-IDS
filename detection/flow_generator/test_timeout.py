"""
test_timeout.py

Tests the enterprise Flow Timeout Manager.

Author: Mohit Sharma
"""

from datetime import datetime, timedelta

from detection.flow_generator.flow import Flow
from detection.flow_generator.timeout import FlowTimeoutManager


# --------------------------------------------------
# Create test flow
# --------------------------------------------------

now = datetime.now()

flow = Flow(
    flow_id="FLOW-TEST-001",
    src_ip="192.168.1.100",
    dst_ip="8.8.8.8",
    src_port=50000,
    dst_port=443,
    protocol="TCP",
    start_time=now - timedelta(seconds=10),
    end_time=now - timedelta(seconds=10),
)


# --------------------------------------------------
# Add packets
# --------------------------------------------------

flow.update(
    packet_size=500,
    timestamp=now - timedelta(seconds=10),
    tcp_flags="A",
)

flow.end_time = now - timedelta(seconds=10)


# --------------------------------------------------
# Create timeout manager
# --------------------------------------------------

timeout_manager = FlowTimeoutManager(
    idle_timeout=5
)


# --------------------------------------------------
# Test expiration
# --------------------------------------------------

print("\n" + "=" * 60)
print("FLOW TIMEOUT TEST")
print("=" * 60)

print("\nTimeout Configuration")
print(f"Idle Timeout : {timeout_manager.idle_timeout} seconds")

print("\nFlow")
print(flow.summary())

print("\nExpired?")
print(
    timeout_manager.is_expired(
        flow,
        current_time=now
    )
)


# --------------------------------------------------
# Test removal
# --------------------------------------------------

active_flows = {
    flow.flow_id: flow
}

print("\nActive Flows Before Expiration")
print(len(active_flows))

expired_flows, expired_count = (
    timeout_manager.expire_flows(
        active_flows,
        current_time=now
    )
)

print("\nExpired Flows")
print(expired_count)

print("\nActive Flows After Expiration")
print(len(active_flows))

print("\nCompleted Flow Objects")

for expired_flow in expired_flows:
    print(expired_flow.to_dict())

print("\n" + "=" * 60)
print("TIMEOUT TEST COMPLETED")
print("=" * 60)