from datetime import datetime
import time

from detection.flow_generator.flow import Flow

flow = Flow(
    flow_id="FLOW-001",
    src_ip="192.168.1.100",
    dst_ip="8.8.8.8",
    src_port=50000,
    dst_port=443,
    protocol="TCP",
    start_time=datetime.now(),
    end_time=datetime.now(),
)

print("Initial Flow")
print(flow.summary())

for size in [100, 500, 1200]:

    time.sleep(1)

    flow.end_time = datetime.now()

    flow.update(size)

print()

print("Updated Flow")

print(flow.summary())

print()

print(flow.to_dict())