from datetime import datetime
import time

from detection.packet_capture.packet import Packet
from detection.flow_generator.flow_manager import FlowManager

manager = FlowManager()

for size in [100, 250, 500, 1200]:

    packet = Packet(
        timestamp=datetime.now(),
        interface="Wi-Fi",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        packet_size=size,
        payload_size=size-20,
        ttl=64,
        tcp_flags="S"
    )

    flow = manager.process_packet(packet)

    time.sleep(1)

print()

print("Total Active Flows :", manager.total_flows())

print()

for f in manager.get_active_flows().values():

    print(f.summary())

    print()

    print(f.to_dict())