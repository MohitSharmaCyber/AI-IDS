from datetime import datetime
import time

from detection.flow_generator.flow_manager import FlowManager
from detection.packet_capture.packet import Packet

manager = FlowManager()

traffic = [

    ("192.168.1.100",50000,"8.8.8.8",443),

    ("192.168.1.100",50000,"8.8.8.8",443),

    ("8.8.8.8",443,"192.168.1.100",50000),

    ("192.168.1.100",50000,"8.8.8.8",443),

    ("8.8.8.8",443,"192.168.1.100",50000),
]

for src,sport,dst,dport in traffic:

    packet = Packet(

        timestamp=datetime.now(),

        interface="Wi-Fi",

        src_ip=src,

        dst_ip=dst,

        src_port=sport,

        dst_port=dport,

        protocol="TCP",

        packet_size=500,

        payload_size=480,

        ttl=64,

        tcp_flags="A",
    )

    manager.process_packet(packet)

    time.sleep(0.5)

print()

print("Active Flows :", manager.total_flows())

print()

for flow in manager.get_active_flows().values():

    print(flow.summary())

    print()

    print(flow.to_dict())