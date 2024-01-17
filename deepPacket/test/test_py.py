import sys
sys.path.append("..")
from traffic_flow import TrafficFlowKey

def mask_ip(tflow):
    tflow.src_ip = "114.114.114.114"
    return 0

def mask_port(tflow):
    tflow.src_port = 5353

a = TrafficFlowKey("123.123.123.123", "8.8.8.8", 443, 54321, "TCP")
b = TrafficFlowKey("123.123.123.123", "8.8.8.8", 443, 54321, "TCP")
print(a == b)

flow_list = dict()
flow_list[a] = [1,2,3]
flow_list[b].append(4)
print(flow_list)

c = TrafficFlowKey()
