# -*- coding: utf-8 -*-
"""
@File    :   traffic_flow.py
@Time    :   2023/12/13 15:17:32
@Author  :   Ziheng Xu
@Desc    :   Define traffic five tuple and flow class
"""

class TrafficFlowKey(object):
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str):
        super().__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

    def __str__(self) -> str:
        ret_str = "TrafficFlowKey object <"
        ret_str += "src ip:{}, dst ip:{}, src port:{}, dst porot:{}>".format(self.src_ip, self.dst_ip, self.src_port, self.dst_port)
        return ret_str

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        cond1 = self.src_ip == other.src_ip
        cond2 = self.dst_ip == other.dst_ip
        cond3 = self.src_port == other.src_port
        cond4 = self.dst_port == other.dst_port
        cond5 = self.proto == other.proto
        return cond1 and cond2 and cond3 and cond4 and cond5 
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))

    def order_ports(self):
        if self.src_port < self.dst_port:
            tmp = self.src_ip
            self.src_ip = self.dst_ip
            self.dst_ip = tmp

            tmp = self.src_port
            self.src_port = self.dst_port
            self.dst_port = tmp


class TrafficFlow(object):
    def __init__(self, tfkey: TrafficFlowKey):
        super().__init__()
        self.tfkey = tfkey
        self.pkt_cnt = 0
        self.pkt_list = list()

    def __str__(self) -> str:
        ret = str(self.tfkey) + " packets count: {}".format(len(self.pkt_list))
        return ret

    def add_pkt(self, pkt):
        self.pkt_list.append(pkt)
        self.pkt_cnt += 1