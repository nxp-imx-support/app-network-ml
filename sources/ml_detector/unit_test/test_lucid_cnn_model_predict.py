# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import unittest
import sys
import numpy as np
sys.path.insert(0, '../imx_board')

from board_inference import LucidCNNBoardModel
from flow_entry import FlowEntry
from socket_ipc import PacketFeature
from util_functions import PROTOCOL_NUM

MODEL_PATH = "/root/imx-ddos-blocker/output/LUCID-ddos-CIC2019-quant-int8.tflite"

class TestLucidCNNModelPredict(unittest.TestCase):
    """Test suite for LucidCNNBoardModel.preprocess function"""

    def _create_packet(self, idx=0, timestamp=1, l4_type=PROTOCOL_NUM.PROTOCOL_TCP,
                       l2_length=1500, l4_length=100, tcp_flags=0x02, tcp_ack=0,
                       tcp_win=8192, icmp_type=0):
        return PacketFeature(
            timestamp=timestamp,
            src_mac=b'\x00\x11\x22\x33\x44\x55',
            dst_mac=b'\x66\x77\x88\x99\xaa\xbb',
            l3_type=0x0800,
            l2_length=l2_length + idx,
            src_ip=0xc0a80001,
            dst_ip=0xc0a80002,
            ip_flags=0x4000,
            l4_type=l4_type,
            l3_length=40,
            src_port=12345 + idx,
            dst_port=80,
            tcp_flags=tcp_flags,
            tcp_ack=tcp_ack + idx,
            tcp_win=tcp_win,
            icmp_type=icmp_type,
            l4_length=l4_length + idx if l4_type in (PROTOCOL_NUM.PROTOCOL_TCP, PROTOCOL_NUM.PROTOCOL_UDP) else 0
        )

    def _create_flow(self, flow_id, packets):
        if len(packets) == 0:
            return None
        flow = FlowEntry(flow_id=flow_id, flow_key=(packets[0].l4_type, packets[0].src_ip, packets[0].src_port, 
                                                    packets[0].dst_ip, packets[0].dst_port), packet=packets[0])
        if len(packets) > 1:
            flow.packets += packets[1:]
        return flow

    def test_multiple_flows_predict(self):
        model = LucidCNNBoardModel(MODEL_PATH, (-1, 10, 11, 1))

        flow1 = self._create_flow(flow_id=1, packets=[self._create_packet(0)])

        flow2_pkt = [self._create_packet(0), self._create_packet(1)]
        flow2_pkt[1].timestamp = flow2_pkt[0].timestamp + 1
        flow2 = self._create_flow(flow_id=2, packets=flow2_pkt)
        
        flow3 = self._create_flow(flow_id=3, packets=[self._create_packet(0)])

        detect_ret = model.detect([flow1, flow2, flow3])

        self.assertEqual(len(detect_ret), 3)
        print(detect_ret)

    def test_multiple_slices_flow_predict(self):
        model = LucidCNNBoardModel(MODEL_PATH, (-1, 10, 11, 1))

        flow1 = self._create_flow(flow_id=1, packets=[self._create_packet(0)])

        flow2_pkt = [self._create_packet(i) for i in range(10)]
        flow2_pkt += [self._create_packet(i, timestamp=21) for i in range(5)]
        flow2_pkt[1].timestamp = flow2_pkt[0].timestamp + 1
        flow2 = self._create_flow(flow_id=2, packets=flow2_pkt)
        
        flow3 = self._create_flow(flow_id=3, packets=[self._create_packet(0)])

        detect_ret = model.detect([flow1, flow2, flow3])

        self.assertEqual(len(detect_ret), 3)
        print(detect_ret)

if __name__ == '__main__':
    unittest.main()
