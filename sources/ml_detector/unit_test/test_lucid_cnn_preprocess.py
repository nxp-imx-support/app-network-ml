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

class TestLucidCNNPreprocess(unittest.TestCase):
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
        flow = FlowEntry(flow_id=flow_id, packets=packets)
        return flow

    def test_preprocess_empty_flows(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        x_data, x_label = model.preprocess([])

        self.assertTrue(x_data.size == 0)
        self.assertTrue(x_label.size == 0)

    def test_preprocess_single_flow_one_packet(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        packets = [self._create_packet(0)]
        flow = self._create_flow(flow_id=1, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(len(x_data), 1)
        self.assertEqual(len(x_label), 1)
        self.assertEqual(x_label[0], 1)
        self.assertEqual(len(x_data[0]), 10)
        self.assertEqual(len(x_data[0][0]), 11)

    def test_preprocess_single_flow_full_window(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        packets = [self._create_packet(i) for i in range(10)]
        flow = self._create_flow(flow_id=5, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(len(x_data), 1)
        self.assertEqual(len(x_label), 1)
        self.assertEqual(x_label[0], 5)

    def test_preprocess_single_flow_full_window_with_more_pkts(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        packets = [self._create_packet(i) for i in range(20)]
        flow = self._create_flow(flow_id=5, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(len(x_data), 1)
        self.assertEqual(len(x_label), 1)
        self.assertEqual(x_label[0], 5)

    def test_preprocess_multiple_flows(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        flow1 = self._create_flow(flow_id=1, packets=[self._create_packet(0)])

        flow2_pkt = [self._create_packet(0), self._create_packet(1)]
        flow2_pkt[1].timestamp = flow2_pkt[0].timestamp + 1
        flow2 = self._create_flow(flow_id=2, packets=flow2_pkt)
        
        flow3 = self._create_flow(flow_id=3, packets=[self._create_packet(0)])

        x_data, x_label = model.preprocess([flow1, flow2, flow3])

        self.assertEqual(len(x_data), 3)
        self.assertEqual(x_label.tolist(), [1, 2, 3])

    def test_preprocess_output_shape(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        packets = [self._create_packet(i) for i in range(5)]
        flow = self._create_flow(flow_id=1, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(x_data[0].shape, (10, 11))

    def test_preprocess_padding(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))
        packets = [self._create_packet(i) for i in range(3)]
        flow = self._create_flow(flow_id=1, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(x_data[0].shape, (10, 11))
        self.assertTrue((x_data[0][3:] == 0).all())

    def test_preprocess_time_window_split(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        packets = [
            self._create_packet(0, timestamp=10),
            self._create_packet(1, timestamp=11),
            self._create_packet(2, timestamp=12),
            self._create_packet(3, timestamp=21),
            self._create_packet(4, timestamp=22),
        ]
        flow = self._create_flow(flow_id=1, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(len(x_data), 2)
        self.assertEqual(x_label.tolist(), [1, 1])

    def test_preprocess_tcp_packet(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        packets = [self._create_packet(0, l4_type=PROTOCOL_NUM.PROTOCOL_TCP, l4_length=100)]
        flow = self._create_flow(flow_id=1, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(len(x_data), 1)

    def test_preprocess_udp_packet(self):
        model = LucidCNNBoardModel(MODEL_PATH, (10, 11, 1))

        packets = [self._create_packet(0, l4_type=PROTOCOL_NUM.PROTOCOL_UDP, l4_length=50)]
        flow = self._create_flow(flow_id=1, packets=packets)
        x_data, x_label = model.preprocess([flow])

        self.assertEqual(len(x_data), 1)


if __name__ == '__main__':
    unittest.main()
