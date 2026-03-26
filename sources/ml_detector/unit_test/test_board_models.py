#!/usr/bin/env python3
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import unittest
import numpy as np
import sys
sys.path.insert(0, '../imx_board')
from board_inference import LucidCNNBoardModel, SimpleDNNBoardModel
from socket_ipc import PacketFeature


class TestBoardModels(unittest.TestCase):
    def _create_test_packet(self, idx=0):
        return PacketFeature(
            timestamp=1000000 + idx,
            src_mac=b'\x00\x11\x22\x33\x44\x55',
            dst_mac=b'\x66\x77\x88\x99\xaa\xbb',
            protocol_type=0x0800,
            src_ip=0xc0a80001,
            dst_ip=0xc0a80002,
            transmission_type=6,
            src_port=12345 + idx,
            dst_port=80,
            packet_size=1500,
            tcp_flags=0x02
        )

    def test_lucid_cnn_preprocess_shape(self):
        model = LucidCNNBoardModel.__new__(LucidCNNBoardModel)
        model.window_size = 10
        model._packet_features_to_array = lambda pkts: np.zeros((10, 11), dtype=np.float32)

        packets = [self._create_test_packet(i) for i in range(10)]
        result = model.preprocess(packets)
        self.assertEqual(result.shape, (1, 10, 11, 1))

    def test_lucid_cnn_input_shape(self):
        model = LucidCNNBoardModel.__new__(LucidCNNBoardModel)
        model.window_size = 10
        self.assertEqual(model.input_shape, (10, 11, 1))

    def test_simple_dnn_preprocess_shape(self):
        model = SimpleDNNBoardModel.__new__(SimpleDNNBoardModel)
        model.window_size = 10
        model._packet_features_to_array = lambda pkts: np.zeros((10, 11), dtype=np.float32)

        packets = [self._create_test_packet(i) for i in range(10)]
        result = model.preprocess(packets)
        self.assertEqual(result.shape, (1, 110))

    def test_simple_dnn_input_shape(self):
        model = SimpleDNNBoardModel.__new__(SimpleDNNBoardModel)
        model.window_size = 10
        self.assertEqual(model.input_shape, (110,))

    def test_lucid_cnn_postprocess_attack(self):
        model = LucidCNNBoardModel.__new__(LucidCNNBoardModel)
        is_attack, confidence = model.postprocess(np.array([0.8]))
        self.assertEqual(is_attack, 1)
        self.assertEqual(confidence, 60)

    def test_lucid_cnn_postprocess_normal(self):
        model = LucidCNNBoardModel.__new__(LucidCNNBoardModel)
        is_attack, confidence = model.postprocess(np.array([0.2]))
        self.assertEqual(is_attack, 0)
        self.assertEqual(confidence, 60)

    def test_simple_dnn_postprocess_attack(self):
        model = SimpleDNNBoardModel.__new__(SimpleDNNBoardModel)
        is_attack, confidence = model.postprocess(np.array([0.9]))
        self.assertEqual(is_attack, 1)
        self.assertEqual(confidence, 80)


if __name__ == '__main__':
    unittest.main()
