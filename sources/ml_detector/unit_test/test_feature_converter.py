#!/usr/bin/env python3
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

import unittest
import numpy as np
import sys
sys.path.insert(0, '../model')
from feature_converter import packet_feature_to_model_input, prepare_time_window
from socket_ipc import PacketFeature

class TestFeatureConverter(unittest.TestCase):
    def test_packet_to_features(self):
        packet = PacketFeature(
            timestamp=1234567890,
            src_mac=b'\x00\x11\x22\x33\x44\x55',
            dst_mac=b'\x66\x77\x88\x99\xaa\xbb',
            protocol_type=0x0800,
            src_ip=0xc0a80001,
            dst_ip=0xc0a80002,
            transmission_type=6,
            src_port=12345,
            dst_port=80,
            packet_size=1500,
            tcp_flags=0x02
        )
        features = packet_feature_to_model_input(packet)
        self.assertEqual(len(features), 11)
        self.assertTrue(np.all(features >= 0))

    def test_time_window_preparation(self):
        packets = [PacketFeature(timestamp=i) for i in range(10)]
        x_data = prepare_time_window(packets)
        self.assertEqual(x_data.shape, (1, 10, 11, 1))

if __name__ == '__main__':
    unittest.main()
