#!/usr/bin/env python3
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

import unittest
import struct
import sys
sys.path.insert(0, '../model')
from socket_ipc import TLVMessage, PacketFeature, DetectionResult

class TestTLVProtocol(unittest.TestCase):
    def test_tlv_header_encoding(self):
        msg_type = TLVMessage.MSG_TYPE_PACKET_FEATURES
        length = 100
        header = struct.pack(TLVMessage.HEADER_FORMAT, msg_type, length)
        decoded_type, decoded_len = struct.unpack(TLVMessage.HEADER_FORMAT, header)
        self.assertEqual(decoded_type, msg_type)
        self.assertEqual(decoded_len, length)

    def test_packet_feature_serialization(self):
        feature = PacketFeature(
            timestamp=1234567890,
            src_mac=b'\x00\x11\x22\x33\x44\x55',
            dst_mac=b'\x66\x77\x88\x99\xaa\xbb',
            protocol_type=0x0800,
            src_ip=0xc0a80001,
            dst_ip=0xc0a80002,
            transmission_type=6,
            src_port=12345,
            dst_port=80
        )
        data = feature.to_bytes()
        self.assertEqual(len(data), PacketFeature.SIZE)
        parsed = PacketFeature.parse(data)
        self.assertEqual(parsed.timestamp, feature.timestamp)
        self.assertEqual(parsed.src_port, feature.src_port)

    def test_detection_result_serialization(self):
        result = DetectionResult(timestamp=9876543210, is_attack=1, confidence=95, flow_id=12345)
        data = result.to_bytes()
        self.assertEqual(len(data), DetectionResult.SIZE)
        parsed = DetectionResult.parse(data)
        self.assertEqual(parsed.is_attack, result.is_attack)
        self.assertEqual(parsed.confidence, result.confidence)

if __name__ == '__main__':
    unittest.main()
