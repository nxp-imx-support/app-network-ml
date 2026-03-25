#!/usr/bin/env python3
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import os
import sys
import socket
import struct
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'imx_board'))
from socket_ipc import TLVMessage, PacketFeature, DetectionResult, SocketIPC


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

    def test_packet_feature_all_fields(self):
        feature = PacketFeature(
            timestamp=1111111111,
            src_mac=b'\xaa\xbb\xcc\xdd\xee\xff',
            dst_mac=b'\x11\x22\x33\x44\x55\x66',
            protocol_type=0x0806,
            src_ip=0xc0a80101,
            dst_ip=0xc0a80102,
            transmission_type=17,
            src_port=54321,
            dst_port=53,
            packet_size=64,
            tcp_flags=0
        )
        data = feature.to_bytes()
        parsed = PacketFeature.parse(data)
        self.assertEqual(parsed.timestamp, feature.timestamp)
        self.assertEqual(parsed.protocol_type, feature.protocol_type)
        self.assertEqual(parsed.transmission_type, feature.transmission_type)
        self.assertEqual(parsed.packet_size, feature.packet_size)
        self.assertEqual(parsed.tcp_flags, feature.tcp_flags)


class EchoServerThread:
    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.sock = None
        self.running = False
        self.thread = None

    def start(self):
        os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.socket_path)
        self.sock.listen(1)
        self.sock.settimeout(1.0)
        self.running = True
        self.thread = threading.Thread(target=self._serve)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
            while self.running:
                try:
                    header = conn.recv(TLVMessage.HEADER_SIZE)
                    if not header:
                        break
                    msg_type, length = struct.unpack(TLVMessage.HEADER_FORMAT, header)
                    data = b''
                    while len(data) < length:
                        chunk = conn.recv(length - len(data))
                        if not chunk:
                            break
                        data += chunk
                    conn.sendall(header + data)
                except socket.timeout:
                    continue
                except Exception:
                    break
            conn.close()
        except Exception:
            pass

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            self.sock.close()
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)


class TestSocketIPCEcho(unittest.TestCase):
    SOCKET_PATH = "/tmp/test_socket_ipc_echo.sock"

    def setUp(self):
        self.server = EchoServerThread(self.SOCKET_PATH)
        self.server.start()
        time.sleep(0.05)

    def tearDown(self):
        self.server.stop()
        time.sleep(0.05)

    def test_send_and_echo_packet_feature(self):
        client = SocketIPC(self.SOCKET_PATH)
        client.connect()

        feature = PacketFeature(
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
        client.send_tlv(TLVMessage.MSG_TYPE_PACKET_FEATURES, feature.to_bytes())
        received = client.recv_packet_feature()

        self.assertEqual(received.timestamp, feature.timestamp)
        self.assertEqual(received.src_port, feature.src_port)
        self.assertEqual(received.dst_port, feature.dst_port)

        client.close()

    def test_send_and_echo_detection_result(self):
        client = SocketIPC(self.SOCKET_PATH)
        client.connect()

        result = DetectionResult(
            timestamp=9876543210,
            is_attack=1,
            confidence=95,
            flow_id=12345
        )
        client.send_tlv(TLVMessage.MSG_TYPE_DETECTION_RESULT, result.to_bytes())
        msg_type, data = client.recv_tlv()

        self.assertEqual(msg_type, TLVMessage.MSG_TYPE_DETECTION_RESULT)
        parsed = DetectionResult.parse(data)
        self.assertEqual(parsed.is_attack, result.is_attack)
        self.assertEqual(parsed.confidence, result.confidence)

        client.close()

    def test_recv_packet_feature_wrong_type_raises(self):
        client = SocketIPC(self.SOCKET_PATH)
        client.connect()

        result = DetectionResult(timestamp=2222222, is_attack=0, confidence=50, flow_id=1)
        client.send_tlv(TLVMessage.MSG_TYPE_DETECTION_RESULT, result.to_bytes())

        with self.assertRaises(ValueError):
            client.recv_packet_feature()

        client.close()


if __name__ == '__main__':
    unittest.main()
