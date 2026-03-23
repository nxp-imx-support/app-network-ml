# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

import socket
import struct

class TLVMessage:
    MSG_TYPE_PACKET_FEATURES = 0x01
    MSG_TYPE_DETECTION_RESULT = 0x02
    MSG_TYPE_HEARTBEAT = 0x03
    HEADER_FORMAT = '<HI'  # uint16_t type, uint32_t length
    HEADER_SIZE = 6

class PacketFeature:
    FORMAT = '<Q6s6sHIIBHHHBH'  # 40 bytes
    SIZE = 40

    def __init__(self, timestamp=0, src_mac=b'\x00'*6, dst_mac=b'\x00'*6,
                 protocol_type=0, src_ip=0, dst_ip=0, transmission_type=0,
                 src_port=0, dst_port=0, packet_size=0, tcp_flags=0):
        self.timestamp = timestamp
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.protocol_type = protocol_type
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.transmission_type = transmission_type
        self.src_port = src_port
        self.dst_port = dst_port
        self.packet_size = packet_size
        self.tcp_flags = tcp_flags

    def to_bytes(self):
        return struct.pack(self.FORMAT, self.timestamp, self.src_mac, self.dst_mac,
                          self.protocol_type, self.src_ip, self.dst_ip,
                          self.transmission_type, self.src_port, self.dst_port,
                          self.packet_size, self.tcp_flags, 0)

    @classmethod
    def parse(cls, data):
        unpacked = struct.unpack(cls.FORMAT, data)
        return cls(*unpacked[:-1])  # Exclude padding

class DetectionResult:
    FORMAT = '<QBBHI'  # 16 bytes
    SIZE = 16

    def __init__(self, timestamp=0, is_attack=0, confidence=0, flow_id=0):
        self.timestamp = timestamp
        self.is_attack = is_attack
        self.confidence = confidence
        self.flow_id = flow_id

    def to_bytes(self):
        return struct.pack(self.FORMAT, self.timestamp, self.is_attack,
                          self.confidence, 0, self.flow_id)

    @classmethod
    def parse(cls, data):
        unpacked = struct.unpack(cls.FORMAT, data)
        return cls(unpacked[0], unpacked[1], unpacked[2], unpacked[4])

class SocketIPC:
    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)

    def send_tlv(self, msg_type, data):
        header = struct.pack(TLVMessage.HEADER_FORMAT, msg_type, len(data))
        self.sock.sendall(header + data)

    def recv_tlv(self):
        header = self._recv_exact(TLVMessage.HEADER_SIZE)
        msg_type, length = struct.unpack(TLVMessage.HEADER_FORMAT, header)
        data = self._recv_exact(length) if length > 0 else b''
        return msg_type, data

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed")
            data += chunk
        return data

    def send_detection_result(self, result):
        self.send_tlv(TLVMessage.MSG_TYPE_DETECTION_RESULT, result.to_bytes())

    def recv_packet_feature(self):
        msg_type, data = self.recv_tlv()
        if msg_type != TLVMessage.MSG_TYPE_PACKET_FEATURES:
            raise ValueError(f"Expected packet feature, got type {msg_type}")
        return PacketFeature.parse(data)

    def close(self):
        if self.sock:
            self.sock.close()


