# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

import socket
import struct

class TLVMessage:
    MSG_PKT = 0x01
    MSG_RET = 0x02
    HEADER_FORMAT = '<HI'  # uint16_t type, uint32_t length
    HEADER_SIZE = 6

class PacketFeature:
    FORMAT = '<Q6s6sHI'  # 26B
    FORMAT += 'IIBBI'    # 14B
    FORMAT += 'HHHIHBI'    # 11B
    FORMAT += '13s'      # 13B PAD
    SIZE = 64            # 51 + 13(PAD)

    def __init__(self, timestamp=0, src_mac=b'\x00'*6, dst_mac=b'\x00'*6,
                 l3_type=0, l2_length=0, src_ip=0, dst_ip=0, ip_flags=0, l4_type=0,
                 l3_length=0, src_port=0, dst_port=0, tcp_flags=0, tcp_ack=0, 
                 tcp_win=0, icmp_type=0, l4_length=0):
        # TODO: Need to check the type of timestamp
        self.timestamp = timestamp
        # Layer2 
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.l3_type = l3_type
        self.l2_length = l2_length

        # Layer3
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ip_flags = ip_flags
        self.l4_type = l4_type
        self.l3_length = l3_length

        # Layer4
        self.src_port = src_port
        self.dst_port = dst_port
        self.tcp_flags = tcp_flags
        self.tcp_ack = tcp_ack
        self.tcp_win = tcp_win
        self.icmp_type = icmp_type
        self.l4_length = l4_length

    def to_bytes(self):
        return struct.pack(self.FORMAT, self.timestamp, self.src_mac, self.dst_mac,
                          self.l3_type, self.l2_length, self.src_ip, self.dst_ip, 
                          self.ip_flags, self.l4_type, self.l3_length, self.src_port, 
                          self.dst_port, self.tcp_flags, self.tcp_ack, self.tcp_win, 
                          self.icmp_type, self.l4_length, b'\x00')

    @classmethod
    def parse(cls, data):
        unpacked = struct.unpack(cls.FORMAT, data)
        return cls(*unpacked[:-1])  # Exclude padding

class DetectionResult:
    def __init__(self):
        self.ret_size = 0
        self.ret_array: ResultEntry = list()

    def append_new_ret_entry(self, ret_entry):
        self.ret_array.append(ret_entry)
        self.ret_size += 1

    def to_bytes(self):
        bytes_data = b''
        bytes_data += struct.pack('<I', self.ret_size)
        for entry in self.ret_array:
            bytes_data += struct.pack(entry.FORMAT, entry.src_ip, entry.src_port,
                                     entry.dst_ip, entry.dst_port, entry.protocol,
                                     entry.is_attack, entry.confidence)
        return bytes_data

class ResultEntry:
    FORMAT = '<BIHIHII'
    SIZE = 21
    def __init__(self, protocol, src_ip, src_port, dst_ip, dst_port, is_attack, confidence):
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.is_attack = is_attack
        self.confidence = confidence

class SocketIPC:
    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.sock = None

    def connect(self, timeout=None):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(self.socket_path)

    def send_tlv(self, msg_type, data):
        header = struct.pack(TLVMessage.HEADER_FORMAT, msg_type, len(data))
        self.sock.sendall(header + data)

    def recv_tlv(self, timeout=None):
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            header = self._recv_exact(TLVMessage.HEADER_SIZE)
            msg_type, length = struct.unpack(TLVMessage.HEADER_FORMAT, header)
            data = self._recv_exact(length) if length > 0 else b''
            return msg_type, data
        except socket.timeout:
            return None, None

    def _recv_exact(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed")
            data += chunk
        return data

    def send_detection_result(self, result):
        self.send_tlv(TLVMessage.MSG_RET, result.to_bytes())

    def recv_packet_feature(self, timeout=None):
        msg_type, data = self.recv_tlv(timeout)
        if msg_type is None:
            return None
        if msg_type != TLVMessage.MSG_PKT:
            raise ValueError(f"Expected packet feature, got type {msg_type}")
        return PacketFeature.parse(data)

    def close(self):
        if self.sock:
            self.sock.close()


