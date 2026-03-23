# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

import numpy as np
import struct
import socket

def packet_feature_to_model_input(packet):
    """Convert packet feature to model input (11 features)"""
    features = np.zeros(11, dtype=np.float32)

    features[0] = packet.protocol_type
    features[1] = packet.src_ip
    features[2] = packet.dst_ip
    features[3] = packet.transmission_type
    features[4] = packet.src_port
    features[5] = packet.dst_port
    features[6] = packet.packet_size
    features[7] = packet.tcp_flags
    features[8] = int.from_bytes(packet.src_mac[:4], 'big')
    features[9] = int.from_bytes(packet.dst_mac[:4], 'big')
    features[10] = packet.timestamp & 0xFFFFFFFF

    return features

def prepare_time_window(packets, window_size=10):
    """Prepare time window for LUCID model (10, 11, 1)"""
    features_list = [packet_feature_to_model_input(p) for p in packets[-window_size:]]

    # Pad if needed
    while len(features_list) < window_size:
        features_list.insert(0, np.zeros(11, dtype=np.float32))

    x_data = np.array(features_list, dtype=np.float32)
    x_data = x_data.reshape(1, window_size, 11, 1)

    return x_data
