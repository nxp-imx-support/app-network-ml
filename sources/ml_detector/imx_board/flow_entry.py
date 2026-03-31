# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

from typing import List


class FlowEntry:
    """Flow entry storing packet buffer and metadata"""
    def __init__(self, flow_id, flow_key, packet):
        self.flow_id: int = flow_id
        self.flow_key: tuple = flow_key
        self.packets: List = list(packet)
        self.first_packet_time: float = packet.timestamp
        self.is_ready: bool = True
