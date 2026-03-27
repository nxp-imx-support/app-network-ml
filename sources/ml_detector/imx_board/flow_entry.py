# -*- coding: utf-8 -*-
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

from dataclasses import dataclass
from typing import List


@dataclass
class FlowEntry:
    """Flow entry storing packet buffer and metadata"""
    flow_id: int
    packets: List
    latest_timestamp: int = 0
    is_ready: bool = False
