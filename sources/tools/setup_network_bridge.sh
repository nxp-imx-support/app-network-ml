#!/bin/bash
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause

set -e

PORT_0="swp0"
PORT_1="eth1"

ip link add name br0 type bridge
ip link set dev ${PORT_0} master br0
ip link set dev ${PORT_1} master br0
ip link set dev br0 up
ip link set dev ${PORT_0} up
ip link set dev ${PORT_1} up

