#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

ip link add name br0 type bridge
ip link set br0 up

ip link add veth0 type veth peer name veth1
# ip addr add $1 dev veth0
ip link set veth0 up
ip link set veth1 up

ip link set eth0 down
ip link set eth1 down
ip link set eth0 up
ip link set eth1 up

ip link set dev eth0 master br0
ip link set dev eth1 master br0
ip link set dev veth1 master br0

sleep 15s
route del default gw 0.0.0.0
