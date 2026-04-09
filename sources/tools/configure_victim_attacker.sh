#!/bin/bash
set -e

IFACE_1=eth0
IFACE_2=eth1
VICTIM_IP=10.0.1.10/24
DEFAULT_IP=10.0.1.9/24

# Configure default net ns
echo "Configure default net namespace"
ip link set ${IFACE_1} up
ip addr add ${DEFAULT_IP} dev ${IFACE_1}

echo "Configure victim net namespace"
ip netns add victim_net
ip link set ${IFACE_2} netns victim_net
ip netns exec victim_net ip link set ${IFACE_2} up
ip netns exec victim_net ip addr add ${VICTIM_IP} dev ${IFACE_2}

echo "Start up victim server"
ip netns exec victim_net python3 simple_webserver.py


