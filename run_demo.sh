#!/bin/bash

rm pcaps/*
rm deepPacket/output_dir/*.pickle

trap "kill %1" SIGINT

cd WebSys
nohup python3 main.py &
cd -
tcpdump -i eth1 -G 7 -w pcaps/%Y_%m_%d-%H_%M_%S.pcap -z "./analysis_pkt.sh" not ip6 and not icmp and not port 5000 and not port 1900

wait %1